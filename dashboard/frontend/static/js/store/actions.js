// UI 가 Store 에 요청하는 유일한 경로(설계 2.1-1·4). 통신은 api/client, 변환은 adapters 가 맡는다.
import {request as send} from './api/client.js?v=local-2';
import {endpoints} from './api/endpoints.js?v=local-2';
import {envelope,listEnvelope,requireContract,isObject,warningsOf} from './api/validators.js?v=local-2';
import {adaptEvents,ACTION_LABELS} from './adapters/events.js?v=local-2';
import {adaptVulnerabilities} from './adapters/vulnerabilities.js?v=local-2';
import {adaptHistory} from './adapters/history.js?v=local-2';
import {createPoller} from './polling.js?v=local-2';
import {filters,config,data,details,summary,session,setConfig,setAsOf,markRequest,resetState} from './state.js?v=local-2';

const listeners=new Set();
export function subscribe(listener){listeners.add(listener);return ()=>listeners.delete(listener);}
function notify(change){for(const listener of [...listeners]){try{listener(change);}catch(error){console.error(error);}}}

const poller=createPoller();
const milliseconds=value=>value==null?null:Date.parse(value);
const unique=list=>[...new Set(list)];

export function reset(){poller.stop();resetState();}
const ctx={csrf:()=>session.csrf,onUnauthorized:()=>{reset();location.assign('/login');}};
export const request=(url,options={})=>send(url,options,ctx);

export function query(){
 const to=Date.now()-filters.endOffset*3600000;
 const q=new URLSearchParams({from:new Date(to-filters.hours*3600000).toISOString(),to:new Date(to).toISOString()});
 if(filters.region&&filters.region!=='all')q.set('region',filters.region);
 if(filters.resource)q.set('resource',filters.resource);
 if(filters.severity)q.set('severity',filters.severity.toUpperCase());
 const status=Object.keys(ACTION_LABELS).find(key=>ACTION_LABELS[key]===filters.status);if(status)q.set('status',status);
 return q;
}
async function pages(path,q,signal){
 const items=[];let cursor=null,meta=null,extra={},warnings=[];
 do{
  const params=new URLSearchParams(q);params.set('limit','200');if(cursor)params.set('cursor',cursor);
  const response=listEnvelope(await request(path+'?'+params,{signal}));
  items.push(...response.data.items);warnings.push(...warningsOf(response));
  cursor=response.data.nextCursor||null;meta=response.meta;extra=response.data;
 }while(cursor);
 return {items,meta,extra,warnings:unique(warnings)};
}
function activeSession(epoch){if(epoch!==session.epoch)throw new DOMException('세션이 변경되었습니다.','AbortError');}
const searchMatches=term=>e=>[e.id,e.title,e.resource,e.scenario].some(v=>String(v||'').toLocaleLowerCase().includes(term));

export const actions={
 async init(){
  if(!session.initializing)session.initializing=(async()=>{
   const epoch=session.epoch,payload=await request(endpoints.session);activeSession(epoch);
   if(!payload?.user){reset();location.assign('/login');throw Error('로그인이 필요합니다.');}
   requireContract(isObject(payload.user)&&typeof payload.user.name==='string'&&typeof payload.csrfToken==='string');
   session.csrf=payload.csrfToken;
   setConfig({mode:'live',writeEnabled:false,role:payload.user.role,user:payload.user,dataSourceConnected:false});
  })().catch(error=>{session.initializing=null;throw error;});
  return session.initializing;
 },
 async load(){
  await this.init();const current=++session.generation;session.controller?.abort();
  session.controller=new AbortController();const signal=session.controller.signal;
  markRequest('events',{status:'loading'});
  try{
   const q=query(),regionalQuery=new URLSearchParams(q),metricQuery=new URLSearchParams(q);
   regionalQuery.delete('region');metricQuery.delete('severity');metricQuery.delete('status');
   const eventRequest=pages(endpoints.events,q,signal);
   const regionalRequest=q.has('region')?pages(endpoints.events,regionalQuery,signal):eventRequest;
   const calls=[eventRequest,regionalRequest,request(endpoints.summary+'?'+q,{signal}),request(endpoints.health,{signal})];
   if(filters.view==='infrastructure')calls.push(request(endpoints.metrics+'?'+metricQuery,{signal}),request(endpoints.infra+'?'+metricQuery,{signal}));
   const [events,all,summaryResponse,health,metricsResponse,infraResponse]=await Promise.all(calls);
   if(current!==session.generation)return false;
   const standardSummary=envelope(summaryResponse).data,healthData=envelope(health).data;
   const adapted=adaptEvents(events.items),regionalAdapted=all===events?adapted:adaptEvents(all.items);
   let rows=adapted.rows,regional=regionalAdapted.rows;
   if(filters.source){rows=rows.filter(e=>e.source===filters.source);regional=regional.filter(e=>e.source===filters.source);}
   if(filters.search){const matches=searchMatches(filters.search.toLocaleLowerCase());rows=rows.filter(matches);regional=regional.filter(matches);}
   data.rows=rows;data.regional=regional;
   data.metric=metricsResponse?envelope(metricsResponse).data:null;data.infra=infraResponse?envelope(infraResponse).data:null;
   const asOf=milliseconds(events.meta?.asOf)||Date.now();setAsOf(asOf);
   const resolved=rows.filter(e=>e.actionState==='VERIFIED').length;
   Object.assign(summary,{total:filters.source||filters.search?rows.length:standardSummary.totalEvents,resolved,
    resolutionRate:rows.length?resolved/rows.length*100:null,asOf,collectedAt:asOf,snapshot:events.meta?.requestId,
    health:{aws_connected:healthData.dataSourceConnected,checks:{worker:'disabled'}},
    // 적재 지연·실패(v21, meta.warnings)와 형식 오류로 뺀 행 수(어댑터)를 숨기지 않는다.
    warnings:unique([...events.warnings,...warningsOf(summaryResponse),...adapted.warnings])});
   setConfig({...config,dataSourceConnected:healthData.dataSourceConnected});
   details.clear();for(const event of [...rows,...regional])details.set(event.id,event);
   markRequest('events',{status:'success',lastUpdated:asOf,requestId:events.meta?.requestId||null,error:null});
   notify('events');
   return true;
  }catch(error){
   if(current===session.generation&&error?.name!=='AbortError')markRequest('events',{status:'error',error:error.message});
   throw error;
  }
 },
 get(id){return details.get(id);},
 async detail(id){const event=details.get(id);if(!event)throw Error('현재 조회 범위에서 이벤트를 찾을 수 없습니다.');return event;},
 async change(){throw Error('조치 공급자가 연결되지 않아 읽기 전용입니다.');},
 async job(id,jobId){const q=query();q.set('jobId',jobId);const result=envelope(await request(endpoints.history+'?'+q)).data;return {execution:result.jobs.find(job=>job.jobId===jobId)};},
 async vulnerabilities({target='',fixableOnly=false}={}){
  const q=query();q.delete('status');if(target)q.set('resource',target);
  if(filters.source&&!['Inspector','Trivy'].includes(filters.source))return {items:[],total:0,warnings:[]};
  if(filters.source)q.set('source',filters.source);
  markRequest('vulnerabilities',{status:'loading'});
  try{
   const result=await pages(endpoints.vulnerabilities,q);const adapted=adaptVulnerabilities(result.items);
   let items=fixableOnly?adapted.rows.filter(item=>item.fixedVersion&&!/pending/i.test(item.fixedVersion)):adapted.rows; // '(pending)' 은 수정본 미배포
   if(filters.search){const term=filters.search.toLocaleLowerCase();items=items.filter(item=>[item.cveId,item.package,item.resource].some(value=>String(value||'').toLocaleLowerCase().includes(term)));}
   markRequest('vulnerabilities',{status:'success',lastUpdated:milliseconds(result.meta?.asOf),requestId:result.meta?.requestId||null,error:null});
   return {items,total:items.length,warnings:unique([...result.warnings,...adapted.warnings])};
  }catch(error){markRequest('vulnerabilities',{status:'error',error:error.message});throw error;}
 },
 async history(){
  const q=query();q.delete('severity');q.delete('status');
  markRequest('history',{status:'loading'});
  try{
   const result=await pages(endpoints.history,q);const adapted=adaptHistory(result.items,result.extra.jobs);
   markRequest('history',{status:'success',lastUpdated:milliseconds(result.meta?.asOf),requestId:result.meta?.requestId||null,error:null});
   return {items:adapted.rows,jobs:adapted.jobs,warnings:unique([...result.warnings,...adapted.warnings]),partial:result.meta?.partial===true};
  }catch(error){markRequest('history',{status:'error',error:error.message});throw error;}
 },
 async logout(){session.controller?.abort();session.generation++;await request(endpoints.logout,{method:'POST',body:'{}'});reset();location.assign('/login');},
 // CSV 내보내기용 이벤트 전체(현재 기간·리전·위험도·상태 필터). 파일 만들기·내려받기는 화면(downloads.js) 몫이다.
 async exportEvents(){const {items}=await pages(endpoints.events,query());return {items};},
 // 필터는 이 action 으로만 바꾼다(설계 2.1-4).
 setFilters(patch){Object.assign(filters,patch);notify('filters');},
 // 자동 새로고침: 타이머는 Store 가 하나만 관리한다. refresh 는 화면 갱신 함수, canRun 은 화면 사정(상세 창·작업 중).
 setAutoRefresh(on,{refresh,canRun}={}){
  filters.auto=Boolean(on);
  if(filters.auto&&refresh)poller.start(refresh,canRun);else poller.stop();
  notify('filters');
 },
 pollingState(){return {running:poller.running,armed:poller.armed};},
};
