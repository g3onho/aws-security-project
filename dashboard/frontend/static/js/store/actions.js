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
export const historyAt=row=>milliseconds(row.lastSeenAt||row.createdAt);
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

// 1주일 지표에서 선택 기간 [from,to) 표본만 남기고, 차트 축에 쓸 조회 경계도 보존한다.
export function sliceMetrics(metric,from,to){
 return {...metric,rangeFrom:from,rangeTo:to,series:(metric.series||[]).map(s=>{const points=(s.points||[]).filter(p=>Date.parse(p.timestamp)>=from&&Date.parse(p.timestamp)<to);
  return {...s,points,observedAt:points.length?points[points.length-1].timestamp:null,
   collectionStatus:points.some(p=>p.value!=null)?'available':'missing'};})};
}
// 허니팟 API 는 기간(from·to)만 쓴다. 그 밖의 필터(리전·위험도 등)는 허니팟과 무관하다.
function windowQuery(){
 const to=Date.now(),q=new URLSearchParams({from:new Date(to-filters.hours*3600000).toISOString(),to:new Date(to).toISOString()});
 return q;
}
async function honeypotRead(name,path,{window=true,extra={}}={}){
 const q=window?windowQuery():new URLSearchParams();
 for(const [key,value] of Object.entries(extra))q.set(key,value);
 markRequest(name,{status:'loading'});
 try{
  const response=envelope(await request(path+(q.size?'?'+q:'')));
  markRequest(name,{status:'success',lastUpdated:Date.now(),requestId:response.meta?.requestId||null,error:null});
  return {data:response.data,warnings:warningsOf(response),partial:response.meta?.partial===true};
 }catch(error){markRequest(name,{status:'error',error:error.message});throw error;}
}
// Idempotency-Key: 보안 컨텍스트가 아닌 HTTP(ALB)에서는 crypto.randomUUID 가 없으므로 getRandomValues 로 만든다.
export function newIdempotencyKey(){
 const bytes=new Uint8Array(16);
 if(globalThis.crypto?.getRandomValues)globalThis.crypto.getRandomValues(bytes);else bytes.forEach((_,i)=>{bytes[i]=Math.floor(Math.random()*256);});
 return 'hp-'+[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');
}
async function blocklistWrite(name,path,method,body){
 markRequest(name,{status:'loading'});
 try{
  const response=envelope(await request(path,{method,headers:{'Idempotency-Key':newIdempotencyKey()},body:JSON.stringify(body)}));
  markRequest(name,{status:'success',lastUpdated:Date.now(),error:null});
  return response.data;
 }catch(error){markRequest(name,{status:'error',error:error.message});throw error;}
}
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
   // CloudWatch 그래프는 기간과 관계없이 5분 평균(v20.5). EC2 기본 모니터링 CPU 가 5분 간격이라 메모리도 맞춘다.
   // /api/infra/status 는 periodSeconds 를 모르는 필터로 거절(400)하므로 metrics 요청에만 붙인다.
   // 기간 트랙(v20.5)이 1주일 임계 초과 구간을 세므로 지표는 늘 1주일을 받고, 그래프·통계용은 선택 기간만 잘라 쓴다(요청 1회).
   const chartQuery=new URLSearchParams(metricQuery);chartQuery.set('periodSeconds','300');
   chartQuery.set('from',new Date(Date.parse(q.get('to'))-7*86400000).toISOString());
   const eventQuery=new URLSearchParams(q);if(filters.view==='events')eventQuery.delete('severity');
   const eventRequest=pages(endpoints.events,eventQuery,signal);
   const regionalRequest=q.has('region')?pages(endpoints.events,regionalQuery,signal):eventRequest;
   const calls=[eventRequest,regionalRequest,request(endpoints.summary+'?'+q,{signal}),request(endpoints.health,{signal})];
   if(filters.view==='infrastructure')calls.push(request(endpoints.metrics+'?'+chartQuery,{signal}),request(endpoints.infra+'?'+metricQuery,{signal}));
   // 통합 관제의 인프라 요약은 선택 기간만 조회한다. 실패해도 탐지 목록은 계속 보여준다.
   const overviewMetricQuery=new URLSearchParams(metricQuery);overviewMetricQuery.set('periodSeconds','300');
   const overviewContext=filters.view==='overview'?Promise.allSettled([
    request(endpoints.metrics+'?'+overviewMetricQuery,{signal}),
    request(endpoints.infra+'?'+metricQuery,{signal}),
   ]):Promise.resolve(null);
   // 기간 트랙(v20.5)은 지금부터 1주일 전까지 누적 탐지 수를 그린다 → 1주일 목록. 1주일을 보고 있으면 본 목록을 그대로 쓴다.
   const weekQuery=new URLSearchParams(q);weekQuery.set('from',new Date(Date.parse(q.get('to'))-7*86400000).toISOString());
   if(filters.view==='events')weekQuery.delete('severity');
   // 인프라(임계 초과)·조치 이력(이력 수)은 트랙에 탐지를 쓰지 않는다.
   const weekRequest=['vulnerabilities','infrastructure','responses'].includes(filters.view)?Promise.resolve(null)
    :filters.hours===168?eventRequest:pages(endpoints.events,weekQuery,signal);
   const [[events,all,summaryResponse,health,baseMetrics,baseInfra],week,overviewResults]=await Promise.all([Promise.all(calls),weekRequest,overviewContext]);
   if(current!==session.generation)return false;
   const optionalWarnings=[];
   const optionalData=(result,label)=>{
    if(result.status==='rejected'){optionalWarnings.push(`${label} 정보를 불러오지 못했습니다.`);return null;}
    try{const response=envelope(result.value);optionalWarnings.push(...warningsOf(result.value));return response.data;}
    catch{optionalWarnings.push(`${label} 응답 형식을 확인할 수 없습니다.`);return null;}
   };
   const standardSummary=envelope(summaryResponse).data,healthData=envelope(health).data;
   const adapted=adaptEvents(events.items),regionalAdapted=all===events?adapted:adaptEvents(all.items);
   let rows=adapted.rows,regional=regionalAdapted.rows;
   if(filters.source){rows=rows.filter(e=>e.source===filters.source);regional=regional.filter(e=>e.source===filters.source);}
   if(filters.search){const matches=searchMatches(filters.search.toLocaleLowerCase());rows=rows.filter(matches);regional=regional.filter(matches);}
   const severityCounts=Object.fromEntries(['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL','UNKNOWN'].map(severity=>[severity,rows.filter(e=>e.severity.toUpperCase()===severity).length]));
   if(filters.view==='events'&&filters.severity){const match=e=>e.severity.toUpperCase()===filters.severity.toUpperCase();rows=rows.filter(match);regional=regional.filter(match);}
   data.rows=rows;data.regional=regional;
   if(week){let weekRows=week===events?adapted.rows:adaptEvents(week.items).rows;
    if(filters.source)weekRows=weekRows.filter(e=>e.source===filters.source);
    if(filters.search)weekRows=weekRows.filter(searchMatches(filters.search.toLocaleLowerCase()));
    if(filters.view==='events'&&filters.severity)weekRows=weekRows.filter(e=>e.severity.toUpperCase()===filters.severity.toUpperCase());
    data.week=weekRows;}else data.week=null;
   const metricData=overviewResults?optionalData(overviewResults[0],'CloudWatch 지표'):baseMetrics?envelope(baseMetrics).data:null;
   data.metricWeek=filters.view==='infrastructure'?metricData:null;
   data.metric=metricData?sliceMetrics(metricData,Date.parse(q.get('from')),Date.parse(q.get('to'))):null;
   data.infra=overviewResults?optionalData(overviewResults[1],'인프라 상태'):baseInfra?envelope(baseInfra).data:null;
   const asOf=milliseconds(events.meta?.asOf)||Date.now();setAsOf(asOf);
   const resolved=rows.filter(e=>e.actionState==='VERIFIED').length;
   Object.assign(summary,{total:filters.source||filters.search?rows.length:standardSummary.totalEvents,bySeverity:filters.view==='events'?severityCounts:(standardSummary.bySeverity??{}),resolved,
    openVulnerabilities:standardSummary.openVulnerabilities??null,
    // v23 통합 관제: 자동 대응 현황(조치 이력 기준)·CloudWatch 경보 요약. 서버가 못 읽으면 null.
    automation:standardSummary.automation??null,alarms:standardSummary.alarms??null,
    resolutionRate:rows.length?resolved/rows.length*100:null,asOf,queryTo:Date.parse(q.get('to')),collectedAt:asOf,snapshot:events.meta?.requestId,
    health:{aws_connected:healthData.dataSourceConnected,checks:{worker:'disabled'}},
    // 적재 지연·실패(v21, meta.warnings)와 형식 오류로 뺀 행 수(어댑터)를 숨기지 않는다.
    warnings:unique([...events.warnings,...warningsOf(summaryResponse),...(baseMetrics?warningsOf(baseMetrics):[]),...optionalWarnings,...adapted.warnings])});
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
 // 탐지 상세의 조치 기록(v23): 그 탐지의 자동조치 판정·실행 기록. 화면 기간과 무관하게 계약 최대 구간(최근 31일).
 async eventHistory(eventId){
  const to=Date.now(),q=new URLSearchParams({eventId,from:new Date(to-31*86400000).toISOString(),to:new Date(to).toISOString()});
  const result=await pages(endpoints.history,q);const adapted=adaptHistory(result.items,result.extra.jobs);
  return {items:adapted.rows,warnings:unique([...result.warnings,...adapted.warnings])};
 },
 async vulnerabilities({target=''}={}){
  // 취약점은 현재 상태 — 화면의 기간과 무관하게 계약 최대 구간(최근 31일)으로 요청한다(v20.5, API 규칙은 그대로).
  const q=query(),to=Date.now();q.delete('status');q.delete('severity');q.set('from',new Date(to-31*86400000).toISOString());q.set('to',new Date(to).toISOString());if(target)q.set('resource',target);
  if(filters.source&&!['Inspector','Trivy'].includes(filters.source))return {items:[],total:0,warnings:[]};
  if(filters.source)q.set('source',filters.source);
  markRequest('vulnerabilities',{status:'loading'});
  try{
   const result=await pages(endpoints.vulnerabilities,q);const adapted=adaptVulnerabilities(result.items);
   let items=adapted.rows;
   if(filters.search){const term=filters.search.toLocaleLowerCase();items=items.filter(item=>[item.cveId,item.package,item.resource].some(value=>String(value||'').toLocaleLowerCase().includes(term)));}
   markRequest('vulnerabilities',{status:'success',lastUpdated:milliseconds(result.meta?.asOf),requestId:result.meta?.requestId||null,error:null});
   return {items,total:items.length,warnings:unique([...result.warnings,...adapted.warnings])};
  }catch(error){markRequest('vulnerabilities',{status:'error',error:error.message});throw error;}
 },
 async history(){
  // 기간 트랙(v20.5)이 1주일 조치 이력 수를 세므로 1주일을 받고, 표에는 선택 기간만 남긴다.
  // 기간 기준 = 서버와 같은 '마지막 발생 시각'(자동: lastSeenAt, 수동: 기록 시각 createdAt).
  const q=query();q.delete('severity');q.delete('status');
  const from=Date.parse(q.get('from'));q.set('from',new Date(Date.parse(q.get('to'))-7*86400000).toISOString());
  markRequest('history',{status:'loading'});
  try{
   const result=await pages(endpoints.history,q);const adapted=adaptHistory(result.items,result.extra.jobs);
   data.historyWeek=adapted.rows;notify('history');
   markRequest('history',{status:'success',lastUpdated:milliseconds(result.meta?.asOf),requestId:result.meta?.requestId||null,error:null});
   return {items:adapted.rows.filter(row=>historyAt(row)>=from),jobs:adapted.jobs,warnings:unique([...result.warnings,...adapted.warnings]),partial:result.meta?.partial===true};
  }catch(error){markRequest('history',{status:'error',error:error.message});throw error;}
 },
 async drillsCatalog(){
  markRequest('drillsCatalog',{status:'loading'});
  try{
   const result=envelope(await request(endpoints.drillsCatalog)).data;
   markRequest('drillsCatalog',{status:'success',lastUpdated:Date.now(),error:null});
   return result;
  }catch(error){markRequest('drillsCatalog',{status:'error',error:error.message});throw error;}
 },
 async drills(){
  markRequest('drills',{status:'loading'});
  try{
   const result=listEnvelope(await request(endpoints.drills)).data;
   markRequest('drills',{status:'success',lastUpdated:Date.now(),error:null});
   return {items:result.items,nextCursor:result.nextCursor??null};
  }catch(error){markRequest('drills',{status:'error',error:error.message});throw error;}
 },
 // 지리별 웹보안검사 실행/상태. 실제 공격(SSM)이라 서버가 WRITE_ENABLED 로 막을 수 있다(403).
 async startWebScan(params={}){
  markRequest('startWebScan',{status:'loading'});
  try{
   const result=envelope(await request(endpoints.drillWebScanStart,{method:'POST',body:JSON.stringify(params||{})})).data;
   markRequest('startWebScan',{status:'success',lastUpdated:Date.now(),error:null});
   return result;
  }catch(error){markRequest('startWebScan',{status:'error',error:error.message});throw error;}
 },
 async webScanStatus(runId){
  const result=envelope(await request(endpoints.drillWebScanStatus(runId))).data;
  return result;
 },
 // 전부 실행(SEC-02/07/08/06B/10) 실행/상태. 실제 실행(SSM)이라 WRITE_ENABLED 로 막힐 수 있다(403).
 async startRunAll(params={}){
  markRequest('startRunAll',{status:'loading'});
  try{
   const result=envelope(await request(endpoints.drillRunAllStart,{method:'POST',body:JSON.stringify(params||{})})).data;
   markRequest('startRunAll',{status:'success',lastUpdated:Date.now(),error:null});
   return result;
  }catch(error){markRequest('startRunAll',{status:'error',error:error.message});throw error;}
 },
 async runAllStatus(runId){
  const result=envelope(await request(endpoints.drillRunAllStatus(runId))).data;
  return result;
 },
 // SEC-08 공격 로그(.txt·.json) 다운로드 링크. 완료 안 된 항목은 url 이 null.
 async runAllReport(runId){
  const result=envelope(await request(endpoints.drillRunAllReport(runId))).data;
  return result;
 },
 // --- 허니팟 화면·차단 IP 관리(v25) -------------------------------------------------------------
 // 기간은 화면의 기간 버튼(filters.hours)을 따른다. 응답의 경고·partial 을 그대로 화면에 넘긴다(0건으로 위장하지 않는다).
 async honeypotStatus(){return honeypotRead('honeypotStatus',endpoints.honeypotStatus,{window:false});},
 async honeypotSessions({cursor=null,ip='',intent='',limit=50}={}){
  const extra={limit:String(limit)};if(cursor)extra.cursor=cursor;if(ip)extra.ip=ip;if(intent)extra.intent=intent;
  return honeypotRead('honeypotSessions',endpoints.honeypotSessions,{extra});
 },
 async honeypotSession(id,{reveal=false}={}){
  return honeypotRead('honeypotSession',endpoints.honeypotSession(id),{extra:reveal?{revealPasswords:'true'}:{}});
 },
 async honeypotStats(){return honeypotRead('honeypotStats',endpoints.honeypotStats);},
 async honeypotTimeline(ip){return honeypotRead('honeypotTimeline',endpoints.honeypotTimeline,{extra:{ip}});},
 async blocklist(){return honeypotRead('blocklist',endpoints.blocklist);},
 // 대시보드 도우미: 읽기 전용 대화. 서버가 CSRF·로그인·상한을 검사하고, 변경 도구는 없다.
 async assistantStatus(){return honeypotRead('assistantStatus',endpoints.assistantStatus,{window:false});},
 async assistantChat(messages){
  markRequest('assistantChat',{status:'loading'});
  try{
   const response=envelope(await request(endpoints.assistantChat,{method:'POST',body:JSON.stringify({messages})}));
   markRequest('assistantChat',{status:'success',lastUpdated:Date.now(),error:null});
   return response.data;
  }catch(error){markRequest('assistantChat',{status:'error',error:error.message});throw error;}
 },
 // 화면별 AI 요약 보고서(조회 전용). 필터는 Store 가 이 화면에서 실제로 쓰는 것만 골라 보낸다(숨겨진 필터가 섞이지 않게).
 // 숫자는 서버가 집계하고 모델은 문장만 쓴다. 취약점·시나리오는 기간 막대를 쓰지 않아 서버가 31일로 고정한다.
 async assistantReport(view){
  const status=Object.keys(ACTION_LABELS).find(key=>ACTION_LABELS[key]===filters.status)||'';
  const period={hours:filters.hours,endOffset:filters.endOffset};
  const scoped={
   events:{...period,region:filters.region==='all'?'':filters.region,resource:filters.resource,severity:filters.severity,status,source:filters.source,search:filters.search},
   vulnerabilities:{region:filters.region==='all'?'':filters.region,search:filters.search},
   infrastructure:period,drills:{},honeypot:period,
  }[view];
  markRequest('assistantReport',{status:'loading'});
  try{
   const response=envelope(await request(endpoints.assistantReport,{method:'POST',body:JSON.stringify({view,...(scoped||{})})}));
   markRequest('assistantReport',{status:'success',lastUpdated:Date.now(),requestId:response.meta?.requestId||null,error:null});
   return response.data;
  }catch(error){markRequest('assistantReport',{status:'error',error:error.message});throw error;}
 },
 // 변경 요청은 자동 재시도하지 않는다(client.js). 같은 화면 조작 한 번 = Idempotency-Key 하나.
 async blocklistRelease(ip,body){return blocklistWrite('blocklistRelease',endpoints.blocklistRelease(ip),'POST',body);},
 async blocklistPatch(ip,body){return blocklistWrite('blocklistPatch',endpoints.blocklistPatch(ip),'PATCH',body);},
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
