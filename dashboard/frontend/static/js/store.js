// Browser client for the schema-v1 API. Presentation changes stay in this layer.
const defaults={view:'overview',region:'all',resource:'',environment:'',hours:24,severity:'',status:'',source:'',search:'',endOffset:0,page:1,auto:false};
export const state={...defaults};
export let config={mode:'live',writeEnabled:false,role:'viewer',dataSourceConnected:false};
export let DATA_AS_OF=0;
export const summary={};
let rows=[],regional=[],metric=null,infra=null,csrf='',generation=0,sessionEpoch=0,controller,initializing;
const details=new Map();
const labels={PENDING_APPROVAL:'승인 대기',APPROVED:'승인됨',CANCELLED:'취소됨',QUEUED:'실행 대기',RUNNING:'조치 실행 중',EXECUTED:'실행 완료',EXECUTION_FAILED:'실행 실패',VERIFY_QUEUED:'재검증 대기',VERIFYING:'재검증 중',VERIFIED:'해결',VERIFICATION_FAILED:'재검증 실패',VERIFICATION_ERROR:'재검증 오류',RECONCILING:'상태 확인 중'};
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
function requireContract(valid){if(!valid)throw Error('서버 데이터 형식이 올바르지 않습니다. 새로고침 후 다시 확인해주세요.');}
const milliseconds=value=>value==null?null:Date.parse(value);
function normalize(event){
 requireContract(object(event)&&typeof event.id==='string'&&typeof event.title==='string'&&typeof event.resource==='string'&&typeof event.actionState==='string'&&typeof event.observedAt==='string'&&['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL','UNKNOWN'].includes(event.severity)&&Array.isArray(event.allowedActions));
 const at=milliseconds(event.observedAt);requireContract(Number.isFinite(at)&&Object.hasOwn(labels,event.actionState));
 // 플레이북이 없는 탐지(actionable:false)는 승인할 수 없다 — '승인 대기' 대신 '탐지됨'.
 const status=event.actionable===false&&event.actionState==='PENDING_APPROVAL'?'탐지됨':labels[event.actionState];
 return {...event,at,status,severity:event.severity[0]+event.severity.slice(1).toLowerCase()};
}
function reset(){controller?.abort();generation++;sessionEpoch++;initializing=null;csrf='';DATA_AS_OF=0;rows=[];regional=[];metric=null;infra=null;details.clear();for(const key of Object.keys(summary))delete summary[key];config={mode:'live',writeEnabled:false,role:'viewer',dataSourceConnected:false};Object.assign(state,defaults);}
export async function request(url,options={}){
 const headers=new Headers(options.headers||{});if(options.body)headers.set('Content-Type','application/json');if(csrf)headers.set('X-CSRF-Token',csrf);
 const response=await fetch(url,{...options,credentials:'same-origin',headers});
 if(response.status===401){reset();location.assign('/login');throw Error('로그인이 필요합니다.');}
 let payload;try{payload=await response.json();}catch{throw Error('서버 응답을 읽을 수 없습니다.');}
 if(!response.ok)throw Error(payload?.title||payload?.error?.message||'서버 요청에 실패했습니다.');
 return payload;
}
function envelope(payload){requireContract(object(payload)&&object(payload.data)&&object(payload.meta)&&payload.meta.schemaVersion==='1');return payload;}
export function query(){
 const to=Date.now()-state.endOffset*3600000;
 const q=new URLSearchParams({from:new Date(to-state.hours*3600000).toISOString(),to:new Date(to).toISOString()});
 if(state.region&&state.region!=='all')q.set('region',state.region);
 if(state.resource)q.set('resource',state.resource);
 if(state.severity)q.set('severity',state.severity.toUpperCase());
 const status=Object.keys(labels).find(key=>labels[key]===state.status);if(status)q.set('status',status);
 return q;
}
async function pages(path,q,signal){
 const items=[];let cursor=null,meta=null,extra={};
 do{
  const params=new URLSearchParams(q);params.set('limit','200');if(cursor)params.set('cursor',cursor);
  const response=envelope(await request(path+'?'+params,{signal}));
  requireContract(Array.isArray(response.data.items));items.push(...response.data.items);
  cursor=response.data.nextCursor||null;meta=response.meta;extra=response.data;
 }while(cursor);
 return {items,meta,extra};
}
function activeSession(epoch){if(epoch!==sessionEpoch)throw new DOMException('세션이 변경되었습니다.','AbortError');}
function csvCell(value){let valueText=String(value??'');if(/^[\s]*[=+@-]/.test(valueText))valueText="'"+valueText;return '"'+valueText.replaceAll('"','""')+'"';}
export const api={
 async init(){
  if(!initializing)initializing=(async()=>{
   const epoch=sessionEpoch,session=await request('/api/auth/session');activeSession(epoch);
   if(!session?.user){reset();location.assign('/login');throw Error('로그인이 필요합니다.');}
   requireContract(object(session.user)&&typeof session.user.name==='string'&&typeof session.csrfToken==='string');
   csrf=session.csrfToken;config={mode:'live',writeEnabled:false,role:session.user.role,user:session.user,dataSourceConnected:false};
  })().catch(error=>{initializing=null;throw error;});
  return initializing;
 },
 async load(){
  await this.init();const current=++generation;controller?.abort();controller=new AbortController();const signal=controller.signal;
  const q=query(),regionalQuery=new URLSearchParams(q),metricQuery=new URLSearchParams(q);
  regionalQuery.delete('region');
  metricQuery.delete('severity');metricQuery.delete('status');
  const eventRequest=pages('/api/events',q,signal);
  const regionalRequest=q.has('region')?pages('/api/events',regionalQuery,signal):eventRequest;
  const requests=[eventRequest,regionalRequest,request('/api/summary?'+q,{signal}),request('/health',{signal})];
  if(state.view==='infrastructure')requests.push(request('/api/metrics?'+metricQuery,{signal}),request('/api/infra/status?'+metricQuery,{signal}));
  const [events,all,summaryResponse,health,metricsResponse,infraResponse]=await Promise.all(requests);
  if(current!==generation)return false;
  const standardSummary=envelope(summaryResponse).data,healthData=envelope(health).data;
  rows=events.items.map(normalize);regional=all.items.map(normalize);
  if(state.source){rows=rows.filter(e=>e.source===state.source);regional=regional.filter(e=>e.source===state.source);}
  if(state.search){const term=state.search.toLocaleLowerCase(),matches=e=>[e.id,e.title,e.resource,e.scenario].some(v=>String(v||'').toLocaleLowerCase().includes(term));rows=rows.filter(matches);regional=regional.filter(matches);}
  metric=metricsResponse?envelope(metricsResponse).data:null;infra=infraResponse?envelope(infraResponse).data:null;
  const asOf=milliseconds(events.meta?.asOf)||Date.now();DATA_AS_OF=asOf;
  const resolved=rows.filter(e=>e.actionState==='VERIFIED').length;
  Object.assign(summary,{total:state.source||state.search?rows.length:standardSummary.totalEvents,resolved,
   resolutionRate:rows.length?resolved/rows.length*100:null,asOf,collectedAt:asOf,snapshot:events.meta?.requestId,
   health:{aws_connected:healthData.dataSourceConnected,checks:{worker:'disabled'}}});
  config={...config,dataSourceConnected:healthData.dataSourceConnected};
  details.clear();for(const event of [...rows,...regional])details.set(event.id,event);
  return true;
 },
 get(id){return details.get(id);},
 async detail(id){const event=details.get(id);if(!event)throw Error('현재 조회 범위에서 이벤트를 찾을 수 없습니다.');return event;},
 async change(){throw Error('조치 공급자가 연결되지 않아 읽기 전용입니다.');},
 async job(id,jobId){const q=query();q.set('jobId',jobId);const result=envelope(await request('/api/history?'+q)).data;return {execution:result.jobs.find(job=>job.jobId===jobId)};},
 async vulnerabilities({target='',fixableOnly=false}={}){
  const q=query();q.delete('status');if(target)q.set('resource',target);
  if(state.source&&!['Inspector','Trivy'].includes(state.source))return {items:[],total:0};
  if(state.source)q.set('source',state.source);
  const result=await pages('/api/vulnerabilities',q);
  let items=fixableOnly?result.items.filter(item=>item.fixedVersion&&!/pending/i.test(item.fixedVersion)):result.items; // '(pending)' 은 수정본 미배포
  if(state.search){const term=state.search.toLocaleLowerCase();items=items.filter(item=>[item.cveId,item.package,item.resource].some(value=>String(value||'').toLocaleLowerCase().includes(term)));}
  return {items,total:items.length};
 },
 async history(){const q=query();q.delete('severity');q.delete('status');const result=await pages('/api/history',q);return {items:result.items,jobs:result.extra.jobs||[],warnings:Array.isArray(result.meta?.warnings)?result.meta.warnings:[],partial:result.meta?.partial===true};},
 async logout(){controller?.abort();generation++;await request('/api/auth/logout',{method:'POST',body:'{}'});reset();location.assign('/login');},
 async export(){const {items}=await pages('/api/events',query());const lines=[['ID','발생 시각','제목','위험도','리전','자원','탐지 소스','상태'],...items.map(e=>[e.id,e.observedAt,e.title,e.severity,e.region,e.resource,e.source,e.actionState])];const csv='\uFEFF'+lines.map(row=>row.map(csvCell).join(',')).join('\r\n');const url=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));const anchor=document.createElement('a');anchor.href=url;anchor.download='events.csv';anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
};
export function selectEvents({ignoreRegion=false}={}){return ignoreRegion?regional:rows;}
export function metricsFor(){return metric;}
export function servicesOf(){return infra;}
