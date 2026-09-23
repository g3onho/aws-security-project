// Compatibility adapter for the unchanged frontend. New integrations use the
// canonical API; this module alone translates its existing calls to /api/legacy.
const defaults={view:'overview',region:'ap-northeast-2',resource:'',environment:'production',hours:24,severity:'',status:'',source:'',search:'',endOffset:0,page:1,auto:false};
export const state={...defaults};
export let config={mode:'live',writeEnabled:false,role:'viewer'};
export let DATA_AS_OF=0;
export const summary={};
let rows=[],regional=[],metric=null,services=null,csrf='',generation=0,sessionEpoch=0,controller,initializing;
const details=new Map();
const statuses={NEW:'신규',PENDING_APPROVAL:'승인 대기',APPROVED:'승인됨',EXECUTING:'조치 실행 중',PENDING_VERIFICATION:'재검증 대기',VERIFYING:'재검증 중',RESOLVED:'해결',VERIFICATION_FAILED:'재검증 실패',EXECUTION_FAILED:'실행 실패'};
const executionLabels={NOT_RUN:'미실행',RUNNING:'실행 중',SUCCEEDED:'성공',FAILED:'실패'};
const verificationLabels={NOT_RUN:'미실행',CHECKING:'검사 중',PASSED:'통과',FAILED:'실패'};
const actions=new Set(['approve','cancel','execute','verify']);
const object=value=>value!==null&&typeof value==='object'&&!Array.isArray(value);
function requireContract(valid){if(!valid)throw Error('서버 데이터 형식이 올바르지 않습니다. 새로고침 후 다시 확인해주세요.');}
function normalize(event){
 requireContract(object(event));
 requireContract(['id','title','resource','scenario','region','source','actionState'].every(key=>typeof event[key]==='string'&&event[key].length>0));
 requireContract(['CRITICAL','HIGH','MEDIUM','LOW'].includes(event.severity)&&Object.hasOwn(statuses,event.status));
 requireContract(['AUTO','MANUAL'].includes(event.mode)&&Object.hasOwn(executionLabels,event.execution)&&Object.hasOwn(verificationLabels,event.verification));
 requireContract(Number.isFinite(event.at)&&Number.isInteger(event.version)&&event.version>0&&typeof event.planHash==='string');
 requireContract(typeof event.actionable==='boolean'&&Array.isArray(event.allowedActions)&&event.allowedActions.every(action=>actions.has(action)));
 requireContract(Array.isArray(event.history)&&event.history.every(item=>object(item)&&Number.isFinite(item.at)&&typeof item.text==='string'));
 requireContract(event.before===null||object(event.before));
 return {...event,rawStatus:event.status,rawActionState:event.actionState,rawExecution:event.execution,rawVerification:event.verification,
  severity:event.severity[0]+event.severity.slice(1).toLowerCase(),status:statuses[event.status],mode:event.mode==='AUTO'?'자동':'수동',
  execution:executionLabels[event.execution],verification:verificationLabels[event.verification],
  before:event.before?.value??null,beforeMeasure:event.before,allowedActions:[...event.allowedActions]};
}
function endpoint(url){
 if(url==='/health'||url.startsWith('/health?'))return url.replace('/health','/api/legacy/health');
 if(url.startsWith('/api/')&&!url.startsWith('/api/auth/')&&!url.startsWith('/api/legacy/'))return url.replace('/api/','/api/legacy/');
 return url;
}
function reset(){
 controller?.abort();generation++;sessionEpoch++;initializing=null;csrf='';DATA_AS_OF=0;
 rows=[];regional=[];metric=null;services=null;details.clear();
 for(const key of Object.keys(summary))delete summary[key];
 config={mode:'live',writeEnabled:false,role:'viewer'};Object.assign(state,defaults);
}
export async function request(url,options={}){
 const headers=new Headers(options.headers||{});headers.set('Content-Type','application/json');headers.set('X-CSRF-Token',csrf);
 const response=await fetch(endpoint(url),{...options,credentials:'same-origin',headers});
 if(response.status===401){reset();location.assign('/login');throw Error('로그인이 필요합니다.');}
 let data;try{data=await response.json();}catch{throw Error('서버 응답을 읽을 수 없습니다. 다시 시도해주세요.');}
 if(!response.ok)throw Error(data?.title||data?.error?.message||'서버 요청에 실패했습니다.');
 return data;
}
export function query(){
 const to=Date.now()-state.endOffset*3600000;
 return new URLSearchParams({from:to-state.hours*3600000,to,region:state.region,resource:state.resource||'',environment:state.environment,
  severity:state.severity.toUpperCase(),status:Object.keys(statuses).find(key=>statuses[key]===state.status)||'',source:state.source,q:state.search,view:state.view});
}
async function collection(url){const data=await request(url);requireContract(object(data)&&Array.isArray(data.items));return data;}
function activeSession(epoch){if(epoch!==sessionEpoch)throw new DOMException('세션이 변경되었습니다.','AbortError');}
export const api={
 async init(){
  if(!initializing)initializing=(async()=>{
   const epoch=sessionEpoch;
   const session=await request('/api/auth/session');
   activeSession(epoch);
   if(!session?.user){reset();location.assign('/login');throw Error('로그인이 필요합니다.');}
   requireContract(object(session.user)&&typeof session.user.name==='string'&&typeof session.csrfToken==='string');
   csrf=session.csrfToken;
   const loaded=await request('/api/config');
   activeSession(epoch);
   requireContract(object(loaded)&&loaded.mode==='live'&&typeof loaded.writeEnabled==='boolean'&&Number.isFinite(loaded.asOf));
   requireContract(['viewer','approver','operator'].includes(loaded.role));
   config={...loaded,user:session.user};DATA_AS_OF=loaded.asOf;
  })().catch(error=>{initializing=null;throw error;});
  return initializing;
 },
 async load(){
  if(!DATA_AS_OF)await this.init();
  const current=++generation;controller?.abort();controller=new AbortController();
  const options={signal:controller.signal},q=query(),mq=new URLSearchParams(q);
  const wantServices=state.view==='infrastructure';if(wantServices)mq.set('scope','all');
  const [snapshot,m,health,svc]=await Promise.all([request('/api/snapshot?'+q,options),request('/api/metrics?'+mq,options),request('/health',options),wantServices?request('/api/services?'+q,options):Promise.resolve(null)]);
  if(current!==generation)return false;
  requireContract(object(snapshot)&&Array.isArray(snapshot.items)&&Array.isArray(snapshot.regionalItems)&&object(snapshot.summary));
  requireContract(object(health)&&object(health.checks));
  requireContract(m===null||object(m));if(svc!==null)requireContract(object(svc)&&Array.isArray(svc.items));
  const nextRows=snapshot.items.map(normalize),nextRegional=snapshot.regionalItems.map(normalize);
  rows=nextRows;regional=nextRegional;metric=m?.resource?m:null;services=svc;
  Object.assign(summary,snapshot.summary,{snapshot:snapshot.snapshot,asOf:snapshot.asOf,collectedAt:snapshot.collectedAt,health});
  DATA_AS_OF=snapshot.asOf;
  details.clear();for(const event of [...rows,...regional])details.set(event.id,event);
  return true;
 },
 get(id){return details.get(id);},
 async detail(id){const epoch=sessionEpoch,event=normalize(await request('/api/events/'+encodeURIComponent(id)));activeSession(epoch);details.set(id,event);return event;},
 async change(id,action,extra={}){
  const event=details.get(id)||await this.detail(id);
  const epoch=sessionEpoch;
  if(!actions.has(action)||!event.allowedActions.includes(action))throw Error('현재 권한과 상태에서 허용되지 않는 조치입니다. 새로고침해주세요.');
  const body={...extra,expected_status:event.rawStatus,plan_hash:event.planHash,expected_version:event.version};
  const result=await request('/api/events/'+encodeURIComponent(id)+'/'+action,{method:'POST',headers:{'Idempotency-Key':crypto.randomUUID()},body:JSON.stringify(body)});
  activeSession(epoch);const updated=normalize(result.event||result);details.set(id,updated);return result;
 },
 async job(id,jobId){const result=await request('/api/events/'+encodeURIComponent(id)+'/executions/'+encodeURIComponent(jobId));requireContract(object(result)&&object(result.execution)&&['RUNNING','SUCCEEDED','FAILED'].includes(result.execution.status));return result;},
 async scenarios(){return collection('/api/scenarios?'+query());},
 async incidents(){return collection('/api/incidents?'+query());},
 async vulnerabilities({target='',fixableOnly=false}={}){
  const q=query();if(target)q.set('resource',target);else q.delete('resource');if(fixableOnly)q.set('fixableOnly','1');
  const data=await collection('/api/vulnerabilities?'+q);requireContract(Array.isArray(data.groups)&&object(data.summary)&&object(data.summary.bySeverity));return data;
 },
 async audit(){return collection('/api/audit');},
 async nacls(){return collection('/api/nacls?'+query());},
 async logout(){controller?.abort();generation++;await request('/api/auth/logout',{method:'POST',body:'{}'});reset();location.assign('/login');},
 async export(){
  const response=await fetch(endpoint('/api/export/events.csv?'+query()),{credentials:'same-origin'});
  if(response.status===401){reset();location.assign('/login');throw Error('로그인이 필요합니다.');}
  if(!response.ok)throw Error('CSV 내보내기에 실패했습니다.');
  const url=URL.createObjectURL(await response.blob()),anchor=document.createElement('a');anchor.href=url;anchor.download='events.csv';anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 }
};
export function selectEvents({ignoreRegion=false}={}){return ignoreRegion?regional:rows;}
export function metricsFor(){return metric;}
export function servicesOf(){return services;}
