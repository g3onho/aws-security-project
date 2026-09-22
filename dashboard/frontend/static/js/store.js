export const state={view:'overview',region:'ap-northeast-2',resource:'',environment:'production',hours:24,severity:'',status:'',source:'',search:'',endOffset:0,page:1,auto:false};
export let config={mode:'demo',writeEnabled:false,role:'viewer'};
export let DEMO_NOW=0;
let rows=[],regional=[],metric=null,services=null,csrf='',generation=0,controller;
const details=new Map();
export const summary={};
const statuses={NEW:'신규',PENDING_APPROVAL:'승인 대기',APPROVED:'승인됨',EXECUTING:'조치 실행 중',PENDING_VERIFICATION:'재검증 대기',VERIFYING:'재검증 중',RESOLVED:'해결',VERIFICATION_FAILED:'재검증 실패',EXECUTION_FAILED:'실행 실패'};
const execLabels={NOT_RUN:'미실행',RUNNING:'실행 중',SUCCEEDED:'성공',FAILED:'실패'};
const verifyLabels={NOT_RUN:'미실행',CHECKING:'검사 중',PASSED:'통과',FAILED:'실패'};
function normalize(e){return {...e,rawStatus:e.status,rawExecution:e.execution,rawVerification:e.verification,
 severity:e.severity[0]+e.severity.slice(1).toLowerCase(),status:statuses[e.status]||e.status,mode:e.mode==='AUTO'?'자동':'수동',execution:execLabels[e.execution],verification:verifyLabels[e.verification],before:e.before?.value??null,beforeMeasure:e.before,
 history:e.history||[]};}
export async function request(url,options={}){
 const res=await fetch(url,{credentials:'same-origin',...options,headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,...options.headers}});
 if(res.status===401){location.assign('/login');throw Error('로그인이 필요합니다.');}
 const data=await res.json();if(!res.ok)throw Error(data.title||'서버 요청에 실패했습니다.');return data;
}
export function query(){const to=(config.mode==='live'?Date.now():DEMO_NOW)-state.endOffset*3600000;return new URLSearchParams({from:to-state.hours*3600000,to,region:state.region,resource:state.resource||'',environment:state.environment,severity:state.severity.toUpperCase(),status:Object.keys(statuses).find(k=>statuses[k]===state.status)||'',source:state.source,q:state.search,view:state.view});}
export const api={
 async init(){const me=await request('/api/auth/session');if(!me.user){location.assign('/login');throw Error('로그인이 필요합니다.');}csrf=me.csrfToken;config=await request('/api/config');config.user=me.user;DEMO_NOW=config.asOf;},
 async load(){if(!DEMO_NOW)await this.init();const seq=++generation;controller?.abort();controller=new AbortController();const options={signal:controller.signal};const q=query();
 // 3계층 상태는 인프라 화면에서만 부른다. 실모드에서 ALB/CloudWatch 를 매 갱신마다 두드리지 않기 위해서다.
 const wantServices=state.view==='infrastructure';
 const mq=new URLSearchParams(q);if(wantServices)mq.set('scope','all');
 const [snapshot,m,health,svc]=await Promise.all([request('/api/snapshot?'+q,options),request('/api/metrics?'+mq,options),request('/health',options),
  wantServices?request('/api/services?'+q,options):Promise.resolve(null)]);
 if(seq!==generation)return false;
 rows=snapshot.items.map(normalize);regional=snapshot.regionalItems.map(normalize);metric=m&&m.resource?m:null;services=svc;Object.assign(summary,snapshot.summary,{snapshot:snapshot.snapshot,asOf:snapshot.asOf,collectedAt:snapshot.collectedAt,health});
 [...rows,...regional].forEach(e=>details.set(e.id,e));return true;},
 get(id){return details.get(id);},
 async detail(id){const e=normalize(await request('/api/events/'+encodeURIComponent(id)));details.set(id,e);return e;},
 async change(id,action,extra={}){const e=details.get(id);const result=await request('/api/events/'+encodeURIComponent(id)+'/'+action,{method:'POST',headers:{'Idempotency-Key':crypto.randomUUID()},body:JSON.stringify({expected_status:e.rawStatus,plan_hash:e.planHash,...extra})});const updated=normalize(result.event||result);details.set(id,updated);return result;},
 async job(id,jobId){return request('/api/events/'+encodeURIComponent(id)+'/executions/'+encodeURIComponent(jobId));},
 async scenarios(){return request('/api/scenarios?'+query());},
 async incidents(){return request('/api/incidents?'+query());},
 // 취약점은 기간 필터를 쓰지 않는다(최신 스캔 기준). 대상·수정가능 여부만 추가로 보낸다.
 async vulnerabilities({target='',fixableOnly=false}={}){const p=query();if(target)p.set('resource',target);else p.delete('resource');if(fixableOnly)p.set('fixableOnly','1');return request('/api/vulnerabilities?'+p);},
 async audit(){return request('/api/audit');},
 async nacls(){return request('/api/nacls?'+query());},
 async logout(){await request('/api/auth/logout',{method:'POST',body:'{}'});location.assign('/login');},
 async export(){const response=await fetch('/api/export/events.csv?'+query(),{credentials:'same-origin'});if(!response.ok)throw Error('CSV 내보내기에 실패했습니다.');const url=URL.createObjectURL(await response.blob());const a=document.createElement('a');a.href=url;a.download='aws-events.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
};
export function selectEvents({ignoreRegion=false}={}){return ignoreRegion?regional:rows;}
export function metricsFor(){return metric;}
export function servicesOf(){return services;}
// Legacy CSV formatter is kept separately in tests/fixtures; production export comes from Flask.
