export const state={view:'overview',region:'ap-northeast-2',environment:'production',hours:24,severity:'',status:'',source:'',search:'',endOffset:0,page:1};
export let config={mode:'demo',writeEnabled:false,role:'viewer'};
export let DEMO_NOW=0;
let rows=[],regional=[],metric=null,csrf='',generation=0,controller;
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
export function query(){const to=DEMO_NOW-state.endOffset*3600000;return new URLSearchParams({from:to-state.hours*3600000,to,region:state.region,environment:state.environment,severity:state.severity.toUpperCase(),status:Object.keys(statuses).find(k=>statuses[k]===state.status)||'',source:state.source,q:state.search,view:state.view});}
export const api={
 async init(){const me=await request('/api/auth/session');if(!me.user){location.assign('/login');throw Error('로그인이 필요합니다.');}csrf=me.csrfToken;config=await request('/api/config');config.user=me.user;DEMO_NOW=config.asOf;},
 async load(){if(!DEMO_NOW)await this.init();const seq=++generation;controller?.abort();controller=new AbortController();const options={signal:controller.signal};const q=query();
 const [snapshot,m,health]=await Promise.all([request('/api/snapshot?'+q,options),request('/api/metrics?'+q,options),request('/health',options)]);
 if(seq!==generation)return false;
 rows=snapshot.items.map(normalize);regional=snapshot.regionalItems.map(normalize);metric=m.resource?m:null;Object.assign(summary,snapshot.summary,{snapshot:snapshot.snapshot,asOf:snapshot.asOf,collectedAt:snapshot.collectedAt,health});
 [...rows,...regional].forEach(e=>details.set(e.id,e));return true;},
 get(id){return details.get(id);},
 async detail(id){const e=normalize(await request('/api/events/'+encodeURIComponent(id)));details.set(id,e);return e;},
 async change(id,action){const e=details.get(id);const result=await request('/api/events/'+encodeURIComponent(id)+'/'+action,{method:'POST',headers:{'Idempotency-Key':crypto.randomUUID()},body:JSON.stringify({expected_status:e.rawStatus,plan_hash:e.planHash})});const updated=normalize(result.event||result);details.set(id,updated);return result;},
 async job(id,jobId){return request('/api/events/'+encodeURIComponent(id)+'/executions/'+encodeURIComponent(jobId));},
 async logout(){await request('/api/auth/logout',{method:'POST',body:'{}'});location.assign('/login');},
 async export(){const response=await fetch('/api/export/events.csv?'+query(),{credentials:'same-origin'});if(!response.ok)throw Error('CSV 내보내기에 실패했습니다.');const url=URL.createObjectURL(await response.blob());const a=document.createElement('a');a.href=url;a.download='aws-events.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
};
export function selectEvents({ignoreRegion=false}={}){return ignoreRegion?regional:rows;}
export function metricsFor(){return metric;}
// Legacy CSV formatter is kept separately in tests/fixtures; production export comes from Flask.
