// 주소창 ↔ 필터·열린 이벤트 동기화.
import {regions,statuses,sources} from './constants.js?v=v44';
import {state,setFilters,ui} from './context.js?v=v44';
export const titles={overview:['통합 관제','Overview'],events:['보안 이벤트','Security events'],vulnerabilities:['취약점 점검','Vulnerabilities'],infrastructure:['인프라 모니터링','Infrastructure'],responses:['조치 이력','Remediation history'],drills:['보안 시나리오','Security scenarios'],honeypot:['허니팟','Honeypot']};
// ── 주소창 상태 동기화 ────────────────────────────────────
// 새로고침하면 필터가 초기화되던 문제. 화면·필터·열어둔 이벤트를 주소에 담아
// 복구와 링크 공유가 되게 한다. 뒤로가기는 **화면 전환과 상세 열기만** 쌓는다 —
// 검색어 한 글자마다 히스토리가 쌓이면 뒤로가기가 못 쓰게 된다.
const URL_DEFAULTS={view:'overview',region:'all',resource:'',hours:24,endOffset:0,severity:'',status:'',source:'',search:'',page:1};
const URL_KEYS={view:'view',region:'region',resource:'resource',hours:'hours',endOffset:'back',severity:'severity',status:'status',source:'source',search:'q',page:'page'};
export function urlFromState(){
 const p=new URLSearchParams();
 for(const [key,param] of Object.entries(URL_KEYS)){
  const value=state[key];
  if(value!==undefined&&value!==null&&String(value)!==String(URL_DEFAULTS[key]))p.set(param,String(value));
 }
 if(ui.activeId)p.set('event',ui.activeId);
 const qs=p.toString();
 return window.location.pathname+(qs?'?'+qs:'');
}
export function syncUrl(push=false){
 const next=urlFromState();
 if(next===window.location.pathname+window.location.search)return;
 try{window.history[push?'pushState':'replaceState']({},'',next);}catch(error){/* 주소 갱신 실패는 화면을 막지 않는다 */}
}
export function applyUrl(){
 const p=new URLSearchParams(window.location.search),next={};
 for(const [key,param] of Object.entries(URL_KEYS)){
  if(!p.has(param)){next[key]=URL_DEFAULTS[key];continue;}
  const raw=p.get(param);
  const value=typeof URL_DEFAULTS[key]==='number'?Number(raw):raw;
  next[key]=(typeof URL_DEFAULTS[key]==='number'&&!Number.isFinite(value))?URL_DEFAULTS[key]:value;
 }
 if(!titles[next.view])next.view=URL_DEFAULTS.view;      // 주소에 잘못된 화면이 와도 죽지 않는다
 if(!['all',...regions.map(r=>r.id)].includes(next.region)&&!/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(next.region))next.region=URL_DEFAULTS.region;
 if(!['','Critical','High','Medium','Low'].includes(next.severity))next.severity='';
 if(!['',...statuses,'승인됨','실행 실패'].includes(next.status))next.status='';
 if(!['',...sources].includes(next.source))next.source='';
 if(![.25,1,24,168].includes(next.hours))next.hours=24;
 next.endOffset=0;   // 되감기 없음 — 항상 지금 기준(v20.5, 옛 주소의 back 값은 무시)
 next.page=Math.max(1,Math.floor(next.page));
 next.search=String(next.search).slice(0,200);
 setFilters(next);
 return p.get('event')||'';
}
