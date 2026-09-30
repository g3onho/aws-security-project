// 보안 이벤트 '대응 현황': 자동으로 처리한 것 / 대시보드에서 조치할 수 있는 미조치 건 / 대시보드로는 못 하고 직접 조치해야 하는 건.
// 확인 기준은 재검증이 아니라 '이벤트가 아직 열려 있는가'다 — 고쳐지면 탐지가 목록에서 사라진다.
import {$,api,summary,selectEvents} from '../context.js?v=v42';
import {esc} from './format.js?v=v42';
import {patchMarkup} from './rendering.js?v=v42';
const cache={autoRows:[],attempts:new Map(),active:new Set(),manualDone:new Set(),externalDone:new Set(),loaded:false,error:null};
const SEV=['Critical','High','Medium','Low'];
const AUTO_TRIED=['auto-executed','auto-skipped'];
const ACTIVE_RUN=['STARTING','RUNNING','VERIFYING'];
export const REASON={manual:['수동 대응 필요','warn'],'auto-failed':['자동 조치 실패','bad'],'auto-open':['자동 조치 후에도 열려 있음','warn'],'auto-pending':['자동 조치 대상 · 실행 기록 없음','muted']};
// 이벤트마다 마지막 자동 조치 시도와, 지금 진행 중인 대시보드 조치를 모은다.
function absorb(data){
 const attempts=new Map();
 for(const r of data.items||[]){
  if(r.source!=='automatic'||!AUTO_TRIED.includes(r.decision)||!r.eventId)continue;
  const at=Date.parse(r.lastSeenAt||r.createdAt)||0,cur=attempts.get(r.eventId);
  if(!cur||cur.at<at)attempts.set(r.eventId,{at,status:r.automationStatus});
 }
 cache.attempts=attempts;
 cache.autoRows=(data.items||[]).filter(r=>r.source==='automatic'&&AUTO_TRIED.includes(r.decision)).sort((x,y)=>(Date.parse(y.lastSeenAt||y.createdAt)||0)-(Date.parse(x.lastSeenAt||x.createdAt)||0));
 cache.active=new Set((data.remediations||[]).filter(r=>ACTIVE_RUN.includes(r.state)).map(r=>r.eventId));
 // 통합 관제 퍼센트용: 대시보드 조치를 재검증까지 통과한 이벤트 / 조치 기록 없이 사라진 이벤트(외부 해결 추정)
 cache.manualDone=new Set((data.remediations||[]).filter(r=>['VERIFIED','ALREADY_COMPLIANT'].includes(r.state)&&r.eventId).map(r=>r.eventId));
 cache.externalDone=new Set((data.external||[]).map(r=>r.eventId).filter(Boolean));
 cache.loaded=true;cache.error=null;
}
export function classify(){
 const rows=selectEvents(),actionable=[],direct=[];let running=0;
 for(const e of rows){
  if(!e.dashboardAction){direct.push(e);continue;}
  const attempt=cache.attempts.get(e.id);
  if(attempt?.status==='IN_PROGRESS'||cache.active.has(e.id)){running++;continue;}
  const auto=e.dashboardAction.category==='auto-eligible';
  const reason=!auto?'manual':!attempt?'auto-pending':['FAILED','TIMED_OUT','CANCELLED'].includes(attempt.status)?'auto-failed':'auto-open';
  actionable.push({e,reason});
 }
 const rank=e=>SEV.indexOf(e.severity);
 actionable.sort((a,b)=>(a.reason==='auto-failed'?0:1)-(b.reason==='auto-failed'?0:1)||rank(a.e)-rank(b.e)||b.e.at-a.e.at);
 direct.sort((a,b)=>rank(a)-rank(b)||b.at-a.at);
 return {actionable,direct,running};
}
const n=v=>Number.isFinite(Number(v))?Number(v):0;
export const autoAttempts=()=>cache.autoRows;
const inner=()=>{
 const a=summary.automation,c=classify();
 const autoOk=!(a==null||a.configured===false);
 const autoCount=autoOk?(cache.loaded?cache.autoRows.length:n(a.autoExecuted)):null;
 const autoNote=!autoOk?(a==null?'자동 대응 기록을 불러오지 못했습니다.':'조치 이력 테이블이 설정되지 않았습니다.')
  :`자동 실행 · 성공 ${n(a.succeeded)} · 실패 ${n(a.failed)} · 진행 ${n(a.inProgress)}`;
 const by=k=>c.actionable.filter(x=>x.reason===k).length;
 const parts=[['수동 대응 필요','manual'],['자동 조치 실패','auto-failed'],['자동 조치 후에도 열려 있음','auto-open'],['자동 조치 대상 · 실행 기록 없음','auto-pending']]
  .map(([label,k])=>by(k)?`${label} ${by(k)}`:'').filter(Boolean);
 const btn=(key,label,count,tag,hint,disabled,tip)=>`<button type="button" class="er-btn er-${key}" data-bulk-open="${key}"${disabled?' disabled':''} title="${esc(tip)}" aria-label="${label} ${count==null?'집계 불가':count+'건'}. 누르면 목록이 열립니다."><i class="er-tag" aria-hidden="true">${tag}</i><span>${label}</span><b>${count==null?'—':count}<em>건</em></b><small>${hint}</small></button>`;
 const note=cache.error?' · 자동 조치 이력을 읽지 못해 자동 조치 실패 여부를 구분하지 못했습니다.':'';
 return `<div class="er-group event-response" data-key="event-response" role="group" aria-label="대응 현황">
  ${btn('auto','자동 대응',autoCount,'AUTO',autoOk?`성공 ${n(a.succeeded)} · 실패 ${n(a.failed)} · 진행 ${n(a.inProgress)}`:'집계 불가',!autoCount,autoNote)}${btn('manual','수동 대응',c.actionable.length,'MANUAL','대시보드에서 조치',!c.actionable.length,`대시보드에서 조치할 수 있는 미조치 항목: ${parts.join(' · ')||'없음'}${c.running?` · 진행 중 ${c.running}건은 제외`:''}${note}`)}${btn('direct','직접 조치',c.direct.length,'DIRECT','AWS 에서 직접 조치',!c.direct.length,'대시보드로 조치할 수 없어 AWS 에서 직접 조치해야 하는 항목')}</div>`;
};
export const eventResponseCard=()=>`<div id="event-response-box" data-key="event-response-box">${inner()}</div>`;
// 조치 이력(자동 조치 시도·진행 중인 대시보드 조치)을 읽어 카드를 다시 그린다. 실패해도 카드는 이벤트 기준으로 계속 보인다.
export async function loadEventResponse(){
 try{absorb(await api.history());}catch(error){if(error?.name==='AbortError')return;cache.error=error.message||'읽지 못함';}
 const box=$('#event-response-box');if(box)patchMarkup(box,inner());
 const toggle=$('.manual-toggle');if(toggle){const count=classify().actionable.length;toggle.textContent=`수동 대응 ${count}건`;toggle.hidden=!count;}
}

// 통합 관제 '자동 대응 현황' 세 카드의 숫자. 기준은 위 대응 현황 카드와 같다(같은 분류·같은 기간).
// 자동: 자동 실행 시도 중 실행 완료(SSM 성공, 재검증 전) / 수동: 대시보드 조치가 재검증을 통과한 건 / 직접: 조치 기록 없이 사라진 건(외부 해결 추정).
export function responseStats(){
 const a=summary.automation,c=classify(),n=v=>Math.max(0,Number(v)||0);
 const ready=cache.loaded&&!cache.error;
 return {loaded:cache.loaded,error:cache.error,
  auto:a==null||a.configured===false?null:{done:n(a.succeeded),total:n(a.autoExecuted),failed:n(a.failed),running:n(a.inProgress)},
  manual:ready?{done:cache.manualDone.size,open:c.actionable.length,failed:c.actionable.filter(x=>x.reason==='auto-failed').length}:null,
  direct:ready?{done:cache.externalDone.size,open:c.direct.length}:null};
}
