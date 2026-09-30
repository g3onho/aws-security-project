// 조치 이력(v32): 조치를 '시도'한 기록을 시간순 한 목록으로 보여준다. 줄마다 [방식]·[실행] 칩.
// 고쳐졌는지는 여기서 판정하지 않는다 — 보안 이벤트 목록에서 이벤트가 사라지는지로 확인한다(실행 성공 ≠ 해결).
// 아직 조치하지 않은 취약 항목은 여기 넣지 않는다 — 보안 이벤트 화면의 '수동 대응' 버튼(팝업)에서 확인한다.
import {$,api} from '../context.js?v=v45';
import {esc,format,milliseconds,shortResource} from '../components/format.js?v=v45';
import {loadPanel} from '../components/panel.js?v=v45';
import {recordTitle,DECISION_KO,AUTOMATION_KO,REMEDIATION_STATE} from '../components/remediation.js?v=v45';
// ── 분류 ───────────────────────────────────────────────────
export const WHO={auto:['자동','who'],dashboard:['대시보드','who'],external:['외부 해결(추정)','muted']};
export const EXEC={success:['실행 성공','ok'],failed:['실행 실패','bad'],running:['실행 중','run'],skipped:['실행 안 함','muted']};
export const VERIFY={passed:['재검증 통과','ok'],failed:['재검증 미통과','bad'],error:['재검증 읽기 실패','warn'],none:['재검증 안 함','muted'],running:['재검증 중','run']};
// [실행, 재검증]. 실행이 실패·진행 중이면 재검증은 해당 없음(null).
const AUTO_STATE={SUCCESS:['success','none'],NO_CHANGE:['success','none'],IN_PROGRESS:['running',null],FAILED:['failed',null],TIMED_OUT:['failed',null],CANCELLED:['failed',null]};
const RUN_STATE={VERIFIED:['success','passed'],ALREADY_COMPLIANT:['skipped','passed'],EXEC_FAILED:['failed',null],START_FAILED:['failed',null],
 NOT_RESOLVED:['success','failed'],VERIFY_ERROR:['success','error'],STARTING:['running',null],RUNNING:['running',null],VERIFYING:['success','running']};
const LEGACY_STATE={QUEUED:['running',null],RUNNING:['running',null],VERIFY_QUEUED:['success','running'],VERIFYING:['success','running'],VERIFIED:['success','passed'],
 EXECUTION_FAILED:['failed',null],VERIFICATION_ERROR:['success','error'],VERIFICATION_FAILED:['success','failed'],EXECUTED:['success','none']};
const JOB_KO={QUEUED:'대기',RUNNING:'실행 중',SUCCEEDED:'완료',FAILED:'실패'};
const at=r=>format(milliseconds(r.lastSeenAt||r.updatedAt||r.createdAt||r.resolvedAt));
const stamp=r=>milliseconds(r.lastSeenAt||r.updatedAt||r.createdAt||r.resolvedAt)||0;
const eventLink=id=>id&&api.get(id)?`<button class="link-button" data-event="${esc(id)}">탐지 보기</button>`:'';
const resourceText=r=>!r.resource?'—':r.resource.includes('←')?r.resource:shortResource(r.resource);
const firstLine=execution=>{const l=[...(execution?.removed||[]).map(x=>'− '+x),...(execution?.added||[]).map(x=>'+ '+x)];return l.length?l[0]+(l.length>1?` 외 ${l.length-1}줄`:''):'';};
function normalize(data){
 const rows=[];
 const add=(row,[exec,verify])=>rows.push({...row,exec,verify});
 for(const r of data.items||[]){
  if(r.source==='automatic'){
   if(!['auto-executed','auto-skipped'].includes(r.decision))continue;  // 알림만·판단만은 조치 시도가 아니다
   const detail=[r.reason,firstLine(r.execution),r.execution?.failureMessage].filter(Boolean)[0]||'';
   add({who:'auto',at:stamp(r),time:at(r),title:recordTitle(r),resource:resourceText(r),full:r.resource,
    eventId:r.eventId,what:r.playbookId||DECISION_KO[r.decision]||r.decision,detail,state:AUTOMATION_KO[r.automationStatus]||r.automationStatus||'',
    tip:r.executionId?'SSM 실행 '+r.executionId:''},AUTO_STATE[r.automationStatus]||['success','none']);
  }else add({who:'dashboard',at:stamp(r),time:at(r),title:esc(r.eventId),resource:'—',full:'',eventId:r.eventId,
   what:DECISION_KO[r.decision]||r.decision,detail:r.reason||'',state:r.actionState||'',tip:''},LEGACY_STATE[r.actionState]||['success','none']);
 }
 for(const r of data.remediations||[])add({who:'dashboard',at:stamp(r),time:at(r),
  title:esc(r.eventTitle||r.controlId||r.eventId),resource:resourceText(r),full:r.resource,eventId:r.eventId,what:r.playbookId,
  detail:r.error||r.verification?.text||r.reason||'',state:(REMEDIATION_STATE[r.state]||[r.state])[0],tip:r.executionId?'SSM 실행 '+r.executionId:'',by:r.actor},RUN_STATE[r.state]||['success','none']);
 for(const r of data.jobs||[])add({who:'dashboard',at:stamp(r),time:at(r),
  title:esc(r.eventId),resource:'—',full:'',eventId:r.eventId,what:r.jobId?`작업 ${r.jobId}`:(DECISION_KO[r.decision]||r.decision),detail:r.error||'',state:JOB_KO[r.status]||r.actionState||r.status||'',tip:''},
  LEGACY_STATE[r.actionState]||({FAILED:['failed',null],SUCCEEDED:['success','none']})[r.status]||['running',null]);
 // 외부 해결은 우리가 시도한 것이 아니므로 실행·재검증 칩이 없다.
 for(const r of data.external||[])rows.push({who:'external',exec:null,verify:null,at:stamp(r),time:at(r),title:esc(r.title||r.eventId),resource:resourceText(r),full:r.resource,
  eventId:r.eventId,what:'대시보드 기록 없이 사라짐',detail:'열린 탐지에서 사라졌고 대시보드·자동 조치 기록이 없어 외부에서 해결된 것으로 추정합니다. 실제 조치는 확인하지 못했습니다.',state:'',tip:'추정'});
 return rows.sort((a,b)=>b.at-a.at);
}
// 같은 이벤트를 여러 번 시도했으면 마지막 시도만 본다. 마지막 시도가 실패했거나 재검증을 통과하지 못했으면 주의 대상.
function attention(rows){
 const latest=new Map();
 for(const r of rows){if(r.who==='external')continue;const k=r.eventId||r.what+r.at;if(!latest.has(k)||latest.get(k).at<r.at)latest.set(k,r);}
 const failed=[];
 for(const r of latest.values()){
  if(r.exec==='failed'){failed.push(r);r.attn='bad';}
 }
 return {events:latest.size,failed};
}
const chip=([label,tone],extra='',cls='')=>`<span class="hist-chip ${cls||tone}"${extra}>${esc(label)}</span>`;
function line(r){
 const tipText=[r.state,r.tip].filter(Boolean).join(' · '),tip=tipText?` title="${esc(tipText)}"`:'';   // 상태 문구(재검증 전 등)는 칩 툴팁에 둔다
 const way=chip(WHO[r.who],'','who'),run=r.exec?chip(EXEC[r.exec],tip):'<span class="muted-mini">—</span>';
 return `<tr data-key="${esc(r.who+r.at+r.eventId+r.what)}"${r.attn?` class="attn-${r.attn}"`:''}><td class="hist-time">${r.time}</td><td class="hist-chips">${way}</td>
  <td><div class="record-target"><strong>${r.title}</strong><small><span class="resource-id" title="${esc(r.full||'')}">${esc(r.resource)}</span>${eventLink(r.eventId)}</small></div></td>
  <td class="hist-what"><b>${esc(r.what||'—')}</b>${r.detail?`<small class="hist-detail">${esc(r.detail)}</small>`:''}</td>
  <td class="hist-run">${run}</td></tr>`;
}
function summary(all){
 const tries=all.filter(r=>r.who!=='external'),a=attention(all);
 const n=(key,value)=>tries.filter(r=>r[key]===value).length;
 const alert=a.failed.length
  ?`<strong>주의 필요</strong> 마지막 시도가 실패한 이벤트 ${a.failed.length}건 — 보안 이벤트의 '수동 대응'에서 다시 조치하세요.`
  :`<strong>실패한 시도가 없습니다.</strong>`;
 const last=tries.length?` · 마지막 시도 ${tries[0].time} KST`:'';
 return `<div class="history-summary ${a.failed.length?'bad':'ok'}" role="status"><p>${alert}</p>
  <small>시도 ${tries.length}건(이벤트 ${a.events}개) · 실행 성공 ${n('exec','success')} · 실행 실패 ${n('exec','failed')}${last}. 실행 성공이 해결은 아닙니다 — 이벤트가 목록에서 사라졌는지로 확인하세요.</small></div>`;
}
export function renderAudit(){
 return loadPanel($('#audit-log'),()=>api.history(),data=>{
  const warn=(data.warnings||[]).map(w=>`<p class="panel-error" role="status">${esc(w)}</p>`).join('');
  const rows=normalize(data),sum=summary(rows);   // summary 가 attn 표시를 rows 에 남기므로 표보다 먼저 계산한다
  const table=rows.length?`<div class="table-scroll"><table class="history-grid hist-list"><caption class="sr-only">조치 시도 ${rows.length}건</caption>
   <colgroup><col><col><col><col><col></colgroup><thead><tr><th>시간 (KST)</th><th>방식</th><th>대상</th><th>내용</th><th>실행</th></tr></thead><tbody>${rows.map(line).join('')}</tbody></table></div>`
   :'<p class="history-empty">선택 기간에 조치 기록이 없습니다.</p>';
  return warn+sum+table+`
   <p class="muted">이력은 시간·리전·자원 범위로 조회합니다. 조치 기록은 30일 보존합니다. 아직 조치하지 않은 취약 항목은 보안 이벤트에서 확인하세요.</p>`;
 },'조치 이력');
}
