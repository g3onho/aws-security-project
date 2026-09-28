// 조치 이력(v23): 자동 조치 실행 기록과 사람이 대응해야 하는 기록을 나눠 보여준다. '실행 완료'는 재검증 전.
import {$,api} from '../context.js?v=ui-1';
import {esc,format,milliseconds,shortResource} from '../components/format.js?v=ui-1';
import {loadPanel} from '../components/panel.js?v=ui-1';
import {automationState,changeList,recordTitle,DECISION_KO} from '../components/remediation.js?v=ui-1';
// ── 조치 이력 ──────────────────────────────────────────────
const at=r=>format(milliseconds(r.lastSeenAt||r.createdAt));
// 원래 탐지가 지금 조회 범위에 있으면 상세 창으로 잇는다.
const eventLink=r=>r.eventId&&api.get(r.eventId)?`<button class="link-button" data-event="${esc(r.eventId)}">탐지 보기</button>`:'';
// NACL 차단 기록의 자원은 'acl-… ← 10.0.2.15/32' 형태 — 줄이지 않고 그대로 보여준다.
const resourceText=r=>!r.resource?'—':r.resource.includes('←')?r.resource:shortResource(r.resource);
function target(r){return `<div class="record-target"><strong>${recordTitle(r)}</strong><small><span class="resource-id" title="${esc(r.resource||'')}">${esc(resourceText(r))}</span>${eventLink(r)}</small></div>`;}
// 자동 실행: 무엇을(플레이북) 어떻게 바꿨는지(SSM 보고값 전/후).
function executedRow(r){
 const change=r.execution?changeList(r.execution):`<p class="muted-mini">${esc(r.beforeState?.text||'—')} → ${esc(r.afterState?.text||'—')}</p>`;
 return `<tr><td>${at(r)}</td><td>${target(r)}</td><td><span title="${esc(r.executionId?'SSM 실행 '+r.executionId:'')}">${esc(r.playbookId||DECISION_KO[r.decision]||r.decision)}</span><br>${automationState(r.automationStatus)}</td><td class="change-cell">${change}</td><td class="reason-cell">${esc(r.reason||'—')}</td></tr>`;
}
// 수동 대응 필요·판단만: 왜 자동으로 안 고쳤는지(판정 이유)와 반복 횟수.
function pendingRow(r){
 return `<tr><td>${at(r)}</td><td>${target(r)}</td><td>${esc(DECISION_KO[r.decision]||r.decision)}<br>${automationState(r.automationStatus)}</td><td class="reason-cell">${esc(r.reason||'판정 이유 기록 없음(이전 형식 기록)')}</td><td>${esc(r.occurrenceCount??1)}회</td></tr>`;
}
function manualRow(r){return `<tr><td>${at(r)}</td><td>${esc(r.eventId)}</td><td>${esc(DECISION_KO[r.decision]||r.decision)}</td><td>${esc(r.actionState)}</td><td>${esc(r.reason||'—')}</td></tr>`;}
const table=(caption,heads,rows)=>`<div class="table-scroll"><table><caption class="sr-only">${caption}</caption><thead><tr>${heads.map(h=>`<th>${h}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div>`;
export function renderAudit(){
 return loadPanel($('#audit-log'),()=>api.history(),data=>{
  const warn=(data.warnings||[]).map(w=>`<p class="panel-error" role="status">${esc(w)}</p>`).join('');
  const auto=data.items.filter(r=>r.source==='automatic'),manual=data.items.filter(r=>r.source!=='automatic');
  const executed=auto.filter(r=>['auto-executed','auto-skipped'].includes(r.decision)),pending=auto.filter(r=>!executed.includes(r));
  const failed=executed.filter(r=>['FAILED','TIMED_OUT','CANCELLED'].includes(r.automationStatus)).length;
  const summary=`<p class="muted">자동 ${auto.length}건(실행 ${executed.length}건${failed?` · 실패 ${failed}건`:''}) · 수동 대응 필요·판단만 ${pending.length}건${manual.length?` · 대시보드 수동 기록 ${manual.length}건`:''} · 같은 탐지의 반복 판정은 한 줄로 합쳐 횟수로 표시합니다.</p>`;
  const sections=data.items.length?summary
   +`<h3 class="history-title">자동 조치 실행 <small>${executed.length}건 · '실행 완료'는 SSM 실행 성공이며 재검증 전입니다</small></h3>`
   +(executed.length?table('자동 실행 기록',['마지막 시각 (KST)','대상','조치 · 상태','바뀐 내용 (조치 직후 SSM 보고값)','판정 이유'],executed.map(executedRow).join('')):'<p class="muted">선택 기간에 자동 실행 기록이 없습니다.</p>')
   +`<h3 class="history-title">수동 대응 필요 · 판단만 <small>${pending.length}건 · 자동 조치 대상이 아니거나 조건이 맞지 않아 담당자에게 알린 기록</small></h3>`
   +(pending.length?table('수동 대응 필요 기록',['마지막 시각 (KST)','대상','판정 · 상태','판정 이유','횟수'],pending.map(pendingRow).join('')):'<p class="muted">선택 기간에 수동 대응이 필요한 기록이 없습니다.</p>')
   +(manual.length?`<h3 class="history-title">대시보드 수동 기록</h3>`+table('대시보드 수동 기록',['시각 (KST)','이벤트','작업','상태','사유'],manual.map(manualRow).join('')):'')
   :'<p class="muted">조회 기간에 기록된 조치가 없습니다.</p>';
  const jobs=data.jobs.length?`<h3>작업 상태</h3><div class="table-scroll"><table><thead><tr><th>작업 ID</th><th>이벤트</th><th>상태</th><th>오류</th></tr></thead><tbody>${data.jobs.map(job=>`<tr><td>${esc(job.jobId)}</td><td>${esc(job.eventId)}</td><td>${esc(job.status)}</td><td>${esc(job.error||'—')}</td></tr>`).join('')}</tbody></table></div>`:'';
  return warn+sections+jobs+'<p class="muted">이력은 시간·리전·자원 범위로 조회합니다. 조치 기록은 30일 보존합니다.</p>';
 },'조치 이력');
}
