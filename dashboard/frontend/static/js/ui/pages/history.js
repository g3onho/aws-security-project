// 대응 이력: 자동조치 기록과 수동 기록 한 표. '실행 완료'는 재검증 전.
import {$,api} from '../context.js?v=ui-1';
import {esc,format,milliseconds,shortResource} from '../components/format.js?v=ui-1';
import {loadPanel} from '../components/panel.js?v=ui-1';
// ── 조치 이력 ──────────────────────────────────────────────

// v20: DynamoDB 자동조치 기록(source=automatic)과 대시보드 수동 기록을 한 표로. '실행 완료'는 재검증 전이다.
const DECISION_KO={'auto-executed':'자동 실행','manual-notified':'수동 대응 필요','dry-run':'판단만(dry-run)',approve:'승인',cancel:'승인 취소',execute:'실행 접수',verify:'재검증 접수','execute-completed':'실행 결과','verify-completed':'재검증 결과'};
const AUTOMATION_KO={NOTIFIED:'담당자 알림',DRY_RUN:'실행 안 함(dry-run)',IN_PROGRESS:'실행 중',SUCCESS:'실행 완료 · 재검증 전',FAILED:'실행 실패',TIMED_OUT:'시간 초과',CANCELLED:'취소됨',UNKNOWN:'확인 불가'};
function auditRow(r){
 const auto=r.source==='automatic',state=auto?(AUTOMATION_KO[r.automationStatus]||r.automationStatus):r.actionState;
 const target=auto?`${esc(r.findingType||r.findingId)}<small><span class="resource-id" title="${esc(r.resource||'')}">${esc(shortResource(r.resource||'—'))}</span></small>`:esc(r.eventId);
 return `<tr><td>${format(milliseconds(r.lastSeenAt||r.createdAt))}</td><td>${auto?'자동':'수동'}</td><td>${target}</td><td>${esc(DECISION_KO[r.decision]||r.decision)}</td><td>${esc(state)}</td><td>${auto?esc(r.occurrenceCount??1):'—'}</td><td>${esc(r.executionId||'—')}</td></tr>`;
}
export function renderAudit(){
 return loadPanel($('#audit-log'),()=>api.history(),data=>{
  const warn=(data.warnings||[]).map(w=>`<p class="panel-error" role="status">${esc(w)}</p>`).join('');
  const autoCount=data.items.filter(r=>r.source==='automatic').length;
  const audits=data.items.length?`<p class="muted">자동 ${autoCount}건 · 수동 ${data.items.length-autoCount}건 · 같은 탐지의 반복 판정은 한 줄로 합쳐 횟수로 표시합니다.</p><div class="table-scroll"><table><caption class="sr-only">대응 이력</caption><thead><tr><th>마지막 시각 (KST)</th><th>구분</th><th>대상</th><th>판정</th><th>상태</th><th>횟수</th><th>실행 ID</th></tr></thead><tbody>${data.items.map(auditRow).join('')}</tbody></table></div>`:'<p class="muted">조회 기간에 기록된 조치가 없습니다.</p>';
  const jobs=data.jobs.length?`<h3>작업 상태</h3><div class="table-scroll"><table><thead><tr><th>작업 ID</th><th>이벤트</th><th>상태</th><th>오류</th></tr></thead><tbody>${data.jobs.map(job=>`<tr><td>${esc(job.jobId)}</td><td>${esc(job.eventId)}</td><td>${esc(job.status)}</td><td>${esc(job.error||'—')}</td></tr>`).join('')}</tbody></table></div>`:'';
  return warn+audits+jobs+'<p class="muted">이력은 시간·리전·자원 범위로 조회합니다.</p>';
 },'조치 이력');
}
