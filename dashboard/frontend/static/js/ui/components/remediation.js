// 자동 조치 표시 공통(v23): 판정·상태 한글 이름, 자동 조치 여부 칩, 조치 전/후 바뀐 줄. 통합 관제·탐지 상세·조치 이력이 함께 쓴다.
import {esc,format,milliseconds} from './format.js?v=v44';
export const DECISION_KO={'auto-executed':'자동 실행','auto-skipped':'실행 생략(이미 조치됨)','manual-notified':'수동 대응 필요','dry-run':'판단만(dry-run)',
 approve:'승인',cancel:'승인 취소',execute:'실행 접수',verify:'재검증 접수','execute-completed':'실행 결과','verify-completed':'재검증 결과'};
// SUCCESS 는 SSM 실행 성공이다. 같은 조건으로 다시 확인한 재검증이 아니다.
export const AUTOMATION_KO={NOTIFIED:'담당자 알림',DRY_RUN:'실행 안 함(dry-run)',IN_PROGRESS:'실행 중',SUCCESS:'실행 완료 · 재검증 전',
 FAILED:'실행 실패',TIMED_OUT:'시간 초과',CANCELLED:'취소됨',NO_CHANGE:'변경 없음',UNKNOWN:'확인 불가'};
const STATE_TONE={SUCCESS:'ok',IN_PROGRESS:'run',FAILED:'bad',TIMED_OUT:'bad',CANCELLED:'bad',NOTIFIED:'warn',DRY_RUN:'muted',NO_CHANGE:'muted',UNKNOWN:'muted'};
export function automationState(status){return `<span class="auto-state ${STATE_TONE[status]||'muted'}">${esc(AUTOMATION_KO[status]||status||'—')}</span>`;}
// 조치 API 자체가 서버에 없을 때(404, 서버가 구버전이거나 다른 서버). 이벤트·기록이 없다는 404(…_NOT_FOUND)와 구분한다.
export const remediationApiMissing=error=>error?.status===404&&!/_NOT_FOUND$/.test(error?.code||'');
export const REMEDIATION_API_MISSING='이 서버에는 조치 API가 없습니다(/api/remediations). 서버가 구버전이거나 다른 서버일 수 있습니다. 조치 건수 0건이 아니라 조치 기능을 사용할 수 없는 상태입니다.';
export const remediationErrorText=error=>remediationApiMissing(error)?REMEDIATION_API_MISSING:(error?.message||'알 수 없는 오류');
// 자동 조치 판정(설정 기준 예상). unknown 은 '수동'으로 보이지 않게 따로 표시한다.
const MODE_TONE={auto:'ok',conditional:'run','dry-run':'muted',manual:'warn',none:'muted',unknown:'muted'};
export function autoChip(auto,{short=false}={}){
 if(!auto||typeof auto.mode!=='string')return '';
 if(short&&!['auto','conditional','dry-run'].includes(auto.mode))return '';
 return `<span class="auto-chip ${MODE_TONE[auto.mode]||'muted'}" title="${esc(auto.reason||'')}">${esc(auto.label||auto.mode)}</span>`;
}
// 조치 이력·요약 한 줄의 대상 이름: 규칙 ID · 한글 이름 → 탐지 제목 → finding ID
export function recordTitle(r){
 if(r.controlTitle)return `${r.controlId&&!/^SEC-/.test(r.controlId)?esc(r.controlId)+' · ':''}${esc(r.controlTitle)}`;
 return esc(r.findingType||r.findingId||r.eventId||'—');
}
// SSM 보고값(조치 직후) — 없어진 줄·생긴 줄. 재검증이 아니라는 표시를 함께 단다.
export function changeList(execution,{limit=6}={}){
 if(!execution)return '';
 const removed=execution.removed||[],added=execution.added||[];
 const lines=[...removed.slice(0,limit).map(l=>`<li class="removed"><span aria-hidden="true">−</span>${esc(l)}</li>`),
  ...added.slice(0,limit).map(l=>`<li class="added"><span aria-hidden="true">+</span>${esc(l)}</li>`)];
 const more=removed.length+added.length-lines.length;
 const running=['InProgress','Pending','Waiting','Scheduled','PendingApproval','RunbookInProgress'].includes(execution.status);
 const empty=running?'실행 중 — 끝나면 조치 전/후가 표시됩니다.':execution.changed===false?'이미 기준을 만족해 바꾼 것이 없습니다.'
  :execution.failureMessage?esc(execution.failureMessage):'바뀐 줄 정보 없음';
 const body=lines.length?`<ul class="change-list">${lines.join('')}${more>0?`<li class="more">외 ${more}줄</li>`:''}</ul>`
  :`<p class="muted-mini">${empty}</p>`;
 return body+`<p class="muted-mini">조치 직후 SSM 보고값 · 재검증 전${execution.status?` · SSM ${esc(execution.status)}`:''}</p>`;
}

// ── 대시보드 원클릭 조치(v29) ─────────────────────────────────────────────
// 상태 = 실행과 해결을 따로 보여준다. '해결 확인'은 실행 뒤 같은 기준으로 다시 읽어 통과했을 때만이다.
export const REMEDIATION_STATE={
 STARTING:['시작 중','run'],RUNNING:['실행 중','run'],VERIFYING:['재검증 중','run'],
 VERIFIED:['해결 확인 · 재검증 통과','ok'],NOT_RESOLVED:['실행됨 · 재검증 미통과','bad'],
 EXEC_FAILED:['실행 실패','bad'],VERIFY_ERROR:['재검증 오류 · 결과 미확인','warn'],
 ALREADY_COMPLIANT:['이미 기준 충족 · 실행 안 함','muted'],START_FAILED:['시작 실패 · 변경 없음','bad']};
export const REMEDIATION_ACTIVE=['STARTING','RUNNING','VERIFYING'];
export const REMEDIATION_FAILED=['EXEC_FAILED','NOT_RESOLVED','VERIFY_ERROR','START_FAILED'];
export function remediationState(state){const [label,tone]=REMEDIATION_STATE[state]||[state||'상태 미상','muted'];return `<span class="auto-state ${tone}">${esc(label)}</span>`;}
// 조치 전/후 값과 재검증 결과 한 묶음. 재검증 값이 없으면 없다고 밝힌다.
export function remediationDetail(r){
 const before=r.before?.text,after=r.verification?.text||r.after?.text;
 const lines=[];
 if(before)lines.push(`<li><span>조치 전</span><span>${esc(before)}</span></li>`);
 if(after)lines.push(`<li><span>재검증</span><span>${esc(after)}${r.verification?.checkedAt?` <small>${esc(format(milliseconds(r.verification.checkedAt)))} KST</small>`:''}</span></li>`);
 else if(REMEDIATION_ACTIVE.includes(r.state))lines.push('<li><span>재검증</span><span>실행이 끝나면 같은 기준으로 다시 읽습니다.</span></li>');
 if(r.executionId)lines.push(`<li><span>SSM 실행</span><span><code>${esc(r.executionId)}</code>${r.ssmStatus?` · ${esc(r.ssmStatus)}`:''}</span></li>`);
 if(r.error)lines.push(`<li class="bad"><span>알림</span><span>${esc(r.error)}</span></li>`);
 return `<ul class="rem-facts-list">${lines.join('')}</ul>`;
}
