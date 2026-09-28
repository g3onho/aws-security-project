// 자동 조치 표시 공통(v23): 판정·상태 한글 이름, 자동 조치 여부 칩, 조치 전/후 바뀐 줄. 통합 관제·탐지 상세·조치 이력이 함께 쓴다.
import {esc} from './format.js?v=ui-1';
export const DECISION_KO={'auto-executed':'자동 실행','auto-skipped':'실행 생략(이미 조치됨)','manual-notified':'수동 대응 필요','dry-run':'판단만(dry-run)',
 approve:'승인',cancel:'승인 취소',execute:'실행 접수',verify:'재검증 접수','execute-completed':'실행 결과','verify-completed':'재검증 결과'};
// SUCCESS 는 SSM 실행 성공이다. 같은 조건으로 다시 확인한 재검증이 아니다.
export const AUTOMATION_KO={NOTIFIED:'담당자 알림',DRY_RUN:'실행 안 함(dry-run)',IN_PROGRESS:'실행 중',SUCCESS:'실행 완료 · 재검증 전',
 FAILED:'실행 실패',TIMED_OUT:'시간 초과',CANCELLED:'취소됨',NO_CHANGE:'변경 없음',UNKNOWN:'확인 불가'};
const STATE_TONE={SUCCESS:'ok',IN_PROGRESS:'run',FAILED:'bad',TIMED_OUT:'bad',CANCELLED:'bad',NOTIFIED:'warn',DRY_RUN:'muted',NO_CHANGE:'muted',UNKNOWN:'muted'};
export function automationState(status){return `<span class="auto-state ${STATE_TONE[status]||'muted'}">${esc(AUTOMATION_KO[status]||status||'—')}</span>`;}
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
