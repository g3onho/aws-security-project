// 통합 관제: 탐지 요약·소스별 막대·자동 대응 현황(v23). 위험도 분포는 지도 지역 패널에 있다(v20.5).
import {summary} from '../context.js?v=ui-1';
import {header} from '../components/panel.js?v=ui-1';
import {esc,format,milliseconds} from '../components/format.js?v=ui-1';
import {severityColors} from '../constants.js?v=ui-1';
import {automationState,recordTitle,DECISION_KO} from '../components/remediation.js?v=ui-1';
const SEVERITIES=['Critical','High','Medium','Low'];
// 탐지 요약: 위험도별 건수, 자동 조치 대상(설정 기준 예상), 열린 취약점, CloudWatch 경보.
function detectionCard(rows){
 const total=summary.total??rows.length,count=s=>rows.filter(e=>e.severity===s).length;
 const auto=rows.filter(e=>['auto','conditional'].includes(e.autoRemediation?.mode)).length;
 const unknownAuto=rows.length>0&&rows.every(e=>!e.autoRemediation||e.autoRemediation.mode==='unknown');
 const vulns=summary.openVulnerabilities?.total,alarms=summary.alarms;
 const alarmText=!alarms?'정보 없음':alarms.alarm?`<b class="bad-text">${alarms.alarm}건 발생</b> / ${alarms.total}개`:`발생 없음 / ${alarms.total}개${alarms.noData?` · 데이터 없음 ${alarms.noData}`:''}`;
 return `<section class="panel">${header('탐지 요약','DETECTIONS')}<div class="summary-body">
  <div class="summary-total"><b>${esc(total)}</b><span>설정·위협 탐지</span></div>
  <div class="summary-sev">${SEVERITIES.map(s=>`<span style="color:${severityColors[s]}">${s} <b>${count(s)}</b></span>`).join('')}</div>
  <dl class="summary-facts"><div><dt>자동 조치 대상</dt><dd>${unknownAuto?'확인 불가':`${auto}건`}</dd></div>
  <div><dt>열린 취약점(CVE)</dt><dd>${vulns==null?'정보 없음':`${vulns}건`}</dd></div>
  <div><dt>CloudWatch 경보</dt><dd>${alarmText}</dd></div></dl></div></section>`;
}
// 실제로 탐지가 들어온 소스만 막대로 그린다(구조상 늘 0인 소스는 뺀다).
function sourceCard(rows){
 const counts=[...rows.reduce((m,e)=>m.set(e.source,(m.get(e.source)||0)+1),new Map())].sort((a,b)=>b[1]-a[1]);
 const max=Math.max(1,...counts.map(([,n])=>n));
 const body=counts.length?counts.map(([source,n])=>`<div><div class="bar-heading"><span>${esc(source)}</span><span>${n}건</span></div><div class="bar-track"><div class="bar-fill" style="width:${n/max*100}%"></div></div></div>`).join('')
  :'<p class="muted">조회 기간에 탐지가 없습니다.</p>';
 return `<section class="panel">${header('탐지 소스별 이벤트','DETECTION SOURCES')}<div class="chart-body source-bars">${body}</div></section>`;
}
// 자동 대응 현황: 조치 이력(asr_trigger 판정 기록) 기준. '실행 완료'는 재검증 전이다.
export function responseCard(){
 const a=summary.automation;
 const note=a==null?'자동 대응 기록을 불러오지 못했습니다.':a.configured===false?'조치 이력 테이블이 설정되지 않았습니다.':null;
 if(note)return `<section class="panel">${header('자동 대응 현황','SOAR')}<div class="response-body"><p class="muted">${note}</p></div></section>`;
 const recent=(a.recent||[]).slice(0,3);
 return `<section class="panel">${header('자동 대응 현황',`${a.total}건 · 선택 기간`)}<div class="response-body">
  <div class="response-summary"><div>자동 실행<b>${a.autoExecuted}</b><small>완료 ${a.succeeded} · 실패 ${a.failed}${a.inProgress?` · 진행 ${a.inProgress}`:''}</small></div>
  <div>수동 대응 필요<b>${a.manual}</b><small>담당자 알림</small></div><div>판단만<b>${a.dryRun+a.noChange}</b><small>dry-run·변경 없음</small></div></div>
  ${recent.length?`<ul class="response-list">${recent.map(r=>`<li class="response-item"><div><strong>${recordTitle(r)}</strong><small>${format(milliseconds(r.lastSeenAt))} · ${esc(DECISION_KO[r.decision]||r.decision)}</small></div>${automationState(r.status)}</li>`).join('')}</ul>`:'<p class="muted response-empty">선택 기간에 자동 대응 기록이 없습니다.</p>'}
  <button class="text-button response-more" data-view="responses">조치 이력 보기 →</button></div></section>`;
}
export function overviewCharts(rows){
 return `<div class="chart-grid">${detectionCard(rows)}${sourceCard(rows)}${responseCard()}</div>`;
}
