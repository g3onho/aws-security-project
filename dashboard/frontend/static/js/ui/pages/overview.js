// 통합 관제: 대응 현황 게이지·소스별 막대·조치 상태 카드(v20.5: 위험도 분포는 지도 지역 패널로 옮김).
import {sources} from '../constants.js?v=ui-1';
import {summary} from '../context.js?v=ui-1';
import {header} from '../components/panel.js?v=ui-1';
export function gauge(value,label,color='#32d4be'){
 const val=value===null?'—':value;return `<div class="gauge-item"><div class="metric-ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="ring-track" cx="50" cy="50" r="42"/><circle class="ring-value" cx="50" cy="50" r="42" style="stroke:${color};stroke-dasharray:${(value??0)/100*264} 264"/></svg><div class="ring-label">${val}<span>${value===null?'':'%'}</span></div></div><span>${label}</span></div>`;
}
export function overviewCharts(rows){
 const done=summary.resolved??rows.filter(e=>e.status==='해결').length;const rate=summary.resolutionRate??null;
 const counts=sources.map(source=>({source,count:rows.filter(e=>e.source===source).length}));const max=Math.max(1,...counts.map(s=>s.count));
 return `<div class="chart-grid"><section class="panel">${header('탐지 및 대응 현황','EVENT SUMMARY')}<div class="chart-body"><div class="gauges">${gauge(rate,'재검증 완료율')}</div><p class="gauge-note">재검증 완료 ${done} / ${summary.total??rows.length}건 · CPU·메모리는 인프라 모니터링에서 조회</p></div></section><section class="panel">${header('탐지 소스별 이벤트','DETECTION SOURCES')}<div class="chart-body source-bars">${counts.map(s=>`<div><div class="bar-heading"><span>${s.source}</span><span>${s.count}건</span></div><div class="bar-track"><div class="bar-fill" style="width:${s.count/max*100}%"></div></div></div>`).join('')}</div></section>${responseCard(rows)}</div>`;
}
export function responseCard(rows){const pending=rows.filter(e=>e.actionState==='PENDING_APPROVAL');return `<section class="panel">${header('조치 상태',`${pending.length} PENDING`)}<div class="response-body"><div class="response-summary"><div>관측 이벤트<b>${rows.length}</b></div><div>승인 대기 상태<b>${pending.length}</b></div></div><p class="muted">현재 조치 공급자가 비활성화되어 승인·실행을 접수하지 않습니다.</p></div></section>`;}
