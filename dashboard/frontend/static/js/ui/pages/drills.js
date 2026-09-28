// 공격·대응 실습(1차 관측·구조): 실행 유형·SEC 시나리오 카탈로그·실행 환경·이력 골격.
// 이 화면은 조회 전용이다. 실제 공격·부하 실행 버튼은 두지 않는다(실행 경로는 후속 단계).
import {$,api} from '../context.js?v=ui-1';
import {esc,format,milliseconds} from '../components/format.js?v=ui-1';
import {loadPanel,header,empty} from '../components/panel.js?v=ui-1';

const SUPPORT_COLOR={runnable:'#32d4be','prep-needed':'#d8ca78','observe-only':'#85b1d5','design-needed':'#8fa295'};
const KIND_KO={attack:'웹 공격 검증',scenario:'목적별 검증(단계 포함)',load:'부하 시험 · 운영 경보 검증'};
// 논리 흐름 단계(구조만). 실제 진행은 실행 경로가 붙는 후속 단계에서 증거로 채운다.
const FLOW=['실행 주체','시험 대상','관측 원천','탐지','조치','재검증'];

function supportPill(support,label){
 const c=SUPPORT_COLOR[support]||SUPPORT_COLOR['design-needed'];
 return `<span class="service-pill" style="color:${c}"><i style="background:${c}"></i>${esc(label)} <small>${esc(support)}</small></span>`;
}

function environmentRow(env){
 const conn=env.dataSourceConnected?'연결됨':'미연결';
 const iso=env.isolationVerified==='unknown'?'확인 불가':esc(env.isolationVerified);
 return `<dl class="drill-env">
  <div><dt>실행 모드</dt><dd>${env.executionMode==='live'?'실제 실행':'데모 재생'}</dd></div>
  <div><dt>리전</dt><dd>${esc(env.region||'—')}</dd></div>
  <div><dt>데이터 소스</dt><dd>${conn} <small>${esc(env.providerState||'')}</small></dd></div>
  <div><dt>격리 환경</dt><dd>${iso}</dd></div>
 </dl>`;
}

function typeCard(t){
 return `<div class="drill-type"><h4>${esc(t.name)} <small>${esc(t.tool)}</small></h4>
  <p class="muted">${esc(KIND_KO[t.kind]||t.kind)}</p>
  <p class="drill-sources">관측 원천: ${t.sources.map(esc).join(' · ')}</p>
  ${t.note?`<p class="drill-note">${esc(t.note)}</p>`:''}</div>`;
}

function scenarioRow(s){
 const obs=s.observation==='connected'?'연결됨':'미연결';
 const types=s.types.length?s.types.map(esc).join(', '):'조회 전용';
 return `<tr><td>${esc(s.id)}</td><td>${esc(s.purpose)}</td><td>${esc(types)}</td>
  <td>${s.sources.map(esc).join(' · ')}</td><td>${esc(s.response)}</td>
  <td>${supportPill(s.support,s.supportLabel)}</td><td>${obs}</td></tr>`;
}

function flowStrip(){
 return `<ol class="drill-flow">${FLOW.map((step,i)=>
  `<li><span class="drill-flow-dot" aria-hidden="true">○</span>${esc(step)}${i<FLOW.length-1?'<span class="drill-flow-arrow" aria-hidden="true">→</span>':''}</li>`).join('')}</ol>`;
}

function runsSection(runs){
 if(!runs.items.length){
  return `<section class="panel full-panel">${header('실행 이력','RUN HISTORY')}
   <p class="muted">기록된 실습 실행이 없습니다. 실제 실행·부하·웹 검사 경로는 후속 단계에서 연결됩니다(1차 범위: 관측·구조).</p></section>`;
 }
 const rows=runs.items.map(r=>`<tr><td>${esc(r.runId||'—')}</td><td>${esc(r.type||'—')}</td><td>${esc(r.target||'—')}</td><td>${esc(r.state||'—')}</td><td>${format(milliseconds(r.createdAt))}</td></tr>`).join('');
 return `<section class="panel full-panel">${header('실행 이력','RUN HISTORY')}
  <div class="table-scroll"><table><caption class="sr-only">실습 실행 이력</caption>
  <thead><tr><th>실행 ID</th><th>유형</th><th>대상</th><th>상태</th><th>접수 시각 (KST)</th></tr></thead>
  <tbody>${rows}</tbody></table></div></section>`;
}

function catalogMarkup({catalog,runs}){
 const c=catalog,warn=[];
 if(!c.environment.dataSourceConnected)warn.push('데이터 소스 미연결 — 관측 원천 조회는 준비되면 표시됩니다. 미연결을 0건이나 정상으로 표기하지 않습니다.');
 const notice=warn.map(w=>`<p class="panel-error" role="status">${esc(w)}</p>`).join('');
 return notice+
  `<div class="view-intro"><span>모의 공격과 부하 시험을 실행하고, 탐지부터 대응·재검증까지 확인합니다. 현재 화면은 1차(관측·구조)로 실제 실행 경로는 연결하지 않았습니다.</span></div>`+
  `<section class="panel full-panel">${header('실행 환경','ENVIRONMENT')}${environmentRow(c.environment)}${flowStrip()}
   <p class="muted">단계는 논리 흐름입니다. 실행 접수만으로 대상에 공격이 도달했다고 표시하지 않으며, 실제 증거는 실행 경로가 붙을 때 채워집니다.</p></section>`+
  `<section class="panel full-panel">${header('실행 유형','DRILL TYPES')}<div class="drill-types">${c.types.map(typeCard).join('')}</div>
   <p class="muted">CPU·메모리 사용률 상승 자체는 실제 침해가 아니라 부하 시험으로 표기합니다.</p></section>`+
  `<section class="panel full-panel">${header('보안 시나리오 카탈로그','SEC SCENARIOS')}
   <p class="muted">지원 상태: ${Object.entries(c.supportLegend).map(([k,v])=>`${esc(v)}(${esc(k)})`).join(' · ')}. 이 분류는 설계 기준이며 즉시 실행 가능 여부의 승인이 아닙니다.</p>
   <div class="table-scroll"><table><caption class="sr-only">SEC 시나리오</caption>
   <thead><tr><th>ID</th><th>목적</th><th>실행 유형</th><th>관측 원천</th><th>대응</th><th>지원 상태</th><th>관측</th></tr></thead>
   <tbody>${c.scenarios.map(scenarioRow).join('')}</tbody></table></div></section>`+
  runsSection(runs);
}

export function renderDrills(){
 return loadPanel($('#drills'),
  async()=>{const [catalog,runs]=await Promise.all([api.drillsCatalog(),api.drills()]);return {catalog,runs};},
  catalogMarkup,'공격·대응 실습');
}
