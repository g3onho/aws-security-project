// 보안 이벤트 표: 같은 제목 묶음, 펼치기, 페이지.
import {severityColors} from '../constants.js?v=v46';
import {state,summary,setFilters,selectEvents} from '../context.js?v=v46';
import {esc,format,shortResource} from '../components/format.js?v=v46';
import {badge,statusBadge,sourceTag} from '../components/badges.js?v=v46';
import {header,empty} from '../components/panel.js?v=v46';
import {autoChip} from '../components/remediation.js?v=v46';
import {classify} from '../components/event-response.js?v=v46';
// ── 목록 표 ────────────────────────────────────────────────
const selected=new Set();

// 같은 점검이 자원마다 한 줄씩(예: S3 로깅 미설정 × 버킷 3개) 나오지 않게 제목으로 묶는다.
// 묶음 줄을 누르면 자원별 줄이 펼쳐지고, 자원 줄을 누르면 기존 상세 창이 열린다.
const openEventGroups=new Set();
const SEV_RANK=Object.keys(severityColors);
const SEV_LABEL={Critical:'긴급',High:'높음',Medium:'보통',Low:'낮음',Informational:'정보',Unknown:'미평가'};
const EVENT_SEVERITIES=['Critical','High','Medium','Low'];
const periodLabel=hours=>hours===168?'1주일':hours===24?'1일':hours===1?'1시간':'15분';
const SOURCE_NAMES=['Security Hub','GuardDuty','WAF','Config'];
const SOURCE_SEVERITIES=['Critical','High','Medium','Low'];
const TREND_BUCKETS=12;
function bucketLabel(at,hours){
 const date=new Date(at),clock=new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',hour:'2-digit',hourCycle:'h23'}).format(date);
 if(hours>24)return new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',month:'numeric',day:'numeric'}).format(date);
 if(hours>=1)return clock;
 return new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).format(date);
}
// 통합 관제에는 시간 흐름을, 보안 이벤트에는 소스 비율을 둔다. 두 차트 모두 현재 조회된 자료만 사용한다.
export function eventTrendWidget(rows){
 const hours=Number(state.hours)||24,asMillis=value=>typeof value==='number'?value:Date.parse(value||'');
 const requestedEnd=asMillis(summary.queryTo),collectedAt=asMillis(summary.asOf);
 const end=Number.isFinite(requestedEnd)?requestedEnd:Number.isFinite(collectedAt)?collectedAt:Date.now(),start=end-hours*3600000,step=(end-start)/TREND_BUCKETS;
 const buckets=Array.from({length:TREND_BUCKETS},(_,index)=>({at:start+index*step,counts:Object.fromEntries(SEV_RANK.map(severity=>[severity,0])),total:0}));
 for(const row of rows){
  const at=Number(row.at);if(!Number.isFinite(at)||at<start||at>=end)continue;
  const bucket=buckets[Math.min(TREND_BUCKETS-1,Math.floor((at-start)/step))],severity=SEV_RANK.includes(row.severity)?row.severity:'Unknown';
  bucket.counts[severity]++;bucket.total++;
 }
 const max=Math.max(1,...buckets.map(bucket=>bucket.total)),total=buckets.reduce((sum,bucket)=>sum+bucket.total,0);
 const columns=buckets.map((bucket,index)=>{
  const pieces=SEV_RANK.filter(severity=>bucket.counts[severity]).map(severity=>`<i style="height:${(bucket.counts[severity]/bucket.total*100).toFixed(1)}%;background:${severityColors[severity]}" title="${SEV_LABEL[severity]} ${bucket.counts[severity]}건"></i>`).join('');
  const label=bucketLabel(bucket.at,hours);
  return `<div class="event-trend-column" aria-label="${esc(label)} ${bucket.total}건"><span class="event-trend-stack"><b>${bucket.total}</b><span class="event-trend-bar" style="--h:${(bucket.total/max).toFixed(3)}" aria-hidden="true">${pieces}</span></span><small>${esc(label)}</small></div>`;
 }).join('');
 const totals=Object.fromEntries(SEV_RANK.map(severity=>[severity,rows.filter(row=>(SEV_RANK.includes(row.severity)?row.severity:'Unknown')===severity).length]));
 const legend=SEV_RANK.filter(severity=>totals[severity]).map(severity=>`<span><i style="background:${severityColors[severity]}"></i>${SEV_LABEL[severity]} ${totals[severity]}건</span>`).join('');
 return `<section class="panel full-panel event-trend-widget" aria-label="최근 보안 이벤트 시간대별 탐지 추이">
  ${header('최근 보안 이벤트',`최근 ${periodLabel(hours)} · 시간대별 탐지 추이`)}
  <div class="event-trend-body"><div class="event-trend-chart" role="img" aria-label="선택 기간 보안 이벤트 ${total}건, 위험도별 시간 구간 막대 그래프" style="--bucket-count:${TREND_BUCKETS}">${columns}</div>
   <div class="event-trend-legend" aria-label="위험도별 건수">${legend||'<span>선택 기간 탐지 없음</span>'}</div></div>${state.view==='overview'?'<div class="table-footer trend-footer"><span></span><button class="text-button" data-view="events">보안 이벤트 전체 보기 →</button></div>':''}</section>`;
}
export function eventSourceDonutWidget(rows){
 const countsBySource=new Map(SOURCE_NAMES.map(source=>[source,Object.fromEntries(SEV_RANK.map(severity=>[severity,0]))]));let otherSources=0;
 for(const row of rows){
  const source=row.source||'';
  if(!countsBySource.has(source)){otherSources++;continue;}
  const severity=SEV_RANK.includes(row.severity)?row.severity:'Unknown';countsBySource.get(source)[severity]++;
 }
 const cards=SOURCE_NAMES.map(source=>{
  const counts=countsBySource.get(source),total=SEV_RANK.reduce((sum,severity)=>sum+counts[severity],0);let angle=0;
  const stops=SEV_RANK.filter(severity=>counts[severity]).map(severity=>{const from=angle;angle+=counts[severity]/Math.max(1,total)*360;return `${severityColors[severity]} ${from.toFixed(2)}deg ${angle.toFixed(2)}deg`;});
  const background=total?`conic-gradient(from 0deg,${stops.join(',')})`:'conic-gradient(#e1e6e5 0deg 360deg)';
  const aria=`${source} 위험도별 이벤트 ${total}건: ${SEV_RANK.map(severity=>`${SEV_LABEL[severity]} ${counts[severity]}건`).join(', ')}`;
  const severities=[...SOURCE_SEVERITIES,...SEV_RANK.filter(severity=>!SOURCE_SEVERITIES.includes(severity)&&counts[severity]>0)];
  const legend=severities.map(severity=>`<span data-severity-count="${severity}"><i style="--severity-color:${severityColors[severity]}"></i>${SEV_LABEL[severity]} <b>${counts[severity]}</b></span>`).join('');
  return `<article class="source-severity-card" data-source="${esc(source)}"><div class="source-severity-heading"><strong>${esc(source)}</strong><span>${total}건</span></div>
   <div class="source-severity-ring" role="img" aria-label="${esc(aria)}" style="background:${background}"><div class="source-severity-center"><b class="source-severity-total">${total}</b><small>건</small></div></div>
   <div class="source-severity-legend" aria-label="${esc(source)} 위험도별 건수">${legend||'<span class="source-severity-empty">표시할 이벤트 없음</span>'}</div></article>`;
 }).join('');
 return `<div class="event-source-donut-widget" aria-label="탐지 소스별 이벤트 비율">
  <div class="event-source-inline-heading"><strong>탐지 소스별 이벤트</strong><span>선택한 위험도 기준</span></div>
  <div class="event-source-severity-grid">${cards}</div>
  ${otherSources?`<p class="event-source-extra-note">지정한 네 소스 외 이벤트 ${otherSources}건은 위 그래프에 포함하지 않았습니다.</p>`:''}</div>`;
}
function eventSeverityButtons(){
 const colors={Critical:'#f28f96',High:'#f8b26e',Medium:'#f6dc7a',Low:'#8fd4a6'},counts=summary.bySeverity||{};
 return `<div class="vuln-summary event-severity-filters" role="group" aria-label="위험도 필터">${EVENT_SEVERITIES.map(severity=>{
  const color=colors[severity],active=String(state.severity||'').toUpperCase()===severity.toUpperCase();
  return `<button type="button" class="vuln-summary-button${active?' active':''}" style="--sev-color:${color};--sev-share:${Number(counts[severity.toUpperCase()]||0)/Math.max(1,Object.values(counts).reduce((sum,n)=>sum+(Number(n)||0),0))*100}%" data-event-severity="${severity}" aria-pressed="${active}"><span>${SEV_LABEL[severity]}</span><b>${Number(counts[severity.toUpperCase()]||0)}</b></button>`;
 }).join('')}</div>`;
}
export function eventGroups(rows){
 const groups=new Map();
 for(const e of rows){const key=e.source+'|'+e.title;groups.set(key,[...(groups.get(key)||[]),e]);}
 return [...groups].map(([key,items])=>({key,items,top:[...items].sort((a,b)=>SEV_RANK.indexOf(a.severity)-SEV_RANK.indexOf(b.severity))[0],at:Math.max(...items.map(e=>e.at))}));
}
// 자동 조치 대상(설정 기준 예상)이면 제목 아래에 표시한다 — 목록에서 "SOAR 가 고치는 탐지"를 바로 구분.
function eventRow(e){return `<tr data-key="${esc(e.id)}" data-event="${esc(e.id)}" class="event-row"><td>${badge(e)}</td><td><button class="event-link" data-event="${esc(e.id)}">${esc(e.title)}<small><span class="event-tags"><span class="scenario-tag">${esc(e.scenario)}</span>${autoChip(e.autoRemediation,{short:true})}${isManual(e)?'<span class="auto-chip warn">수동 대응</span>':''}</span><span class="event-resources"><span class="resource-id" title="${esc(e.resource)}">${esc(shortResource(e.resource))}</span></span></small></button></td><td class="source-cell">${sourceTag(e.source)}</td><td>${format(e.at,state.hours<=24)}</td><td>${statusBadge(e.status)}</td></tr>`;}
function groupDetail(g){
 const times=g.items.map(x=>x.at).filter(Number.isFinite),mix=SEV_RANK.filter(v=>g.items.some(x=>x.severity===v)).map(v=>`${SEV_LABEL[v]} ${g.items.filter(x=>x.severity===v).length}`).join(' · ');
 const statuses=[...new Set(g.items.map(x=>x.status))].join(' · ');
 const rows=[...g.items].sort((a,b)=>b.at-a.at).map(x=>`<tr class="event-row" data-event="${esc(x.id)}"><td>${badge(x)}</td><td><button class="event-link" data-event="${esc(x.id)}"><span class="resource-id" title="${esc(x.resource)}">${esc(shortResource(x.resource))}</span><small>${esc(x.resource)}</small></button></td><td class="source-cell">${sourceTag(x.source)}</td><td>${format(x.at,state.hours<=24)}</td><td>${statusBadge(x.status)}</td></tr>`).join('');
 return `<div class="group-detail"><div class="group-detail-head"><strong>같은 제목으로 묶인 이벤트 ${g.items.length}건</strong><span>위험도 ${esc(mix)}</span><span>상태 ${esc(statuses)}</span>${times.length?`<span>${format(Math.min(...times),true)} ~ ${format(Math.max(...times),true)}</span>`:''}</div>
  <table><colgroup><col style="width:12%"><col><col style="width:15%"><col style="width:14%"><col style="width:12%"></colgroup><tbody>${rows}</tbody></table></div>`;
}
function eventGroupRows(g){
 if(g.items.length===1)return eventRow(g.items[0]);
 const e=g.top,open=openEventGroups.has(g.key),statuses=[...new Set(g.items.map(x=>x.status))];
 return `<tr data-key="grp-${esc(g.key)}" class="event-group-row${open?' open':''}"><td>${badge(e)}</td><td><button class="event-link" data-event-group="${esc(g.key)}" aria-expanded="${open}"><span class="group-caret" aria-hidden="true">${open?'▾':'▸'}</span>${esc(e.title)}<small><span class="event-tags"><span class="scenario-tag">${esc(e.scenario)}</span>${autoChip(e.autoRemediation,{short:true})}<span class="group-count">자원 ${g.items.length}개</span></span>${open?'':`<span class="event-resources">${g.items.slice(0,3).map(x=>`<span class="resource-id">${esc(shortResource(x.resource))}</span>`).join('')}${g.items.length>3?`<span class="resource-id more">외 ${g.items.length-3}개</span>`:''}</span>`}</small></button></td><td class="source-cell">${[...new Set(g.items.map(x=>x.source))].map(sourceTag).join(' ')}</td><td>${format(g.at,state.hours<=24)}</td><td>${statuses.length===1?statusBadge(statuses[0]):statusBadge('혼합')}</td></tr>`
  +(open?`<tr data-key="detail-${esc(g.key)}" class="event-group-detail"><td colspan="5">${groupDetail(g)}</td></tr>`:'');
}
// 수동 대응 대상(서버가 dashboardAction 으로 알려 준다). 제목 옆 버튼이 모아 보기·한 번에 조치 팝업(remediate-bulk.js)을 연다.
const isManual=e=>e.dashboardAction?.category==='manual';
export function table(rows,full=false){
 const events=state.view==='events',manualCount=events?classify().actionable.length:0;
 const groups=eventGroups(rows),total=rows.length,pages=Math.max(1,Math.ceil(groups.length/15));if(state.page>pages)setFilters({page:pages});
 const page=groups.slice((state.page-1)*15,state.page*15);
 const title=state.view==='responses'?'조치 이력':state.view==='vulnerabilities'?'취약점 점검 결과':'최근 보안 이벤트';
 const tools='<button id="export" class="text-button">↓ CSV 내보내기</button>';
 const toggle=events?`<button type="button"${manualCount?'':' hidden'} class="manual-toggle" data-bulk-open="manual" aria-haspopup="dialog" title="대시보드에서 조치할 수 있는 미조치 항목을 모아 한 번에 조치합니다">수동 대응 ${manualCount}건</button>`:'';
 const heading=events?`<div class="panel-heading"><div class="heading-left"><h2>${title}</h2>${toggle}</div><span class="meta">${tools}</span></div>`:header(title,tools);
 return `${events?`${eventSeverityButtons()}${eventSourceDonutWidget(rows)}`:''}<section class="panel ${full?'full-panel':''}">${heading}${page.length?`<div class="table-scroll"><table><caption class="sr-only">현재 필터에 해당하는 ${total}개 이벤트</caption><thead><tr><th>위험도</th><th>이벤트 / 자원</th><th class="source-cell">탐지 소스</th><th>발생 시각 (KST)</th><th>상태</th></tr></thead><tbody>${page.map(eventGroupRows).join('')}</tbody></table></div>`:empty()}<div class="table-footer"><span>총 ${total}건 · 같은 제목 묶음 ${groups.length}줄 · 현재 필터 적용</span><span>${state.view==='overview'?'<button class="text-button" data-view="events">전체 이벤트 보기 →</button>':'이벤트를 누르면 문제·위험·고치는 법과 자동 조치 기록을 볼 수 있습니다.'}</span></div><div class="table-pager"><button data-page="prev" ${state.page<=1?'disabled':''}>← 이전</button><span>${state.page} / ${pages}</span><button data-page="next" ${state.page>=pages?'disabled':''}>다음 →</button></div></section>`;
}
export function visibleRows(){return selectEvents();}
export function clearSelection(){selected.clear();}
export function toggleEventGroup(k){openEventGroups.has(k)?openEventGroups.delete(k):openEventGroups.add(k);}
