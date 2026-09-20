import {project,globeArtwork,bindMapInteraction,connectionMarkup,polygonPath,wrapLon,clampPhi,findCountryIndex,DEFAULT_ROTATION,DEFAULT_ZOOM,REGION_ZOOM,ZOOM_MIN,ZOOM_MAX} from './map.js?v=2.2.2';
import {regions,sources,statuses,severityColors,threatActors,DEMO_NOW,metricsFor} from './data.js?v=2.2.2';
import {state,selectEvents,api,toCSV} from './store.js?v=2.2.2';
const $=s=>document.querySelector(s);
const $$=s=>[...document.querySelectorAll(s)];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const format=(time,short=false)=>new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(short?{}:{month:'2-digit',day:'2-digit'}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
const titles={overview:['통합 관제','Overview'],events:['보안 이벤트','Security events'],vulnerabilities:['취약점 점검','Vulnerabilities'],infrastructure:['인프라 모니터링','Infrastructure'],responses:['대응 이력','Response history']};
let attackSelection='all';
let charts=[],mapReady=false,zoom=DEFAULT_ZOOM,rotation=[...DEFAULT_ROTATION],panelOpen=true,activeId=null,approval=false,lastTrigger=null,toastTimer;
let worldFeatures=[],cachedAll=[],cachedMapped=[],rafPending=false,selectedCountryIndex=-1;
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
function toast(text){$('#toast').textContent=text;$('#toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').hidden=true,3500);}
function badge(e){return `<span class="badge" style="color:${severityColors[e.severity]}">${e.severity}</span>`;}
function statusBadge(status){return `<span class="status-badge" style="color:${status==='해결'?'#32d4be':status==='재검증 실패'?'#ef777f':status==='승인 대기'?'#d8ca78':'#a9bcb1'}">${status}</span>`;}
function empty(message='선택한 조건에 맞는 이벤트가 없습니다.'){return `<div class="empty"><strong>데이터 없음</strong>${message}</div>`;}
function header(title,meta=''){return `<div class="panel-heading"><h2>${title}</h2><span class="meta">${meta}</span></div>`;}
function canvas(id,label){return `<canvas id="${id}" role="img" aria-label="${esc(label)}">${esc(label)}</canvas>`;}
function drawChart(id,type,data,options={}){
 const el=$(`#${id}`);if(!el)return;
 if(!window.Chart){el.replaceWith(Object.assign(document.createElement('p'),{className:'chart-fallback',textContent:'차트 라이브러리를 불러오지 못했습니다. 텍스트 수치를 확인해주세요.'}));return;}
 charts.push(new Chart(el,{type,data,options:{responsive:true,maintainAspectRatio:false,animation:reduce?false:{duration:500},plugins:{legend:{display:false},tooltip:{backgroundColor:'#17251e',titleColor:'#e7eeec',bodyColor:'#c4d7cb',padding:10}},...options}}));
}
async function loadMap(){
 const response=await fetch('/static/data/countries.geojson?v=2.2.2');if(!response.ok)throw Error('지도 데이터를 불러오지 못했습니다.');
 const data=await response.json();worldFeatures=data.features.filter(f=>f.properties.ADMIN!=='Antarctica');mapReady=true;
 updateSelectedCountry(state.region);
 renderCountries();
}
// v2.2: 선택된 리전이 속한 국가를 강조 표시하기 위해 점-폴리곤 판정으로 국가 인덱스를 계산.
// 한 국가에 리전이 여러 개(미국 4개, 일본 2개)여도 국가 단위로만 강조하므로 별도 분기 없이 동일하게 동작한다.
function updateSelectedCountry(id){
 const r=regions.find(r=>r.id===id);
 selectedCountryIndex=(r&&r.lon!==undefined&&worldFeatures.length)?findCountryIndex(r.lon,r.lat,worldFeatures):-1;
}
function renderCountries(){
 $('#countries').innerHTML=worldFeatures.map((f,i)=>`<path class="${i===selectedCountryIndex?'country-selected':''}" d="${f.geometry.type==='Polygon'?polygonPath(f.geometry.coordinates,rotation,zoom):f.geometry.coordinates.map(c=>polygonPath(c,rotation,zoom)).join('')}"/>`).join('');
}
function renderGlobeArt(){
 const artwork=globeArtwork(rotation,zoom);$('#globe-base').innerHTML=artwork.base;$('#globe-shade').innerHTML=artwork.shade;
}
function scheduleCameraUpdate(){
 if(rafPending)return;rafPending=true;
 requestAnimationFrame(()=>{rafPending=false;updateCamera();});
}
function updateCamera(){
 zoom=Math.max(ZOOM_MIN,Math.min(ZOOM_MAX,zoom));
 rotation=[wrapLon(rotation[0]),clampPhi(rotation[1])];
 renderGlobeArt();
 if(mapReady)renderCountries();
 renderMarkersOnly();
 renderAttacksOnly();
 $('#world-map').dataset.zoom=zoom.toFixed(2);$('#zoom-label').textContent=`${zoom.toFixed(1)}×`;$('#zoom-in').disabled=zoom>=ZOOM_MAX;$('#zoom-out').disabled=zoom<=ZOOM_MIN;
}
function animateTo(targetRotation,targetZoom,duration=650){
 if(reduce){rotation=targetRotation;zoom=targetZoom;updateCamera();return;}
 const startRotation=[...rotation],startZoom=zoom,startTime=performance.now();
 let dLambda=targetRotation[0]-startRotation[0];dLambda=((dLambda+180)%360+360)%360-180;
 const dPhi=targetRotation[1]-startRotation[1];
 (function step(now){
  const t=Math.min(1,(now-startTime)/duration);
  const ease=t<.5?2*t*t:1-Math.pow(-2*t+2,2)/2;
  rotation=[wrapLon(startRotation[0]+dLambda*ease),startRotation[1]+dPhi*ease];
  zoom=startZoom+(targetZoom-startZoom)*ease;
  updateCamera();
  if(t<1)requestAnimationFrame(step);
 })(performance.now());
}
function renderMarkersOnly(){
 $('#markers').innerHTML=regions.filter(r=>r.lon!==undefined).map((r,i)=>{
  const count=cachedAll.filter(e=>e.region===r.id).length;const [x,y,vis]=project(r.lon,r.lat,rotation,zoom);if(vis<=0)return '';
  const radius=count?6+Math.sqrt(count)*3:4;const selected=r.id===state.region;const dy=i===1?27:-15;
  return `<g class="marker ${count?'':'no-events'} ${selected?'selected':''}" data-region="${r.id}" tabindex="0" role="button" aria-label="${r.name} 리전, ${count}건" transform="translate(${x.toFixed(2)},${y.toFixed(2)})"><title>${esc(r.name)} · ${r.id} · ${count}건</title><circle class="halo" r="${radius*1.45}"/><circle class="pulse" r="${radius}" style="animation-delay:-${i*.4}s"/><circle class="selected-ring" r="${selected?8:5}"/><circle class="core" r="${count?3.5:2}"/><rect class="region-marker-label" x="12" y="${dy-11}" width="${r.en.length*6+32}" height="18" rx="2"/><text class="region-marker-label" x="18" y="${dy+1}">${r.en} · ${count}</text></g>`;
 }).join('');
}
function renderAttacksOnly(){
 $('#attack-paths').innerHTML=connectionMarkup(cachedMapped,regions,esc,rotation,zoom);
}
function renderAttacks(rows){
 const attacks=rows.filter(e=>e.sourceIp);if(attackSelection!=='all'&&!attacks.some(e=>e.id===attackSelection))attackSelection='all';
 $('#attack-filter').innerHTML='<option value="all">전체 공격 흐름</option>'+attacks.map(e=>`<option value="${e.id}">${esc(e.sourceIp)} · ${e.id}${e.sourceLocation?'':' · 위치 미상'}</option>`).join('');$('#attack-filter').value=attackSelection;
 const chosen=attackSelection==='all'?attacks:attacks.filter(e=>e.id===attackSelection);
 cachedMapped=chosen.filter(e=>e.sourceLocation&&regions.some(r=>r.id===e.region&&r.lon!==undefined));
 renderAttacksOnly();
 $('#attack-summary').textContent=`${cachedMapped.length}개 흐름 · 위치 미상 ${chosen.length-cachedMapped.length}건 · 모의 IP/좌표`;
}

function chooseRegion(id,move=true){state.region=id;$('#region').value=id;panelOpen=true;updateSelectedCountry(id);if(mapReady)renderCountries();if(move){const r=regions.find(r=>r.id===id);if(r?.lon!==undefined)animateTo([r.lon,clampPhi(r.lat)],REGION_ZOOM);else animateTo(DEFAULT_ROTATION,DEFAULT_ZOOM);}render();}
function mapRender(rows){
 if(!mapReady)return;
 cachedAll=selectEvents({ignoreRegion:true});renderAttacks(rows);
 renderMarkersOnly();
 $('#region-panel').hidden=!panelOpen;$('#open-region').hidden=panelOpen;
 const r=regions.find(r=>r.id===state.region);const unresolved=rows.filter(e=>e.status!=='해결').length;
 $('#region-panel').innerHTML=`<button id="close-region" class="region-close" aria-label="지역 상세 닫기">×</button><div class="region-kicker">SELECTED REGION</div><h3 class="region-title">${r?.en||'ALL REGIONS'}</h3><div class="region-code">${r?.id==='global'?'글로벌 서비스 / 위치 미상':r?`${r.name} · ${r.id}`:'전체 AWS 리전'}</div><div class="region-total"><strong>${String(rows.length).padStart(2,'0')}</strong><span>탐지 이벤트</span></div><div class="region-stats"><span>미해결 <b>${unresolved}</b></span><span>영향 자원 <b>${new Set(rows.map(e=>e.resource)).size}</b></span></div><div class="spark">${canvas('region-spark',`현재 시간 범위의 이벤트 ${rows.length}건 추세`)}</div><div class="region-events">${rows.slice(0,2).map(e=>`<button data-event="${e.id}"><i style="background:${severityColors[e.severity]}"></i>${esc(e.title)}</button>`).join('')||'<span class="muted">데이터 없음</span>'}</div><button class="nongeo-button" data-region="global">글로벌 / 위치 미상 ${cachedAll.filter(e=>e.region==='global').length}건 ↗</button>`;
 const end=DEMO_NOW-state.endOffset*3600000,start=end-state.hours*3600000,values=Array(12).fill(0);rows.forEach(e=>values[Math.min(11,Math.floor((e.at-start)/(end-start)*12))]++);
 drawChart('region-spark','line',{labels:values.map((_,i)=>format(start+(i+.5)*(end-start)/12,true)),datasets:[{label:'탐지 건수',data:values,borderColor:'#32d4be',backgroundColor:'#32d4be10',fill:true,pointRadius:0,tension:.35,borderWidth:1.5}]},{scales:{x:{display:false},y:{display:false,beginAtZero:true}}});
}
function gauge(value,label,color='#32d4be'){
 const val=value===null?'—':value;return `<div class="gauge-item"><div class="metric-ring"><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="ring-track" cx="50" cy="50" r="42"/><circle class="ring-value" cx="50" cy="50" r="42" style="stroke:${color};stroke-dasharray:${(value??0)/100*264} 264"/></svg><div class="ring-label">${val}<span>${value===null?'':'%'}</span></div></div><span>${label}</span></div>`;
}
function overviewCharts(rows){
 const r=regions.find(r=>r.id===state.region);const m=metricsFor(r,state.hours,state.endOffset,state.environment);const done=rows.filter(e=>e.status==='해결').length;const rate=rows.length?Math.round(done/rows.length*100):null;
 const counts=sources.map(source=>({source,count:rows.filter(e=>e.source===source).length}));const max=Math.max(1,...counts.map(s=>s.count));
 return `<div class="chart-grid"><section class="panel">${header('자원 및 대응 현황','RESOURCE HEALTH')}<div class="chart-body"><div class="gauges">${gauge(m?.cpu??null,'CPU 사용률')}${gauge(m?.memory??null,'메모리 사용률')}${gauge(rate,'대응 완료율')}</div><p class="gauge-note">${m?esc(m.resource):'EC2 데이터 없음'} · 해결 ${done} / ${rows.length}건</p></div></section><section class="panel">${header('탐지 소스별 이벤트','DETECTION SOURCES')}<div class="chart-body source-bars">${counts.map(s=>`<div><div class="bar-heading"><span>${s.source}</span><span>${s.count}건</span></div><div class="bar-track"><div class="bar-fill" style="width:${s.count/max*100}%"></div></div></div>`).join('')}</div></section><section class="panel">${header('위험도 분포',`${rows.length} EVENTS`)}<div class="chart-body donut-body"><div class="donut-wrap">${canvas('severity-chart','위험도별 건수는 오른쪽 범례에 표시됩니다.')}<div class="donut-center"><b>${rows.length}</b><span>전체 이벤트</span></div></div><div class="donut-legend">${Object.entries(severityColors).map(([s,c])=>`<div><i style="background:${c}"></i><span>${s}</span><b>${rows.filter(e=>e.severity===s).length}</b></div>`).join('')}</div></div></section></div>`;
}
function table(rows,full=false){return `<section class="panel ${full?'full-panel':''}">${header(state.view==='responses'?'대응 이력':state.view==='vulnerabilities'?'취약점 점검 결과':'최근 보안 이벤트',`<button id="export" class="text-button">↓ CSV 내보내기</button>`)}${rows.length?`<div class="table-scroll"><table><caption class="sr-only">현재 필터에 해당하는 ${rows.length}개 이벤트</caption><thead><tr><th>위험도</th><th>이벤트 / 자원</th><th>탐지 소스</th><th>발생 시각 (KST)</th><th>상태</th>${full?'<th>대응</th><th>재검증</th>':''}</tr></thead><tbody>${rows.map(e=>`<tr><td>${badge(e)}</td><td><button class="event-link" data-event="${e.id}">${esc(e.title)}<small>${e.scenario} · ${esc(e.resource)}</small></button></td><td>${e.source}</td><td>${format(e.at,true)}</td><td>${statusBadge(e.status)}</td>${full?`<td>${e.mode} · ${e.execution}</td><td>${e.verification}</td>`:''}</tr>`).join('')}</tbody></table></div>`:empty()}<div class="table-footer"><span>총 ${rows.length}건 · 현재 필터 적용</span><span>${state.view==='overview'?'<button class="text-button" data-view="events">전체 이벤트 보기 →</button>':'이벤트를 선택해 근거와 조치 결과 확인'}</span></div></section>`;}
function responseCard(rows){const pending=rows.filter(e=>e.status==='승인 대기');return `<section class="panel">${header('대응 관리',`${pending.length} APPROVALS`)}<div class="response-body"><div class="response-summary"><div>자동 대응<b>${rows.filter(e=>e.mode==='자동').length}</b></div><div>수동 대응<b>${rows.filter(e=>e.mode==='수동').length}</b></div><div>승인 대기<b style="color:#d8ca78">${pending.length}</b></div></div><div class="response-list">${pending.slice(0,4).map(e=>`<div class="response-item"><span class="response-icon">!</span><div><strong>${esc(e.title)}</strong><small>${e.scenario} · ${format(e.at,true)} KST</small></div><button data-event="${e.id}">검토</button></div>`).join('')||'<p class="muted">승인 대기 이벤트가 없습니다.</p>'}</div></div></section>`;}
function infrastructure(){const r=regions.find(r=>r.id===state.region);const m=metricsFor(r,state.hours,state.endOffset,state.environment);return `<div class="view-intro"><span>CloudWatch · CPU / 메모리 · 5분 평균 · 데모 시계열</span><span>경보 임계치 <strong class="mint">80%</strong></span></div><div class="infrastructure-grid"><section class="panel">${header('EC2 자원 사용률',m?.resource||'EC2 미선택')}${m?`<div class="metric-large">${canvas('metrics-chart',`CPU ${m.cpu}%, 메모리 ${m.memory}%, 임계치 80%`)}</div><div class="context-note">CPU ${m.cpu}% · 메모리 ${m.memory}% · 임계치 80% — 선택 구간 종료 시점의 값입니다. 보안 이벤트 필터와 독립적인 자원 지표입니다.</div>`:empty('단일 AWS 리전을 선택하면 EC2 데모 지표를 볼 수 있습니다.')}</section><section class="panel">${header('3계층 서비스','DEMO HEALTH')}<div class="service-flow"><div class="service-node">Nginx<span>● 정상</span></div><span class="mint">→</span><div class="service-node">Flask<span>● 정상</span></div><span class="mint">→</span><div class="service-node">MySQL<span>● 정상</span></div></div><div class="context-note">데모 서비스 구성도 · 실제 상태 미연동<br>HTTP /health: 데모 200<br>실제 AWS 조회 및 조치: 미연동</div></section></div>`;}
function visibleRows(){const rows=selectEvents();return state.view==='vulnerabilities'?rows.filter(e=>['Trivy','Inspector'].includes(e.source)):state.view==='responses'?rows.filter(e=>e.history.length>1||e.status==='승인 대기'):rows;}
function render(){
 charts.forEach(c=>c.destroy());charts=[];
 const rows=selectEvents();const [title,en]=titles[state.view];$('#page-title').innerHTML=`${title} <span>${en}</span>`;document.title=`AWS Security Operations · ${title}`;
 $$('nav [data-view]').forEach(b=>{b.classList.toggle('active',b.dataset.view===state.view);b.setAttribute('aria-current',b.dataset.view===state.view?'page':'false');});
 $('#map-section').hidden=state.view!=='overview';
 const end=DEMO_NOW-state.endOffset*3600000;$('#time-label').innerHTML=`${format(end-state.hours*3600000)} — ${format(end)}<br>KST · 고정 데모 시각`;
 $$('[data-hours]').forEach(b=>{b.classList.toggle('active',+b.dataset.hours===state.hours);b.setAttribute('aria-pressed',String(+b.dataset.hours===state.hours));});
 $('#time-range').setAttribute('aria-valuetext',`${state.endOffset}시간 전까지, 최근 ${state.hours}시간`);
 if(state.view==='overview'){$('#content').innerHTML=overviewCharts(rows)+`<div class="table-layout">${table(rows)}${responseCard(rows)}</div>`;mapRender(rows);drawChart('severity-chart','doughnut',{labels:Object.keys(severityColors),datasets:[{data:Object.keys(severityColors).map(s=>rows.filter(e=>e.severity===s).length),backgroundColor:Object.values(severityColors),borderWidth:0,hoverOffset:3}]},{cutout:'75%'});}
 else if(state.view==='infrastructure'){
  $('#content').innerHTML=infrastructure();const m=metricsFor(regions.find(r=>r.id===state.region),state.hours,state.endOffset,state.environment);if(m)drawChart('metrics-chart','line',{labels:m.points.map(p=>format(p.at,true)),datasets:[{label:'CPU %',data:m.points.map(p=>p.cpu),borderColor:'#32d4be',pointRadius:2,tension:.3,borderWidth:2},{label:'메모리 %',data:m.points.map(p=>p.memory),borderColor:'#a3c7b7',pointRadius:2,tension:.3,borderWidth:2},{label:'80% 임계치',data:m.points.map(()=>80),borderColor:'#e7a064',borderDash:[5,5],pointRadius:0,borderWidth:1}]},{plugins:{legend:{display:true,labels:{color:'#b8cdbf',boxWidth:14,font:{size:11}}}},scales:{x:{ticks:{color:'#9eb5a5',maxTicksLimit:6,font:{size:10}},grid:{color:'#334737'}},y:{min:0,max:100,ticks:{color:'#9eb5a5',callback:v=>`${v}%`},grid:{color:'#334737'}}}});
 }else {const visible=visibleRows();$('#content').innerHTML=`<div class="view-intro"><span>${state.view==='vulnerabilities'?'Trivy / Inspector · 같은 자원과 검사 기준으로 결과 비교':state.view==='responses'?'실행 결과와 재검증 결과를 구분하여 확인합니다.':'탐지 근거에서 대응과 재검증까지 추적합니다.'}</span><span class="view-summary">전체 <strong>${visible.length}건</strong> 미해결 <strong>${visible.filter(e=>e.status!=='해결').length}건</strong></span></div>${table(visible,true)}`;}
 $('#notification-count').hidden=!rows.some(e=>e.status==='승인 대기');
}
function eventDialog(id,ask=false){
 const e=api.get(id);if(!e)return;activeId=id;approval=ask;
 const running=['조치 실행 중','재검증 중'].includes(e.status);
 const actor=e.sourceLocation?.actorId?threatActors.find(a=>a.id===e.sourceLocation.actorId):null;
 $('#dialog-content').innerHTML=`<div class="dialog-header"><div><div class="eyebrow">${e.id} / ${e.scenario}</div><h2 id="dialog-title">${esc(e.title)}</h2></div><button class="dialog-close" data-action="close" aria-label="상세 닫기">×</button></div><div class="dialog-body"><dl class="detail-meta"><div><dt>위험도</dt><dd>${badge(e)}</dd></div><div><dt>탐지 소스</dt><dd>${e.source}</dd></div><div><dt>발생 시각 (KST)</dt><dd>${format(e.at)}</dd></div><div><dt>대상 자원</dt><dd>${esc(e.resource)}</dd></div><div><dt>리전</dt><dd>${e.region}</dd></div><div><dt>처리 상태</dt><dd>${statusBadge(e.status)}</dd></div></dl><div class="execution-flow" role="status" aria-live="polite"><span>${e.mode} 대응</span><span>→ 실행 <b>${e.execution}</b></span><span>→ 재검증 <b>${e.verification}</b></span></div>${e.sourceIp?`<section class="detail-section attack-detail"><h3>공격 출발지 → 대상</h3><p><strong>${esc(e.sourceIp)}</strong> → ${esc(e.region)} / ${esc(e.resource)}</p><p>${e.sourceLocation?`${esc(e.sourceLocation.city)} · ${esc(e.sourceLocation.provenance)} · 좌표 ${e.sourceLocation.lat}, ${e.sourceLocation.lon}`:esc(e.geoStatus)+' · 지도 연결선 미표시'}</p><p>선은 출발지와 대상의 관계를 나타냅니다. 실제 인터넷 경로나 공격자의 물리적 위치를 의미하지 않습니다.</p>${actor?`<div class="threat-actor-box"><div class="threat-actor-head">${esc(actor.country)} 배후 추정 그룹(예시): ${esc(actor.groups.join(', '))}</div><dl class="threat-actor-meta"><div><dt>주요 목적</dt><dd>${esc(actor.purpose)}</dd></div><div><dt>주요 타겟</dt><dd>${esc(actor.targets.join(', '))}</dd></div><div><dt>주요 전술</dt><dd>${esc(actor.tactics.join(', '))}</dd></div></dl><p class="threat-actor-disclaimer">공개 위협 인텔리전스 자료(CISA, MITRE ATT&CK 등)를 참고해 구성한 교육용 데모 정보이며, 이 개별 이벤트에 대한 실제 귀속(attribution)이 아닙니다.</p></div>`:''}</section>`:''}<section class="detail-section"><h3>탐지 근거</h3><p>${esc(e.evidence)}</p></section><section class="detail-section"><h3>권장 조치</h3><p>${esc(e.recommendation)}</p></section>${ask?`<div class="approval-box"><strong>데모 조치 승인</strong>대상: ${esc(e.resource)}<br>변경: ${esc(e.recommendation)}<br>실제 AWS 자원은 변경되지 않습니다. 승인 후 실행 결과를 확인하고 재검증을 진행하세요.</div>`:''}<section class="detail-section"><h3>Before / After · 동일 기준 재검증</h3><p>${esc(e.criterion)}</p><p>비교 자원: ${esc(e.resource)}</p><div class="comparison"><div><label>BEFORE · 조치 전</label><strong>${e.before}${e.unit}</strong><small>${format(e.beforeAt)} KST</small></div><div><label>AFTER · 재검증 ${e.verification}</label><strong>${e.afterValue===null?'검사 대기':`${e.afterValue}${e.unit}`}</strong><small>${e.afterAt?format(e.afterAt)+' KST':'조치 성공만으로 해결되지 않습니다.'}</small></div></div></section><section class="detail-section"><h3>처리 이력</h3><ol class="history-list">${e.history.map(h=>`<li><time>${format(h.at)} KST</time>${esc(h.text)}</li>`).join('')}</ol></section></div><div class="dialog-actions"><span>DEMO · 실제 AWS 조치 없음</span>${ask?'<button class="cancel-button" data-action="cancel-approval">취소</button><button class="primary-button" data-action="execute">승인 및 데모 실행</button>':running?'<button class="primary-button" disabled>처리 중…</button>':e.status==='재검증 대기'?'<button class="primary-button" data-action="verify">동일 기준 재검증</button>':e.status==='해결'?'<button class="cancel-button" data-action="close">닫기</button>':`<button class="cancel-button" data-action="close">닫기</button><button class="primary-button" data-action="${e.mode==='수동'?'approve':'execute'}">${e.mode==='수동'?'조치 검토 및 승인':'자동 대응 데모 실행'}</button>`}</div>`;
 if(!$('#event-dialog').open){lastTrigger=document.activeElement;$('#event-dialog').showModal();}else if(!running){$('#dialog-content .primary-button, #dialog-content .cancel-button')?.focus();}
}
function closeDialog(){ $('#event-dialog').close(); }
async function dialogAction(action){
 if(action==='close'){closeDialog();return;}if(action==='approve'){eventDialog(activeId,true);return;}if(action==='cancel-approval'){eventDialog(activeId);toast('승인을 취소했습니다. 상태는 변경되지 않았습니다.');return;}
 if(['execute','verify'].includes(action)){
  const id=activeId;try{const operation=action==='execute'?api.execute(id):api.verify(id);eventDialog(id);render();await operation;render();if($('#event-dialog').open&&activeId===id)eventDialog(id);toast(action==='execute'?'데모 조치 실행 성공. 재검증이 필요합니다.':`재검증 ${api.get(id).verification} · ${api.get(id).status}`);}catch(error){toast(error.message);}
 }
}
async function refresh(){
 const box=$('#load-state');box.hidden=false;box.className='load-state';box.textContent='데모 데이터를 불러오는 중…';$('#refresh').disabled=true;$('#content').setAttribute('aria-busy','true');
 try{await Promise.all([api.load(),mapReady?Promise.resolve():loadMap()]);render();box.hidden=true;$('#updated').textContent=`갱신 ${format(Date.now(),true)} KST`;}catch(e){box.classList.add('error');box.innerHTML=`${esc(e.message)} <button id="retry">다시 시도</button>`;}finally{$('#refresh').disabled=false;$('#content').removeAttribute('aria-busy');}
}
$('#region').innerHTML='<option value="all">전체 리전</option>'+regions.map(r=>`<option value="${r.id}">${r.name}${r.id==='global'?'':` · ${r.id}`}</option>`).join('');$('#region').value=state.region;
$('#status').insertAdjacentHTML('beforeend',statuses.map(s=>`<option>${s}</option>`).join(''));$('#source').insertAdjacentHTML('beforeend',sources.map(s=>`<option>${s}</option>`).join(''));
['environment','severity','status','source'].forEach(key=>$(`#${key}`).addEventListener('change',e=>{state[key]=e.target.value;render();}));
$('#region').addEventListener('change',e=>chooseRegion(e.target.value));
$('#search').addEventListener('input',e=>{state.search=e.target.value;render();});
$('#time-range').addEventListener('input',e=>{state.endOffset=+e.target.value;render();});
$('#event-dialog').addEventListener('close',()=>{activeId=null;approval=false;const target=lastTrigger?.isConnected?lastTrigger:$('#page-title');if(!target.hasAttribute('tabindex')&&target.tagName==='H1')target.tabIndex=-1;target.focus();});
$('#event-dialog').addEventListener('click',e=>{if(e.target===$('#event-dialog')){const r=e.target.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)closeDialog();}});
document.addEventListener('keydown',e=>{const attack=e.target.closest('.attack-connection');if(attack&&['Enter',' '].includes(e.key)){e.preventDefault();eventDialog(attack.dataset.event);return;}const marker=e.target.closest('.marker');if(marker&&['Enter',' '].includes(e.key)){e.preventDefault();const id=marker.dataset.region;chooseRegion(id);$(`#markers [data-region="${id}"]`)?.focus();}});
document.addEventListener('click',e=>{
 const view=e.target.closest('[data-view]');if(view){state.view=view.dataset.view;render();return;}
 const region=e.target.closest('[data-region]');if(region){chooseRegion(region.dataset.region);return;}
 const event=e.target.closest('[data-event]');if(event){eventDialog(event.dataset.event);return;}
 const action=e.target.closest('[data-action]');if(action){dialogAction(action.dataset.action);return;}
 const hours=e.target.closest('[data-hours]');if(hours){state.hours=+hours.dataset.hours;render();return;}
 const id=e.target.closest('button')?.id;
 if(id==='refresh'||id==='retry')refresh();
 if(id==='close-region'){panelOpen=false;$('#region-panel').hidden=true;$('#open-region').hidden=false;$('#open-region').focus();}
 if(id==='open-region'){panelOpen=true;render();$('#close-region')?.focus();}
 if(id==='zoom-in'){animateTo(rotation,Math.min(ZOOM_MAX,zoom+.3),300);}
 if(id==='zoom-out'){animateTo(rotation,Math.max(ZOOM_MIN,zoom-.3),300);}
 if(id==='zoom-reset'){animateTo(DEFAULT_ROTATION,DEFAULT_ZOOM,500);}
 if(id==='clear-filters'){Object.assign(state,{severity:'',status:'',source:'',search:'',endOffset:0,hours:24});['severity','status','source','search'].forEach(k=>$(`#${k}`).value='');$('#time-range').value=0;render();toast('검색·위험도·상태·소스·시간 필터를 초기화했습니다.');}
 if(id==='notifications'){state.view='events';state.status='승인 대기';$('#status').value=state.status;render();toast('현재 지역과 시간 범위의 승인 대기 알림을 표시합니다.');}
 if(id==='export'){const rows=visibleRows();const blob=new Blob([toCSV(rows)],{type:'text/csv;charset=utf-8'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=`aws-events-${state.region}-${state.view}.csv`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);toast(`${rows.length}개 이벤트를 CSV로 내보냈습니다.`);}
});
bindMapInteraction($('#world-map'),()=>({zoom,rotation}),value=>{zoom=value.zoom;rotation=value.rotation;scheduleCameraUpdate();});
$('#attack-filter').addEventListener('change',e=>{attackSelection=e.target.value;renderAttacks(selectEvents());});
updateCamera();
refresh();




