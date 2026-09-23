import {globeArtwork,bindMapInteraction,connectionMarkup,polygonPath,wrapLon,clampPhi,findCountryIndex,DEFAULT_ROTATION,DEFAULT_ZOOM,REGION_ZOOM,ZOOM_MIN,ZOOM_MAX} from './map.js?v=local-4';
import {regions,sources,statuses,severityColors} from './data.js?v=local-1';
import {state,selectEvents,api as storeApi,config,summary,DATA_AS_OF,metricsFor,servicesOf,request as storeRequest} from './store.js?v=local-1';
import {patchMarkup} from './rendering.js?v=local-2';
import {createMarkerLayer,createCameraController} from './map-ui.js?v=local-4';
import {createNotificationPopover} from './notifications.js?v=local-4';
import {vulnerabilityCsv,downloadCsv} from './downloads.js?v=local-4';
import {createJobWatcher} from './jobs.js?v=local-4';
import {animateLayout} from './layout-motion.js?v=local-5';
import {createRequestActivity} from './request-activity.js?v=local-5';
const $=s=>document.querySelector(s);
const $$=s=>[...document.querySelectorAll(s)];
const activity=createRequestActivity($('#network-activity'));
// Track UI requests without changing either backend adapter or synchronous cache reads.
const api=Object.fromEntries(Object.entries(storeApi).map(([name,method])=>[
 name,name==='get'?method.bind(storeApi):(...args)=>activity.run(()=>method.apply(storeApi,args)),
]));
const request=(...args)=>activity.run(()=>storeRequest(...args));
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const format=(time,short=false)=>time==null?'데이터 없음':new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(short?{}:{month:'2-digit',day:'2-digit'}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
// 구간이 하루를 넘으면 시:분만 찍힌 x축은 읽을 수 없다. 창 길이를 보고 날짜를 붙인다.
const formatAt=(time,span=0)=>time==null?'데이터 없음':new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(span>24*3600000?{month:'2-digit',day:'2-digit'}:{}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
const titles={overview:['통합 관제','Overview'],events:['보안 이벤트','Security events'],vulnerabilities:['취약점 점검','Vulnerabilities'],incidents:['침해사례','Incident cases'],infrastructure:['인프라 모니터링','Infrastructure'],responses:['대응 이력','Response history']};
let attackSelection='all';
const charts=new Map();
let mapReady=false,zoom=DEFAULT_ZOOM,rotation=[...DEFAULT_ROTATION],panelOpen=true,activeId=null,approval=false,lastTrigger=null,toastTimer;
let refreshSerial=0,renderedView='';
let worldFeatures=[],cachedAll=[],cachedMapped=[],rafPending=false,selectedCountryIndex=-1;
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
const notifications=createNotificationPopover({button:$('#notifications'),panel:$('#notification-panel')});
function toast(text){$('#toast').textContent=text;$('#toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').hidden=true,3500);}
// severityBumped: correlator 가 "위협+CVE 동시 존재"로 한 단계 올린 건. 올렸다는 사실이
// 화면에 없으면 자동 모니터링 2번이 동작한 증거가 남지 않는다.
function badge(e){return `<span class="badge" style="color:${severityColors[e.severity]}">${e.severity}</span>`+(e.severityBumped?` <span class="badge bumped" title="GuardDuty 위협과 Inspector CVE가 같은 자원에 있어 심각도를 한 단계 올렸습니다">↑상향</span>`:'');}
function statusBadge(status){return `<span class="status-badge" style="color:${status==='해결'?'#32d4be':status==='재검증 실패'?'#ef777f':status==='승인 대기'?'#d8ca78':'#a9bcb1'}">${esc(status)}</span>`;}
function empty(message='선택한 조건에 맞는 이벤트가 없습니다.'){return `<div class="empty"><strong>데이터 없음</strong>${message}</div>`;}
function header(title,meta=''){return `<div class="panel-heading"><h2>${title}</h2><span class="meta">${meta}</span></div>`;}
function canvas(id,label){return `<canvas id="${id}" role="img" aria-label="${esc(label)}">${esc(label)}</canvas>`;}
function drawChart(id,type,data,options={}){
 const el=$(`#${id}`);if(!el)return;
 if(!window.Chart){el.replaceWith(Object.assign(document.createElement('p'),{className:'chart-fallback',textContent:'차트 라이브러리를 불러오지 못했습니다. 텍스트 수치를 확인해주세요.'}));return;}
 const chartOptions={responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false},tooltip:{backgroundColor:'#17251e',titleColor:'#e7eeec',bodyColor:'#c4d7cb',padding:10}},...options};
 const existing=charts.get(id);
 if(existing?.canvas===el){existing.data=data;existing.options=chartOptions;existing.update('none');return;}
 existing?.destroy();
 charts.set(id,new Chart(el,{type,data,options:chartOptions}));
}
function cleanCharts(){
 for(const [id,chart] of charts){if(!chart.canvas.isConnected){chart.destroy();charts.delete(id);}}
}
function renderContent(html){
 const content=$('#content');
 if(renderedView!==state.view){content.replaceChildren();renderedView=state.view;patchMarkup(content,html);}
 else patchAnimated(content,html);
}
function patchAnimated(container,html){return animateLayout(container,()=>patchMarkup(container,html));}
function resetTableScroll(control){
 const table=control.closest('.panel')?.querySelector('.table-scroll');
 if(table)table.scrollTop=0;
}
const panelRequests=new WeakMap();
const panelScope=()=>JSON.stringify([state.view,state.region,state.resource,state.environment,state.hours,state.endOffset,state.severity,state.status,state.source,state.search]);
async function loadPanel(box,fetchData,markup,label){
 if(!box)return;
 const token={},serial=refreshSerial,scope=panelScope();
 panelRequests.set(box,token);box.setAttribute('aria-busy','true');
 const current=()=>box.isConnected&&panelRequests.get(box)===token&&serial===refreshSerial&&scope===panelScope();
 try{
  const data=await fetchData();if(!current())return;
  const html=markup(data);
  animateLayout(box,()=>{box.querySelector(':scope > .panel-error')?.remove();patchMarkup(box,html);});box.dataset.loaded='true';
 }catch(error){
  if(!current()||error.name==='AbortError')return;
  const message=`${label} 갱신 실패: ${error.message}`;
  if(box.dataset.loaded){
   animateLayout(box,()=>{
    let note=box.querySelector(':scope > .panel-error');
    if(!note){note=document.createElement('p');note.className='panel-error';note.setAttribute('role','status');box.prepend(note);}
    note.textContent=message+' · 이전 데이터를 표시하고 있습니다.';
   });
  }else patchAnimated(box,`<p class="panel-error" role="status">${esc(message)}</p>`);
 }finally{if(panelRequests.get(box)===token)box.removeAttribute('aria-busy');}
}
async function loadMap(){
 const response=await fetch('/static/data/countries.geojson?v=local-1');if(!response.ok)throw Error('지도 데이터를 불러오지 못했습니다.');
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
const markerLayer=createMarkerLayer($('#markers'));
const camera=createCameraController(()=>({rotation,zoom}),value=>{rotation=value.rotation;zoom=value.zoom;updateCamera();},{reducedMotion:reduce});
const animateTo=(...args)=>camera.animateTo(...args);
function renderMarkersOnly(){
 markerLayer.update({regions,events:cachedAll,selectedRegion:state.region,rotation,zoom});
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
 $('#attack-summary').textContent=`${cachedMapped.length}개 흐름 · 위치 미상 ${chosen.length-cachedMapped.length}건`;
}

function chooseRegion(id,move=true){
 const changed=state.region!==id||state.resource!=='';
 state.region=id;state.resource='';$('#region').value=id;panelOpen=true;
 updateSelectedCountry(id);if(mapReady)renderCountries();
 if(move){const r=regions.find(r=>r.id===id);animateTo(r?.lon!==undefined?[r.lon,clampPhi(r.lat)]:DEFAULT_ROTATION,r?.lon!==undefined?REGION_ZOOM:DEFAULT_ZOOM);}
 if(!changed){if(state.view==='overview')mapRender(selectEvents());return;}
 vulnTarget='';vulnPage=1;selected.clear();state.page=1;refresh();
}
function mapRender(rows){
 if(!mapReady)return;
 cachedAll=selectEvents({ignoreRegion:true});renderAttacks(rows);
 renderMarkersOnly();
 $('#region-panel').hidden=!panelOpen;$('#open-region').hidden=panelOpen;
 const r=regions.find(r=>r.id===state.region);const unresolved=rows.filter(e=>e.status!=='해결').length;
 patchAnimated($('#region-panel'),`<button id="close-region" class="region-close" aria-label="지역 상세 닫기">×</button><div class="region-kicker">SELECTED REGION</div><h3 class="region-title">${r?.en||'ALL REGIONS'}</h3><div class="region-code">${r?.id==='global'?'글로벌 서비스 / 위치 미상':r?`${r.name} · ${r.id}`:'전체 AWS 리전'}</div><div class="region-total"><strong>${String(rows.length).padStart(2,'0')}</strong><span>탐지 이벤트</span></div><div class="region-stats"><span>미해결 <b>${unresolved}</b></span><span>영향 자원 <b>${new Set(rows.map(e=>e.resource)).size}</b></span></div><div class="spark">${canvas('region-spark',`현재 시간 범위의 이벤트 ${rows.length}건 추세`)}</div><div class="region-events">${rows.slice(0,2).map(e=>`<button data-event="${e.id}"><i style="background:${severityColors[e.severity]}"></i>${esc(e.title)}</button>`).join('')||'<span class="muted">데이터 없음</span>'}</div><button class="nongeo-button" data-region="global">글로벌 / 위치 미상 ${cachedAll.filter(e=>e.region==='global').length}건 ↗</button>`);
 const end=DATA_AS_OF-state.endOffset*3600000,start=end-state.hours*3600000,values=Array(12).fill(0);rows.forEach(e=>values[Math.min(11,Math.floor((e.at-start)/(end-start)*12))]++);
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
// ── 목록 표 ────────────────────────────────────────────────
// v3 (보완설계 §3.2): 표 안에서 바로 조치할 수 있게 조치 열과 선택 열을 붙였다.
// 이전에는 상세 창을 열어야만 승인/실행/재검증이 가능해, 취약점 점검 화면에서
// 항목을 눈으로 확인하고도 아무것도 할 수 없었다.
const selected=new Set();
function canAct(){return config.writeEnabled&&config.role==='operator';}
function rowAction(e){
 if(!canAct())return '<span class="muted-mini">조회 전용</span>';
 if(!e.actionable)return '<span class="muted-mini" title="자동 대응 경로이거나 등록된 수동 조치가 없습니다">자동 대응</span>';
 const s=e.rawStatus;
 if(['EXECUTING','VERIFYING'].includes(s))return '<button class="row-action" disabled>진행 중</button>';
 if(s==='RESOLVED')return '<button class="row-action" disabled>완료</button>';
 if(s==='APPROVED')return `<button class="row-action primary" data-row-action="execute" data-event="${e.id}">조치 실행</button>`;
 if(['PENDING_VERIFICATION','VERIFICATION_FAILED'].includes(s))return `<button class="row-action primary" data-row-action="verify" data-event="${e.id}">재검증</button>`;
 if(['NEW','PENDING_APPROVAL','EXECUTION_FAILED'].includes(s))return `<button class="row-action" data-row-action="approve" data-event="${e.id}">승인</button>`;
 return '<span class="muted-mini">—</span>';
}
function approvable(e){return canAct()&&e.actionable&&['NEW','PENDING_APPROVAL','EXECUTION_FAILED'].includes(e.rawStatus);}
function table(rows,full=false){
 const total=rows.length,pages=Math.max(1,Math.ceil(total/15));state.page=Math.min(state.page,pages);
 const page=rows.slice((state.page-1)*15,state.page*15);
 const pick=full&&canAct();
 const bulk=page.filter(approvable);
 const title=state.view==='responses'?'대응 이력':state.view==='vulnerabilities'?'취약점 점검 결과':'최근 보안 이벤트';
 const tools=`${pick&&bulk.length?`<button id="bulk-approve" class="text-button">☑ 선택 일괄 승인 (<span id="bulk-count">${bulk.filter(e=>selected.has(e.id)).length}</span>)</button>`:''}<button id="export" class="text-button">↓ CSV 내보내기</button>`;
 return `<section class="panel ${full?'full-panel':''}">${header(title,tools)}${page.length?`<div class="table-scroll"><table><caption class="sr-only">현재 필터에 해당하는 ${total}개 이벤트</caption><thead><tr>${pick?`<th class="pick-col"><input type="checkbox" id="pick-all" aria-label="현재 페이지 전체 선택"></th>`:''}<th>위험도</th><th>이벤트 / 자원</th><th>탐지 소스</th><th>발생 시각 (KST)</th><th>상태</th>${full?'<th>대응</th><th>재검증</th><th>조치</th>':''}</tr></thead><tbody>${page.map(e=>`<tr data-key="${esc(e.id)}">${pick?`<td class="pick-col">${approvable(e)?`<input type="checkbox" class="row-pick" data-pick="${e.id}" aria-label="${esc(e.title)} 선택"${selected.has(e.id)?' checked':''}>`:''}</td>`:''}<td>${badge(e)}</td><td><button class="event-link" data-event="${e.id}">${esc(e.title)}<small>${esc(e.scenario)} · ${esc(e.resource)}</small></button></td><td>${esc(e.source)}</td><td>${format(e.at,true)}</td><td>${statusBadge(e.status)}</td>${full?`<td>${esc(e.mode)} · ${esc(e.execution)}</td><td>${esc(e.verification)}</td><td>${rowAction(e)}</td>`:''}</tr>`).join('')}</tbody></table></div>`:empty()}<div class="table-footer"><span>총 ${total}건 · 현재 필터 적용</span><span>${state.view==='overview'?'<button class="text-button" data-view="events">전체 이벤트 보기 →</button>':'표에서 바로 승인·실행·재검증하거나, 이벤트를 눌러 근거를 확인하세요.'}</span></div><div class="table-pager"><button data-page="prev" ${state.page<=1?'disabled':''}>← 이전</button><span>${state.page} / ${pages}</span><button data-page="next" ${state.page>=pages?'disabled':''}>다음 →</button></div></section>`;
}
function responseCard(rows){const pending=rows.filter(e=>e.status==='승인 대기');return `<section class="panel">${header('대응 관리',`${pending.length} APPROVALS`)}<div class="response-body"><div class="response-summary"><div>자동 대응<b>${rows.filter(e=>e.mode==='자동').length}</b></div><div>수동 대응<b>${rows.filter(e=>e.mode==='수동').length}</b></div><div>승인 대기<b style="color:#d8ca78">${pending.length}</b></div></div><div class="response-list">${pending.slice(0,4).map(e=>`<div class="response-item"><span class="response-icon">!</span><div><strong>${esc(e.title)}</strong><small>${esc(e.scenario)} · ${format(e.at,true)} KST</small></div><button data-event="${e.id}">검토</button></div>`).join('')||'<p class="muted">승인 대기 이벤트가 없습니다.</p>'}</div></div></section>`;}
// ── 인프라 모니터링 ────────────────────────────────────────
// v3 (보완설계 §3.1): 하드코딩된 `○ 미연동` 을 전부 걷어내고
//   ① 서버가 준 표본 주기·표본 수·창(window)을 그대로 표시하고
//   ② 임계치 초과 구간을 근거와 함께 보여주며
//   ③ 3계층 상태는 /api/services 응답으로 그린다.
const SERVICE_TEXT={UP:'정상',DEGRADED:'저하',DOWN:'장애',UNKNOWN:'확인 불가'};
const SERVICE_COLOR={UP:'#32d4be',DEGRADED:'#d8ca78',DOWN:'#ef777f',UNKNOWN:'#8fa295'};
const periodLabel=s=>s==null?'—':s>=3600?`${s/3600}시간`:`${s/60}분`;
const metricKo=m=>m==='cpu'?'CPU':'메모리';
function servicePill(status){return `<span class="service-pill" style="color:${SERVICE_COLOR[status]||SERVICE_COLOR.UNKNOWN}"><i style="background:${SERVICE_COLOR[status]||SERVICE_COLOR.UNKNOWN}"></i>${SERVICE_TEXT[status]||status}</span>`;}
function hostPicker(m){
 if(!m?.hosts?.length)return '';
 return `<label class="host-picker"><span>대상 호스트</span><select id="host">${m.hosts.map(h=>`<option value="${esc(h.id)}"${h.id===m.resource?' selected':''}>${esc(h.name)} · ${esc(h.id)} (${esc(h.type)})</option>`).join('')}</select></label>`;
}
function breachPanel(m,span){
 if(!m.breaches.length)return `<div class="context-note">선택 구간에 ${m.threshold.cpu}% 임계치를 넘은 표본이 없습니다. CPU 최대 ${m.summary.cpu.max}% · 메모리 최대 ${m.summary.memory.max}%.</div>`;
 return `<ul class="breach-list">${m.breaches.map(b=>`<li><span class="breach-metric" style="color:${b.metric==='cpu'?'#e7a064':'#ef777f'}">${metricKo(b.metric)}</span><span>${formatAt(b.from,span)} — ${formatAt(b.to,span)} KST</span><b>최고 ${b.peak}%</b><small>표본 ${b.samples}개 · 임계치 ${m.threshold[b.metric]}%</small></li>`).join('')}</ul>`;
}
function serviceFlow(svc){
 if(!svc)return `<div class="context-note">3계층 상태를 불러오지 못했습니다. 새로고침 후에도 같으면 백엔드 /api/services 응답을 확인하세요.</div>`;
 if(!svc.items.length)return empty(svc.note||'이 리전에는 3계층 서비스를 올린 호스트가 없습니다.');
 return `<div class="service-flow">${svc.items.map((item,i)=>`${i?'<span class="service-arrow" style="color:'+(SERVICE_COLOR[item.status]||SERVICE_COLOR.UNKNOWN)+'">→</span>':''}<div class="service-node ${item.status.toLowerCase()}"><strong>${esc(item.name)}</strong>${servicePill(item.status)}<small>${item.latencyMs==null?'응답 없음':esc(item.latencyMs)+'ms'}${item.errorRate==null?'':' · 오류 '+esc(item.errorRate)+'%'}</small></div>`).join('')}</div>
 <table class="service-table"><caption class="sr-only">계층별 점검 결과</caption><thead><tr><th>계층</th><th>상태</th><th>응답</th><th>판정 근거</th></tr></thead><tbody>${svc.items.map(item=>`<tr><td>${esc(item.name)} <small>${esc(item.tier)}/${esc(item.port)}</small></td><td>${servicePill(item.status)}</td><td>${item.latencyMs==null?'—':esc(item.latencyMs)+'ms'}</td><td>${esc(item.detail)}${item.blockers.length?`<br>${item.blockers.map(b=>`<button class="link-button" data-event="${esc(b.id)}">${esc(b.scenario)} ${esc(b.title)}</button>`).join(' ')}`:''}<br><small class="muted">${esc(item.probe)} · ${esc(item.source)}</small></td></tr>`).join('')}</tbody></table>
 <div class="context-note">점검 주기 ${svc.intervalSec}초 · 마지막 점검 ${formatAt(svc.checkedAt,0)} KST · 대상 ${esc(svc.target||'—')}${svc.note?'<br>'+esc(svc.note):''}</div>`;
}
function hostGrid(m,span){
 if(!m.series?.length)return '';
 return `<div class="host-grid">${m.series.map(h=>{
  const over=h.breaches.length,sel=h.resource===m.resource;
  const bar=(v,limit)=>`<div class="host-bar"><div class="host-bar-fill" style="width:${Math.min(100,v)}%;background:${v>limit?'#e7a064':'#32d4be'}"></div><i style="left:${limit}%"></i></div>`;
  return `<button data-key="host-${esc(h.resource)}" class="host-card ${sel?'selected':''} ${over?'over':''}" data-host="${esc(h.resource)}" aria-pressed="${sel}">
   <div class="host-card-head"><strong>${esc(h.host.name)}</strong><small>${esc(h.host.type)}</small></div>
   <div class="host-metric"><span>CPU</span><b>${h.cpu}%</b></div>${bar(h.cpu,h.threshold.cpu)}
   <div class="host-metric"><span>메모리</span><b>${h.memory}%</b></div>${bar(h.memory,h.threshold.memory)}
   <div class="host-card-foot">${over?`<span class="over-flag">임계 초과 ${over}구간</span>`:'<span>임계 초과 없음</span>'}<small>${esc(h.resource)}</small></div>
  </button>`;}).join('')}</div>`;
}
function infrastructure(){
 const m=metricsFor(),svc=servicesOf(),span=state.hours*3600000;
 if(!m)return `<div class="view-intro"><span>CloudWatch · CPU / 메모리</span></div><section class="panel">${header('EC2 자원 사용률','대상 없음')}${empty('단일 AWS 리전을 선택하면 EC2 지표를 볼 수 있습니다.')}</section>`;
 const overCpu=m.breaches.filter(b=>b.metric==='cpu').length,overMem=m.breaches.length-overCpu;
 const hosts=m.series?.length||1;
 return `<div class="view-intro"><span>운영 중인 서버 ${hosts}대 · ${periodLabel(m.period)} 평균 · 표본 ${m.summary.samples}개</span><span>${formatAt(m.window.from,span)} — ${formatAt(m.window.to,span)} KST · 경보 임계치 <strong class="mint">${m.threshold.cpu}%</strong></span></div>
 <section class="panel">${header('운영 중인 서버',`${hosts}대 · 카드를 누르면 아래 상세 차트가 바뀝니다`)}${hostGrid(m,span)}
  <div class="context-note">리전에서 실행 중인 EC2 전체입니다. 실모드에서는 ec2:DescribeInstances 로 목록을 만듭니다.</div></section>
 <div class="infrastructure-grid">
  <section class="panel">${header(`상세 · ${esc(m.host.name)}`,hostPicker(m))}<div class="metric-large">${canvas('metrics-chart',`CPU ${m.cpu}%, 메모리 ${m.memory}%, 임계치 ${m.threshold.cpu}%`)}</div>
   <div class="metric-stats"><div><span>CPU 현재</span><b>${m.cpu}%</b></div><div><span>CPU 최대 / 평균</span><b>${m.summary.cpu.max}% / ${m.summary.cpu.avg}%</b></div><div><span>메모리 현재</span><b>${m.memory}%</b></div><div><span>메모리 최대 / 평균</span><b>${m.summary.memory.max}% / ${m.summary.memory.avg}%</b></div></div>
   <div class="context-note">${esc(m.host.role)} · ${esc(m.resource)} — 선택 구간의 마지막 표본 기준입니다.</div></section>
  <section class="panel">${header('임계치 초과 구간',`CPU ${overCpu}회 / 메모리 ${overMem}회`)}${breachPanel(m,span)}
   <div class="context-note">CloudWatch 알람 조건은 5분 평균 2회 연속 초과입니다. 위 구간은 화면 표본 기준이라 알람 건수와 1:1이 아닙니다.</div></section>
  <section class="panel full-panel">${header('3계층 서비스',svc?`전체 ${SERVICE_TEXT[svc.overall]||svc.overall} · ${'수집된 상태'}`:'조회 실패')}${serviceFlow(svc)}</section>
 </div>`;
}
function visibleRows(){return selectEvents();}
// ── 보완 화면 조각 ────────────────────────────────────────
// 취약점 점검 상단의 SEC 커버리지 보드, 대응 이력 상단의 개선 효과 요약,
// 하단의 감사 로그. 백엔드에는 이미 /api/scenarios · /api/audit 이 있었는데
// 화면이 그 둘을 한 번도 부르지 않고 있었다(보완설계 §3.3).
function improvementCard(rows){
 const passed=rows.filter(e=>e.rawVerification==='PASSED');
 const failed=rows.filter(e=>e.rawVerification==='FAILED');
 const pending=rows.filter(e=>['PENDING_VERIFICATION','VERIFYING'].includes(e.rawStatus));
 const counted=passed.filter(e=>typeof e.before==='number'&&typeof e.afterValue==='number');
 const before=counted.reduce((a,e)=>a+e.before,0),after=counted.reduce((a,e)=>a+e.afterValue,0);
 const rate=before?Math.round((before-after)/before*100):null;
 return `<section class="panel">${header('Before / After 개선 효과','SAME-CRITERION RE-CHECK')}<div class="improve-grid">
  <div><span>재검증 통과</span><b class="mint">${passed.length}건</b></div>
  <div><span>재검증 실패</span><b style="color:#ef777f">${failed.length}건</b></div>
  <div><span>재검증 대기</span><b style="color:#d8ca78">${pending.length}건</b></div>
  <div><span>측정값 합계 Before → After</span><b>${counted.length?`${before} → ${after}`:'—'}</b></div>
  <div><span>개선율</span><b class="mint">${rate==null?'—':rate+'%'}</b></div>
 </div><div class="context-note">같은 대상·같은 검사 기준으로 다시 측정한 값만 집계합니다(측정 가능 ${counted.length}건). 실행 성공은 해결이 아니며, 재검증 통과만 해결로 봅니다.</div></section>`;
}
function renderCoverage(){
 return loadPanel($('#coverage'),()=>api.scenarios(),data=>{
  return `<div class="coverage-grid">${data.items.map(i=>`<div class="coverage-item ${i.detection.observed?'':'idle'}"><div class="coverage-head"><strong>${esc(i.scenario)}</strong>${i.remediation.wired?'<span class="tag ok">배선됨</span>':'<span class="tag warn">미배선</span>'}</div><span>${esc(i.title)}</span><small>탐지 ${i.detection.count}건 · ${i.remediation.mode==='AUTO'?'자동':'수동'} · ${esc(i.remediation.playbook||'플레이북 없음')}</small><small class="coverage-verify ${i.verification.status.toLowerCase()}">재검증 ${i.verification.status==='PASSED'?'통과':i.verification.status==='FAILED'?'실패':'미실행'}</small></div>`).join('')}</div><div class="context-note">카탈로그 v${esc(data.catalogVersion)} 기준. '미배선'은 SSM 문서와 환경변수는 있으나 Lambda 에 호출 분기가 없는 항목입니다(README 5-1).</div>`;
 },'커버리지');
}
function renderAudit(){
 return loadPanel($('#audit-log'),()=>api.audit(),data=>{
  return data.items.length?`<div class="table-scroll"><table><caption class="sr-only">감사 로그</caption><thead><tr><th>시각 (KST)</th><th>수행자</th><th>이벤트</th><th>동작</th><th>세부</th></tr></thead><tbody>${data.items.slice(0,50).map(r=>`<tr><td>${format(r.at)}</td><td>${esc(r.actor)}</td><td>${r.event_id?`<button class="link-button" data-event="${esc(r.event_id)}">${esc(r.event_id)}</button>`:'—'}</td><td>${esc(r.action)}</td><td><small>${esc(r.detail)}</small></td></tr>`).join('')}</tbody></table></div>`:'<p class="muted">기록된 조치가 없습니다.</p>';
 },'감사 로그');
}
function notificationItems(rows){
 const groups=[
  {key:'승인 대기',filter:e=>e.status==='승인 대기',view:'events',status:'승인 대기'},
  {key:'재검증 실패',filter:e=>e.status==='재검증 실패',view:'responses',status:'재검증 실패'},
  {key:'재검증 대기',filter:e=>e.status==='재검증 대기',view:'responses',status:'재검증 대기'},
  {key:'임계치 경보 (CloudWatch)',filter:e=>e.source==='CloudWatch'&&e.status!=='해결',view:'infrastructure',status:''},
 ].map(g=>({...g,count:rows.filter(g.filter).length}));
 return groups;
}
function renderNotifications(rows){
 const groups=notificationItems(rows);
 const total=rows.filter(event=>groups.some(group=>group.filter(event))).length;
 $('#notification-count').hidden=!total;
 $('#notification-count').textContent=total>99?'99+':String(total||'');
 $('#notifications').setAttribute('aria-label',`알림 보기 · ${total}건`);
 patchMarkup($('#notification-panel'),`<h3>알림 ${total}건</h3>${groups.map(g=>`<button class="notification-row" data-notify="${esc(g.key)}" ${g.count?'':'disabled'}><span>${esc(g.key)}</span><b>${g.count}</b></button>`).join('')}<small>현재 리전·기간 필터 기준입니다.</small>`);
}
// ── 침해사례 탭 ────────────────────────────────────────────
// 설계안 12장의 대시보드 파트 책임 중 하나. 시나리오별로
// "공격 → 탐지 → 승인 → 조치 → 재검증" 을 한 줄에 세운다.
// 단계 완료 여부는 카탈로그 서술이 아니라 **실제 이벤트 값**으로만 켜진다.
const STAGE_TONE={ok:'#32d4be',warn:'#d8ca78',info:'#8fa295'};
function stageRail(stages){
 return `<ol class="stage-rail">${stages.map(s=>`<li class="stage ${s.done?'done':''} tone-${s.tone}"><span class="stage-dot" style="--tone:${STAGE_TONE[s.tone]||STAGE_TONE.ok}"></span><b>${esc(s.label)}</b><small>${s.at?format(s.at,true)+' KST':'—'}</small><span class="stage-detail">${esc(s.detail)}</span></li>`).join('')}</ol>`;
}
function incidentCard(i){
 const r=i.remediation;
 const list=(title,rows)=>rows.length?`<div class="incident-block"><h4>${title}</h4><ul>${rows.map(v=>`<li>${esc(v)}</li>`).join('')}</ul></div>`:'';
 const line=(title,value)=>value?`<div class="incident-block"><h4>${title}</h4><p>${esc(value)}</p></div>`:'';
 return `<section class="panel incident-card" data-key="${esc(i.scenario)}">
  <div class="incident-head">
   <div><div class="eyebrow">${esc(i.scenario)}${i.severityHint?` · ${esc(i.severityHint)}`:''}</div><h3>${esc(i.title)}</h3><p class="incident-summary">${esc(i.summary||'')}</p></div>
   <div class="incident-counts"><div><span>탐지</span><b>${i.counts.total}</b></div><div><span>미해결</span><b style="color:${i.counts.open?'#d8ca78':'#32d4be'}">${i.counts.open}</b></div><div><span>재검증 실패</span><b style="color:${i.counts.verifyFailed?'#ef777f':'#a9bcb1'}">${i.counts.verifyFailed}</b></div></div>
  </div>
  ${stageRail(i.stages)}
  <div class="incident-tags">${r.mode?`<span class="tag ${r.mode==='AUTO'?'ok':''}">${r.mode==='AUTO'?'자동':'수동'} 개선</span>`:''}${r.playbook?`<span class="tag">${esc(r.playbook)}</span>`:''}<span class="tag ${r.wired?'ok':'warn'}">${r.wired?'배선됨':'미배선'}</span><span class="tag ${r.reversible?'ok':'warn'}">${r.reversible?'되돌릴 수 있음':'되돌릴 수 없음'}</span>${r.plannedMode&&r.plannedMode!==r.mode?`<span class="tag warn">기획서 분류: ${r.plannedMode==='AUTO'?'자동':'수동'}</span>`:''}</div>
  <details class="incident-details"><summary>공격 재현 · 흔적 · 대응 보기</summary>
   ${list('공격 · 재현 절차',i.attack)}
   ${list('흔적이 남는 위치',i.trace)}
   ${line('영향',i.impact)}
   ${line('대응',i.control)}
   ${line('판정 기준',i.criterion?`${i.criterion} (${i.unit||''})`:'')}
   ${line('근거 문서',i.basis)}
   ${i.note?`<div class="incident-block warn-block"><h4>주의</h4><p>${esc(i.note)}</p></div>`:''}
   <p class="muted">공격 재현은 팀 소유의 격리된 계정·VPC 안에서만 실행합니다(설계안 2-1).</p>
   ${i.latestEventId?`<button class="row-action primary" data-event="${esc(i.latestEventId)}">최근 이벤트 상세 · 증적 열기</button>`:'<p class="muted">이 구간에 해당 시나리오 이벤트가 없습니다.</p>'}
  </details>
 </section>`;
}
function renderIncidents(){
 return loadPanel($('#incidents'),()=>api.incidents(),data=>{
  const done=data.items.filter(i=>i.stages.find(s=>s.key==='verify').done).length;
  return `<div class="view-intro"><span>설계안 2장 SEC-01~10 · 공격에서 재검증까지 한 줄로</span><span class="view-summary">시나리오 <strong>${data.items.length}개</strong> 재검증 도달 <strong>${done}개</strong></span></div>${data.items.map(incidentCard).join('')}<div class="context-note">카탈로그 v${esc(data.incidentCatalogVersion)} · 단계 완료는 실제 이벤트 값으로만 켜집니다. 문서에 적혀 있다고 켜지지 않습니다.</div>`;
 },'침해사례');
}
// ── 취약점 점검 ────────────────────────────────────────────
// /api/vulnerabilities 를 화면에 연결한다. 이전에는 이 엔드포인트를 한 번도 부르지 않아
// 취약점 탭이 이벤트 목록의 복사본이었다(CVE·패키지·CVSS 컬럼 자체가 없었다).
let vulnTarget='',vulnPage=1,vulnSize=50,vulnFixable=false,vulnData=null,vulnDataKey='';
const vulnKey=()=>panelScope()+JSON.stringify([vulnTarget,vulnFixable,refreshSerial]);
const SEV_COLOR={CRITICAL:'#EF777F',HIGH:'#E7A064',MEDIUM:'#D8CA78',LOW:'#32D4BE'};
function sevChip(s){return `<span class="sev-chip" style="color:${SEV_COLOR[s]||'#a9bcb1'};border-color:${SEV_COLOR[s]||'#3a4a42'}">${esc(s)}</span>`;}
function groupAction(g){
 if(!canAct())return '<span class="muted-mini">조회 전용</span>';
 if(!g.eventId)return '<span class="muted-mini">연결된 조치 이벤트 없음</span>';
 if(!g.actionable)return '<span class="muted-mini">자동 대응 경로</span>';
 const s=g.eventStatus;
 if(['EXECUTING','VERIFYING'].includes(s))return '<button class="row-action" disabled>진행 중</button>';
 if(s==='RESOLVED')return '<button class="row-action" disabled>완료</button>';
 const action=s==='APPROVED'?'execute':['PENDING_VERIFICATION','VERIFICATION_FAILED'].includes(s)?'verify':'approve';
 const label={approve:'조치 승인',execute:'조치 실행',verify:'재검증'}[action];
 return `<button class="row-action primary" data-row-action="${action}" data-event="${esc(g.eventId)}">${label}</button>
  <button class="link-button" data-event="${esc(g.eventId)}">${esc(g.eventId)} 상세</button>`;
}
function vulnGroups(data){
 return `<div class="vuln-groups">${data.groups.map(g=>`<div data-key="${esc(g.target)}" class="vuln-group ${g.target===vulnTarget?'selected':''}">
  <button class="vuln-group-head" aria-pressed="${g.target===vulnTarget}" data-vuln-target="${esc(g.target)}"><strong>${esc(g.target)}</strong><small>${esc(g.kind==='IMAGE'?'이미지':'인스턴스')} · ${esc(g.source)}${g.note?' · '+esc(g.note):''}</small></button>
  <div class="vuln-group-counts">${['CRITICAL','HIGH','MEDIUM','LOW'].map(s=>g.bySeverity[s]?`<span style="color:${SEV_COLOR[s]}">${s[0]}${g.bySeverity[s]}</span>`:'').join('')}<b>${g.total}건</b></div>
  <div class="vuln-group-meta">수정 버전 있음 ${g.fixable}건 · 스캔 ${g.scannedAt?format(g.scannedAt,true)+' KST':'—'}</div>
  <div class="vuln-group-action">${groupAction(g)}</div>
 </div>`).join('')}</div>`;
}
function vulnTable(data){
 const rows=vulnTarget?data.items.filter(v=>v.target===vulnTarget):data.items;
 const size=vulnSize===0?rows.length||1:vulnSize;
 const pages=Math.max(1,Math.ceil(rows.length/size));
 vulnPage=Math.min(vulnPage,pages);
 const page=rows.slice((vulnPage-1)*size,vulnPage*size);
 const sizes=[25,50,100,200,0].map(n=>`<option value="${n}"${n===vulnSize?' selected':''}>${n?n+'건씩':'전체'}</option>`).join('');
 return `<section class="panel full-panel">${header(vulnTarget?`CVE 목록 · ${esc(vulnTarget)}`:'CVE 목록',
  `<label class="page-size">표시 <select id="vuln-size">${sizes}</select></label><button id="export-vulns" class="text-button">↓ CVE CSV 내보내기</button>`)}
 ${page.length?`<div class="table-scroll"><table><caption class="sr-only">CVE ${rows.length}건</caption><thead><tr><th>심각도</th><th>CVSS</th><th>CVE</th><th>패키지</th><th>설치 → 수정</th><th>대상</th><th>계열</th></tr></thead><tbody>${page.map(v=>`<tr><td>${sevChip(v.severity)}</td><td class="num">${v.cvss??'—'}</td><td><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cveId)}" target="_blank" rel="noreferrer">${esc(v.cveId)}</a></td><td>${esc(v.package||'—')}</td><td><code>${esc(v.installedVersion||'?')}</code> → <code class="fixed">${esc(v.fixedVersion||'수정본 없음')}</code></td><td><button class="link-button" data-vuln-target="${esc(v.target)}">${esc(v.target)}</button></td><td><small>${esc(v.family||'—')}</small></td></tr>`).join('')}</tbody></table></div>`:empty('현재 필터에 맞는 CVE 가 없습니다.')}
 <div class="table-footer"><span>${rows.length}건 표시 중 · 전체 ${data.total}건</span><span>CVE 번호를 누르면 NVD 원문이 열립니다.</span></div>
 <div class="table-pager"><button data-vuln-page="prev" ${vulnPage<=1?'disabled':''}>← 이전</button><span>${vulnPage} / ${pages}</span><button data-vuln-page="next" ${vulnPage>=pages?'disabled':''}>다음 →</button></div></section>`;
}
function renderVulnerabilities({reuse=false}={}){
 const box=$('#vulns');if(!box)return;
 const key=vulnKey();
 if(reuse&&vulnData&&vulnDataKey===key){patchAnimated(box,vulnerabilityMarkup(vulnData));return;}
 return loadPanel(box,()=>api.vulnerabilities({target:vulnTarget,fixableOnly:vulnFixable}),data=>{
  vulnData=data;vulnDataKey=key;return vulnerabilityMarkup(data);
 },'취약점 목록');
}
function vulnerabilityMarkup(data){
  const sev=data.summary.bySeverity;
  return `<div class="view-intro"><span>Trivy(이미지) · Inspector(인스턴스) — 최신 스캔 기준이라 기간 필터를 적용하지 않습니다.</span>
   <span class="view-summary">전체 <strong>${data.total}건</strong> · 고유 CVE <strong>${data.summary.uniqueCves}</strong> · 수정 버전 있음 <strong>${data.summary.fixable}</strong></span></div>
  <section class="panel">${header('점검 대상 및 조치',`대상 ${data.summary.targets}개 · C${sev.CRITICAL} H${sev.HIGH} M${sev.MEDIUM} L${sev.LOW}`)}
   <div class="vuln-toolbar">${vulnTarget?`<button class="text-button" data-vuln-target="">전체 대상 보기 ←</button>`:'<span class="muted-mini">대상을 누르면 해당 CVE 만 봅니다.</span>'}
    <label class="vuln-check"><input type="checkbox" id="vuln-fixable"${vulnFixable?' checked':''}> 수정 버전이 있는 항목만</label></div>
   ${vulnGroups(data)}
   <div class="context-note">조치는 CVE 단위가 아니라 **대상 단위**입니다 — 이미지 교체 또는 패키지 업데이트. 버튼은 연결된 이벤트의 승인·실행·재검증 API 를 그대로 탑니다.${data.catalogVersion?` 자료 버전 ${esc(data.catalogVersion)}.`:''}</div></section>
  ${vulnTable(data)}`;
}
function render({loadPanels=false}={}){
 const pending=[];

 const rows=selectEvents();const [title,en]=titles[state.view];$('#page-title').innerHTML=`${title} <span>${en}</span>`;document.title=`AWS Security Operations · ${title}`;
 $$('nav [data-view]').forEach(b=>{b.classList.toggle('active',b.dataset.view===state.view);b.setAttribute('aria-current',b.dataset.view===state.view?'page':'false');});
 $('#map-section').hidden=state.view!=='overview';
 const span=state.hours*3600000,end=clockNow()-state.endOffset*3600000;
 $('#time-label').innerHTML=`${format(end-span)} — ${format(end)}<br>KST · ${'조회 기준 시각'} · 되감기 ${state.endOffset}시간`;
 $$('[data-hours]').forEach(b=>{b.classList.toggle('active',+b.dataset.hours===state.hours);b.setAttribute('aria-pressed',String(+b.dataset.hours===state.hours));});
 syncTimeRange();
 if(state.view==='overview'){renderContent(overviewCharts(rows)+`<div class="table-layout">${table(rows)}${responseCard(rows)}</div>`);mapRender(rows);drawChart('severity-chart','doughnut',{labels:Object.keys(severityColors),datasets:[{data:Object.keys(severityColors).map(s=>rows.filter(e=>e.severity===s).length),backgroundColor:Object.values(severityColors),borderWidth:0,hoverOffset:3}]},{cutout:'75%'});}
 else if(state.view==='infrastructure'){
  renderContent(infrastructure());
  const m=metricsFor();
  if(m)drawChart('metrics-chart','line',{labels:m.points.map(p=>formatAt(p.at,span)),datasets:[
   // 임계치를 넘은 표본만 점을 키우고 색을 바꾼다. 어느 시각에 넘었는지 눈으로 찾을 수 있어야 한다.
   {label:'CPU %',data:m.points.map(p=>p.cpu),borderColor:'#32d4be',tension:.3,borderWidth:2,
    pointRadius:m.points.map(p=>p.cpu>m.threshold.cpu?3.5:0),
    pointBackgroundColor:m.points.map(p=>p.cpu>m.threshold.cpu?'#e7a064':'#32d4be')},
   {label:'메모리 %',data:m.points.map(p=>p.memory),borderColor:'#a3c7b7',tension:.3,borderWidth:2,
    pointRadius:m.points.map(p=>p.memory>m.threshold.memory?3.5:0),
    pointBackgroundColor:m.points.map(p=>p.memory>m.threshold.memory?'#ef777f':'#a3c7b7')},
   {label:`${m.threshold.cpu}% 임계치`,data:m.points.map(()=>m.threshold.cpu),borderColor:'#e7a064',borderDash:[5,5],pointRadius:0,borderWidth:1}]},
   {plugins:{legend:{display:true,labels:{color:'#b8cdbf',boxWidth:14,font:{size:11}}}},
    scales:{x:{ticks:{color:'#9eb5a5',maxTicksLimit:8,font:{size:10}},grid:{color:'#334737'}},
            y:{min:0,max:100,ticks:{color:'#9eb5a5',callback:v=>`${v}%`},grid:{color:'#334737'}}}});
 }else if(state.view==='vulnerabilities'){
  renderContent(`<section class="panel">${header('SEC 시나리오 커버리지','COVERAGE BOARD')}<div id="coverage" data-async-panel><p class="panel-loading">불러오는 중…</p></div></section><div id="vulns" data-async-panel><p class="panel-loading">불러오는 중…</p></div>`);
  if(loadPanels)pending.push(renderCoverage(),renderVulnerabilities());
 }else if(state.view==='incidents'){
  renderContent('<div id="incidents" data-async-panel><p class="panel-loading">불러오는 중…</p></div>');
  if(loadPanels)pending.push(renderIncidents());
 }else {
  const visible=visibleRows();
  const intro=state.view==='responses'?'실행 결과와 재검증 결과를 구분하여 확인합니다.':'탐지 근거에서 대응과 재검증까지 추적합니다.';
  const head=`<div class="view-intro"><span>${intro}</span><span class="view-summary">전체 <strong>${visible.length}건</strong> 미해결 <strong>${visible.filter(e=>e.status!=='해결').length}건</strong></span></div>`;
  const before=state.view==='responses'?improvementCard(visible):'';
  const after=state.view==='responses'
   ?`<section class="panel full-panel">${header('감사 로그','AUDIT TRAIL')}<div id="audit-log" data-async-panel><p class="panel-loading">불러오는 중…</p></div></section>`:'';
  renderContent(head+before+table(visible,true)+after);
  if(state.view==='responses'&&loadPanels)pending.push(renderAudit());
 }
 renderNotifications(rows);
 $('#footer-asof').textContent=`기준 데이터 ${format(clockNow())} KST`;
 cleanCharts();
 updateBulkCount();
 syncUrl();
 return Promise.all(pending);
}
// 되감기 슬라이더는 선택한 창 길이에 맞춰 움직여야 한다. 24시간 창에서 1시간 단위,
// 7일 창에서 6시간 단위로 잡아 어느 기간에서도 끝까지 되감을 수 있게 한다.
function clockNow(){return summary.asOf||Date.now();}
function syncTimeRange(){
 const input=$('#time-range');
 const step=state.hours>=168?6:state.hours>=24?1:1;
 const max=Math.max(state.hours*3,24);
 input.step=step;input.max=max;
 if(state.endOffset>max){state.endOffset=max;}
 input.value=state.endOffset;
 $('#range-max').textContent=`${Math.round(max/24*10)/10}일 전`;
 $('#range-mid').textContent=`${Math.round(max/48*10)/10}일 전`;
 input.setAttribute('aria-valuetext',`${state.endOffset}시간 전까지, 최근 ${state.hours}시간`);
}

let detailSerial=0,operationBusy=false,pollTimer;
const rowJobs=createJobWatcher({
 loadJob:(id,jobId)=>api.job(id,jobId),
 isVisible:()=>document.visibilityState==='visible',
 onSettled:async(id,result)=>{await refresh();toast(`${id} · ${result.execution.status==='FAILED'?'작업 실패':'작업 처리 완료'} · 목록을 갱신했습니다.`);},
 onError:(id,error)=>toast(`${id} 작업 상태 조회 실패: ${error.message}`),
});
async function eventDialog(id,ask=false){
 clearTimeout(pollTimer);notifications.close();
 const serial=++detailSerial;activeId=id;approval=ask;syncUrl(true);
 if(!$('#event-dialog').open)lastTrigger=document.activeElement;
 $('#dialog-content').innerHTML='<div class="dialog-header"><h2 id="dialog-title">이벤트 상세</h2><button data-action="close" aria-label="상세 닫기">×</button></div><div class="dialog-body" role="status">상세 정보를 불러오는 중…</div>';
 if(!$('#event-dialog').open)$('#event-dialog').showModal();
 try{const e=await api.detail(id);if(!currentDetail(id,serial))return;drawDetail(e,ask);if(e.activeExecutionId)pollJob(id,e.activeExecutionId,serial);}
 catch(error){if(currentDetail(id,serial)){$('#dialog-content').innerHTML=`<div class="dialog-body"><h2 id="dialog-title">이벤트 상세</h2><p>${esc(error.message)}</p><button data-action="retry-detail">재시도</button><button data-action="close">닫기</button></div>`;}}
}
function currentDetail(id,serial){return serial===detailSerial&&activeId===id&&$('#event-dialog').open;}
function applyModeLabels(){
 $('#data-mode').textContent=config.dataSourceConnected?'실데이터':'데이터 소스 미연결';
 $('#aws-state').textContent=summary.health?.aws_connected?'AWS 연동 정상':'AWS 미연결';
 $('#env-label').textContent='실데이터 전용';
 $('#env-sub').textContent=config.writeEnabled?'조치 활성화':'읽기 전용';
}
// 알림은 대시보드가 보내지 않는다. CloudWatch 알람의 alarm_actions 와 asr_trigger 의
// sns.publish 가 보낸다(설계안 5-2·5-3). 화면은 "갔는지"만 보여준다.
const NOTIFY_SOURCE={'cloudwatch-alarm':'CloudWatch 알람','asr_trigger':'asr_trigger(자동조치 판정)'};
function notifyCell(e){
 const n=e.notification;
 if(!n)return '<span class="muted-mini">발송 기록 없음</span>';
 return `<span class="notify-sent">✓ ${esc(n.channel)}</span> ${format(n.at,true)}${n.count>1?` · ${n.count}회`:''}`;
}
function notifySection(e){
 const n=e.notification;
 if(!n)return `<section class="detail-section"><h3>알림 발송</h3><p class="muted">이 이벤트에 대한 발송 기록이 없습니다. 알림은 대시보드가 아니라 CloudWatch 알람과 asr_trigger 가 직접 보냅니다.</p></section>`;
 return `<section class="detail-section"><h3>알림 발송</h3><p>${esc(NOTIFY_SOURCE[n.source]||n.source)} → ${esc(n.channel)} · ${format(n.at)} KST${n.count>1?` · ${n.count}회`:''}</p><p class="muted">사유: ${esc(n.reason)}</p><p class="muted">대시보드에는 발송 버튼이 없습니다. 임계치 초과(alarm_actions)와 자동조치 게이트 불충족(asr_trigger)에서 자동 발행됩니다.</p></section>`;
}
function drawDetail(e,ask=false){
 const canWrite=config.writeEnabled&&config.role==='operator'&&e.actionable;
 const running=['EXECUTING','VERIFYING'].includes(e.rawStatus);
 const value=v=>v==null?'검사 대기':esc(v)+esc(e.unit);
 let buttons='<button class="cancel-button" data-action="close">닫기</button>';
 if(canWrite&&!running&&!operationBusy){
  if(ask)buttons='<button data-action="cancel-review">돌아가기</button><button class="primary-button" data-action="confirm-approve">변경 내용 승인</button>';
  // 작은따옴표 문자열 안에 ${...} 를 넣어 두어 app.js 전체가 SyntaxError 로 죽던 자리다.
  else if(e.rawStatus==='APPROVED')buttons+=`<button data-action="cancel">승인 취소</button><button class="primary-button" data-action="execute">${e.plan?.manual?'수동 조치 완료 기록':'승인한 조치 실행'}</button>`;
  else if(['PENDING_VERIFICATION','VERIFICATION_FAILED'].includes(e.rawStatus))buttons+='<button class="primary-button" data-action="verify">동일 기준 재검증</button>';
  else if(['NEW','PENDING_APPROVAL','EXECUTION_FAILED'].includes(e.rawStatus))buttons+='<button class="primary-button" data-action="approve">조치 검토 및 승인</button>';
 }
 patchMarkup($('#dialog-content'),`<div class="dialog-header"><div><div class="eyebrow">${esc(e.id)} / ${esc(e.scenario)}</div><h2 id="dialog-title">${esc(e.title)}</h2></div><button class="dialog-close" data-action="close" aria-label="상세 닫기">×</button></div><div class="dialog-body"><dl class="detail-meta"><div><dt>위험도</dt><dd>${badge(e)}</dd></div><div><dt>탐지 소스</dt><dd>${esc(e.source)}</dd></div><div><dt>대상 자원</dt><dd>${esc(e.resource)}</dd></div><div><dt>상태</dt><dd>${esc(e.status)}</dd></div><div><dt>승인자</dt><dd>${esc(e.approver||'미승인')}</dd></div><div><dt>알림 발송</dt><dd>${notifyCell(e)}</dd></div><div><dt>발생 시각</dt><dd>${format(e.at)} KST</dd></div></dl><div class="execution-flow"><span>실행 ${esc(e.execution)}</span><span>→ 재검증 ${esc(e.verification)}</span></div>${e.sourceIp?`<section class="detail-section"><h3>공격 출발지 → 대상</h3><p>${esc(e.sourceIp)} → ${esc(e.region)}</p><p>${esc(e.geoStatus)} · ${esc(e.sourceLocation?.provenance||'좌표 없음')}</p><p>${'탐지 서비스가 제공한 출발지 정보입니다.'}</p></section>`:''}<section class="detail-section"><h3>탐지 근거</h3><p>${esc(e.evidence)}</p></section><section class="detail-section"><h3>권장 조치</h3><p>${esc(e.recommendation)}</p></section>${e.plan?`<section class="${ask?'approval-box':'detail-section'}"><h3>${ask?'승인할 변경 내용':('승인 대상 조치 계획')}</h3><p>대상: ${esc(e.plan.target)}</p><p>변경: ${esc(e.plan.change)}</p><p>절차: ${esc(e.plan.document)} · 버전 ${esc(e.plan.version)}</p>${e.plan.imageBefore?`<p>이미지 ${esc(e.plan.imageBefore)} → ${esc(e.plan.imageAfter)}</p>`:''}<p>${e.plan.manual?'담당자가 수행한 조치와 증적을 기록합니다.':'승인 후 실행하면 대상 자원이 변경됩니다.'}</p></section>`:'<p class="muted">이 이벤트의 수동 실행은 미지원입니다. 자동 대응 이력은 조회만 가능합니다.</p>'}<section class="detail-section"><h3>Before / After · 동일 기준 재검증</h3><p>${esc(e.criterion)} · 검사 버전 ${esc(e.criterionVersion)}</p><p>같은 대상: ${esc(e.resource)}</p><div class="comparison"><div><label>BEFORE</label><strong>${value(e.before)}</strong><small>${format(e.beforeAt)} KST</small></div><div><label>AFTER · ${esc(e.verification)}</label><strong>${value(e.afterValue)}</strong><small>${format(e.afterAt)}${e.afterAt?' KST':''}</small></div></div></section>${notifySection(e)}<section class="detail-section"><h3>처리 이력</h3><ol class="history-list">${e.history.map(h=>`<li><time>${format(h.at)} KST</time>${esc(h.text)}</li>`).join('')}</ol></section><section class="detail-section"><button data-action="evidence">증적 12항목 보기</button><div id="evidence-content" data-async-panel></div></section></div><div class="dialog-actions"><span>${running?'작업 처리 중 · 창을 닫아도 계속됩니다.':('처리 이력')}</span>${buttons}</div>`);
 if(needsBlockPlan(e)&&(canWrite||config.mode!=='live')){
  $('.dialog-body').insertAdjacentHTML('beforeend','<section class="detail-section" id="block-plan">차단 대상을 불러오는 중…</section>');
  renderBlockPlan(e);
 }
 if(config.mode==='live'&&canWrite&&((e.plan?.manual&&e.rawStatus==='APPROVED')||(e.verificationMethod==='operator-evidence'&&['PENDING_VERIFICATION','VERIFICATION_FAILED'].includes(e.rawStatus)))){
  $('.dialog-body').insertAdjacentHTML('beforeend',`<section class="detail-section"><h3>담당자 증적</h3><label>조치 내용 <input id="manual-note" maxlength="2000"></label><label>증적 파일 경로 또는 참조 <input id="manual-reference" maxlength="2000"></label><label>동일 기준 재검사 결과값 <input id="manual-value" type="number" min="0"></label><p>현재 대상과 검사 버전으로 수행한 점검만 기록하세요. 자동 검증 결과와 구분하여 저장합니다.</p></section>`);
 }
}
// ── SEC-06 차단 계획 폼 ──────────────────────────────────
// POST /api/events/:id/plan 은 구현돼 있었으나 화면에서 부르는 곳이 없었다.
// 값을 손으로 찾지 않도록 NACL 목록과 빈 규칙 번호를 서버에서 받아 채운다.
let naclCache=null;
function needsBlockPlan(e){
 return e.scenario==='SEC-06'&&['NEW','PENDING_APPROVAL','EXECUTION_FAILED','VERIFICATION_FAILED'].includes(e.rawStatus);
}
async function renderBlockPlan(e){
 const box=$('#block-plan'),serial=detailSerial;if(!box)return;
 const live=config.mode==='live';
 try{
  if(!naclCache)naclCache=await api.nacls();
  if(!box.isConnected||!currentDetail(e.id,serial))return;
  const acls=naclCache.items;
  const [lo,hi]=naclCache.denyRuleRange;
  const first=acls[0];
  box.innerHTML=`<h3>차단 대상 설정 · ASR-BlockIpWithNacl</h3>
   <p class="muted">Private NACL 의 <b>${lo}~${hi}</b> 번은 Deny 예약 구간입니다. 서버가 비어 있는 번호를 제안합니다.</p>
   <label>대상 NACL
    <select id="nacl-id">${acls.map(a=>`<option value="${esc(a.id)}" data-suggest="${a.suggestedRuleNumber??''}">${esc(a.id)}${a.name?' · '+esc(a.name):''}${a.isDefault?' (기본)':''} — 사용 중 ${a.usedDenyRuleNumbers.join(', ')||'없음'}</option>`).join('')}</select></label>
   <label>차단할 출발지 IP <input id="nacl-ip" value="${esc(e.sourceIp||'')}" readonly>
    <small class="muted">탐지된 출발지입니다. 다른 값을 보내면 서버가 409로 막습니다.</small></label>
   <label>규칙 번호 (${lo}~${hi}) <input id="nacl-rule" type="number" min="${lo}" max="${hi}" value="${first?.suggestedRuleNumber??''}"></label>
   <label>차단 근거 <input id="nacl-evidence" maxlength="2000" placeholder="예: 5분간 인증 실패 47회 · CloudWatch 알람 soar-sec-dev-mysql-bruteforce"></label>
   ${live?'<button class="primary-button" data-action="prepare-plan">차단 계획 설정</button>'
        :'<p class="muted">조치 공급자가 연결되지 않아 계획을 적용할 수 없습니다.</p>'}`;
  const select=$('#nacl-id');
  if(select)select.addEventListener('change',()=>{const v=select.selectedOptions[0]?.dataset.suggest;if(v)$('#nacl-rule').value=v;});
 }catch(error){box.innerHTML=`<p class="muted">NACL 목록을 불러오지 못했습니다: ${esc(error.message)}</p>`;}
}
async function submitBlockPlan(){
 const id=activeId,serial=detailSerial;
 const acl=$('#nacl-id')?.value,ip=$('#nacl-ip')?.value,rule=$('#nacl-rule')?.value,why=$('#nacl-evidence')?.value;
 if(!acl||!ip||!rule||!why?.trim()){toast('NACL, 출발지 IP, 규칙 번호, 차단 근거를 모두 채워주세요.');return;}
 operationBusy=true;
 try{
  await api.change(id,'plan',{parameters:{networkAclId:acl,sourceIp:ip,ruleNumber:Number(rule),sourceEvidence:why.trim()}});
  await refresh();
  if(currentDetail(id,serial)){const detail=await api.detail(id);if(currentDetail(id,serial))drawDetail(detail);}
  toast('차단 계획을 설정했습니다. 이제 승인할 수 있습니다.');
 }catch(error){toast(error.message);}
 finally{operationBusy=false;updateBulkCount();}
}
function closeDialog(fromHistory=false){
 clearTimeout(pollTimer);detailSerial++;activeId=null;approval=false;
 if(!fromHistory)syncUrl();
 if($('#event-dialog').open)$('#event-dialog').close();
}
function pollJob(id,jobId,serial=detailSerial){
 clearTimeout(pollTimer);
 pollTimer=setTimeout(async()=>{try{
  if(!currentDetail(id,serial))return;
  const result=await api.job(id,jobId);if(!currentDetail(id,serial))return;
  const e=await api.detail(id);if(!currentDetail(id,serial))return;
  drawDetail(e);if(result.execution.status==='RUNNING')pollJob(id,jobId,serial);else{await refresh();if(currentDetail(id,serial))toast('작업 완료 · '+e.status);}
 }catch(error){if(currentDetail(id,serial))toast(error.message);}},800);
}
// ── 표 안에서 바로 실행하는 조치 ──────────────────────────
async function rowActionRun(id,action){
 if(operationBusy)return;
 operationBusy=true;
 try{
  if(!api.get(id))await api.detail(id);
  const result=await api.change(id,action,{});
  if(result.execution?.executionId)rowJobs.watch(id,result.execution.executionId);
  selected.delete(id);
  await refresh();
  toast({approve:'승인했습니다.',execute:'조치 실행을 접수했습니다.',verify:'동일 기준 재검증을 시작했습니다.'}[action]);
 }catch(error){toast(error.message);}
 finally{operationBusy=false;updateBulkCount();}
}
async function bulkApprove(){
 updateBulkCount();
 const ids=$$('.row-pick').filter(box=>box.checked&&selected.has(box.dataset.pick)).map(box=>box.dataset.pick);
 if(!ids.length){toast('먼저 승인할 항목을 선택하세요.');return;}
 if(operationBusy)return;
 operationBusy=true;
 let done=0;const failures=[];
 try{
  for(const id of ids){
   try{if(!api.get(id))await api.detail(id);await api.change(id,'approve',{});done++;selected.delete(id);}
   catch(error){failures.push(`${id}: ${error.message}`);}
  }
  await refresh();
  toast(failures.length?`${done}건 승인 · ${failures.length}건 실패 (${failures[0]})`:`${done}건을 승인했습니다.`);
 }finally{operationBusy=false;updateBulkCount();}
}
let autoTimer=null;
function setAuto(on){
 state.auto=on;
 const button=$('#auto-refresh');
 button.textContent=on?'자동 새로고침 30초':'자동 새로고침 꺼짐';
 button.setAttribute('aria-pressed',String(on));
 button.classList.toggle('active',on);
 clearInterval(autoTimer);autoTimer=null;
 // 상세 창이 열려 있거나 탭이 숨겨져 있으면 건너뛴다. 읽는 중에 화면이 갈아엎히면 안 된다.
 if(on)autoTimer=setInterval(()=>{if(document.visibilityState==='visible'&&!$('#event-dialog').open&&!operationBusy&&!$('#content').hasAttribute('aria-busy'))refresh();},30000);
}
async function dialogAction(action){
 if(action==='close'){closeDialog();return;}
 if(action==='approve'){approval=true;drawDetail(api.get(activeId),true);return;}
 if(action==='cancel-review'){approval=false;drawDetail(api.get(activeId));return;}
 if(action==='retry-detail'){eventDialog(activeId);return;}
 if(action==='prepare-plan'){if(!operationBusy)submitBlockPlan();return;}
 if(action==='evidence'){
  const id=activeId,serial=detailSerial,box=$('#evidence-content');if(!box)return;
  box.setAttribute('aria-busy','true');
  try{
   const result=await request('/api/events/'+encodeURIComponent(id)+'/evidence');
   if(currentDetail(id,serial)&&box.isConnected)patchMarkup(box,result.items.map(i=>`<p><strong>${i.no}. ${esc(i.label)}</strong><br>${esc(i.value||'데이터 없음')} <small>(${esc(i.source)})</small></p>`).join(''));
  }catch(error){if(currentDetail(id,serial))toast(error.message);}
  finally{box.removeAttribute('aria-busy');}return;
 }
 if(operationBusy)return;
 if(['confirm-approve','cancel','execute','verify'].includes(action)){
  const id=activeId,serial=detailSerial,e=api.get(id),extra={};
  if(!e)return;
  if(config.mode==='live'&&action==='execute'&&e.plan?.manual)extra.evidence={note:$('#manual-note')?.value||'',reference:$('#manual-reference')?.value||''};
  if(config.mode==='live'&&action==='verify'&&e.verificationMethod==='operator-evidence'){
   const raw=$('#manual-value')?.value;
   if(!raw||!$('#manual-reference')?.value){toast('재검사 결과값과 증적 참조를 입력해주세요.');return;}
   extra.evidence={resource:e.resource,criterionVersion:e.criterionVersion,value:Number(raw),observedAt:Date.now(),reference:$('#manual-reference').value};
  }
  operationBusy=true;drawDetail(e);
  try{
   const result=await api.change(id,action==='confirm-approve'?'approve':action,extra);await refresh();
   if(currentDetail(id,serial)){
    const detail=await api.detail(id);
    if(currentDetail(id,serial)){drawDetail(detail);if(result.execution)pollJob(id,result.execution.executionId,serial);}
   }
   toast(result.execution?'작업이 접수됐습니다.':'승인 상태를 저장했습니다.');
  }catch(error){
   toast(error.message);
   if(currentDetail(id,serial)){try{await api.detail(id);}catch{ /* keep the last known detail and the original error */ }}
  }finally{operationBusy=false;updateBulkCount();const detail=api.get(id);if(detail&&currentDetail(id,serial))drawDetail(detail);}
 }
}
// ── 주소창 상태 동기화 ────────────────────────────────────
// 새로고침하면 필터가 초기화되던 문제. 화면·필터·열어둔 이벤트를 주소에 담아
// 복구와 링크 공유가 되게 한다. 뒤로가기는 **화면 전환과 상세 열기만** 쌓는다 —
// 검색어 한 글자마다 히스토리가 쌓이면 뒤로가기가 못 쓰게 된다.
const URL_DEFAULTS={view:'overview',region:'ap-northeast-2',resource:'',hours:24,endOffset:0,severity:'',status:'',source:'',search:'',page:1};
const URL_KEYS={view:'view',region:'region',resource:'resource',hours:'hours',endOffset:'back',severity:'severity',status:'status',source:'source',search:'q',page:'page'};
function urlFromState(){
 const p=new URLSearchParams();
 for(const [key,param] of Object.entries(URL_KEYS)){
  const value=state[key];
  if(value!==undefined&&value!==null&&String(value)!==String(URL_DEFAULTS[key]))p.set(param,String(value));
 }
 if(activeId)p.set('event',activeId);
 const qs=p.toString();
 return window.location.pathname+(qs?'?'+qs:'');
}
function syncUrl(push=false){
 const next=urlFromState();
 if(next===window.location.pathname+window.location.search)return;
 try{window.history[push?'pushState':'replaceState']({},'',next);}catch(error){/* 주소 갱신 실패는 화면을 막지 않는다 */}
}
function applyUrl(){
 const p=new URLSearchParams(window.location.search);
 for(const [key,param] of Object.entries(URL_KEYS)){
  if(!p.has(param)){state[key]=URL_DEFAULTS[key];continue;}
  const raw=p.get(param);
  const value=typeof URL_DEFAULTS[key]==='number'?Number(raw):raw;
  state[key]=(typeof URL_DEFAULTS[key]==='number'&&!Number.isFinite(value))?URL_DEFAULTS[key]:value;
 }
 if(!titles[state.view])state.view=URL_DEFAULTS.view;      // 주소에 잘못된 화면이 와도 죽지 않는다
 if(!['all',...regions.map(r=>r.id)].includes(state.region))state.region=URL_DEFAULTS.region;
 if(!['','Critical','High','Medium','Low'].includes(state.severity))state.severity='';
 if(!['',...statuses,'승인됨','실행 실패'].includes(state.status))state.status='';
 if(!['',...sources].includes(state.source))state.source='';
 if(![.25,1,24,168].includes(state.hours))state.hours=24;
 state.endOffset=Math.max(0,Math.min(Math.max(state.hours*3,24),Math.floor(state.endOffset)));
 state.page=Math.max(1,Math.floor(state.page));
 state.search=state.search.slice(0,200);
 return p.get('event')||'';
}
function navigateView(view){
 if(!titles[view]||state.view===view)return;
 camera.cancel();
 notifications.close();selected.clear();
 if(activeId)closeDialog(true);
 state.view=view;state.resource='';state.page=1;
 window.scrollTo({top:0,behavior:'auto'});
 refresh({push:true});
}
function syncControls(){
 $('#region').value=state.region;
 ['severity','status','source','search'].forEach(key=>{const el=$('#'+key);if(el)el.value=state[key];});
 $('#time-range').value=state.endOffset;
 updateSelectedCountry(state.region);
}
async function refresh(options={}){
 clearTimeout(searchTimer);
 syncTimeRange();
 syncUrl(options.push===true);
 const serial=++refreshSerial,scope=panelScope(),box=$('#load-state'),content=$('#content');
 const endActivity=activity.begin();
 box.hidden=true;box.className='load-state';
 $('#refresh').disabled=true;content.setAttribute('aria-busy','true');
 $$('[data-async-panel]').forEach(panel=>panel.removeAttribute('aria-busy'));
 try{
  const [loaded]=await Promise.all([api.load(),mapReady?Promise.resolve():loadMap()]);
  if(serial!==refreshSerial||scope!==panelScope()||loaded===false)return;
  await render({loadPanels:true});
  if(serial!==refreshSerial)return;
  box.hidden=true;content.removeAttribute('data-stale');
  $('#updated').textContent=`갱신 ${format(summary.collectedAt,true)} KST`;
  $('#session-user').textContent=config.user.name+' · '+(config.role==='operator'?'조치 담당':'조회 전용');
  applyModeLabels();
  $('#worker-state').textContent=summary.health.checks.worker==='ok'?'작업 처리기 정상':'조치 처리기 미연결 또는 중지';
 }catch(e){
  if(serial!==refreshSerial||e.name==='AbortError')return;
  applyModeLabels();
  if(config.user)$('#session-user').textContent=config.user.name;
  content.setAttribute('data-stale','true');box.hidden=false;box.classList.add('error');
  box.innerHTML=`${esc(e.message)}${content.hasChildNodes()?' · 이전 데이터를 표시하고 있습니다.':''} <button id="retry">다시 시도</button>`;
 }finally{
  endActivity();
  if(serial===refreshSerial){$('#refresh').disabled=false;content.removeAttribute('aria-busy');}
 }
}
$('#region').innerHTML='<option value="all">전체 리전</option>'+regions.map(r=>`<option value="${r.id}">${r.name}${r.id==='global'?'':` · ${r.id}`}</option>`).join('');$('#region').value=state.region;
let searchTimer;
$('#status').insertAdjacentHTML('beforeend',[...statuses,'승인됨','실행 실패'].map(s=>`<option>${s}</option>`).join(''));$('#source').insertAdjacentHTML('beforeend',sources.map(s=>`<option>${s}</option>`).join(''));
['severity','status','source'].forEach(key=>$(`#${key}`).addEventListener('change',e=>{state[key]=e.target.value;state.page=1;refresh();}));
$('#region').addEventListener('change',e=>chooseRegion(e.target.value));
$('#search').addEventListener('input',e=>{state.search=e.target.value;state.page=1;clearTimeout(searchTimer);searchTimer=setTimeout(refresh,220);});
$('#time-range').addEventListener('input',e=>{state.endOffset=+e.target.value;state.page=1;clearTimeout(searchTimer);searchTimer=setTimeout(refresh,120);});
$('#event-dialog').addEventListener('cancel',e=>{e.preventDefault();closeDialog();});
$('#event-dialog').addEventListener('close',()=>{
 // closeDialog owns cleanup synchronously; a queued close event can belong to
 // an older dialog while browser history is already opening the next event.
 if($('#event-dialog').open||activeId)return;
 const target=lastTrigger?.isConnected&&!lastTrigger.closest('[hidden]')?lastTrigger:$('#page-title');
 if(!target.hasAttribute('tabindex')&&target.tagName==='H1')target.tabIndex=-1;
 target.focus();
});
$('#event-dialog').addEventListener('click',e=>{if(e.target===$('#event-dialog')){const r=e.target.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)closeDialog();}});
document.addEventListener('keydown',e=>{const attack=e.target.closest('.attack-connection');if(attack&&['Enter',' '].includes(e.key)){e.preventDefault();eventDialog(attack.dataset.event);return;}const marker=e.target.closest('.marker');if(marker&&['Enter',' '].includes(e.key)){e.preventDefault();const id=marker.dataset.region;chooseRegion(id);$(`#markers [data-region="${id}"]`)?.focus();}});
document.addEventListener('click',e=>{
 const view=e.target.closest('[data-view]');if(view){navigateView(view.dataset.view);return;}
 const region=e.target.closest('[data-region]');if(region){chooseRegion(region.dataset.region);return;}
 const hostCard=e.target.closest('[data-host]');if(hostCard){if(state.resource===hostCard.dataset.host)return;state.resource=hostCard.dataset.host;refresh();return;}
 const vt=e.target.closest('[data-vuln-target]');if(vt){if(vulnTarget===vt.dataset.vulnTarget)return;vulnTarget=vt.dataset.vulnTarget;vulnPage=1;renderVulnerabilities();return;}
 const vp=e.target.closest('[data-vuln-page]');if(vp){vulnPage+=vp.dataset.vulnPage==='next'?1:-1;resetTableScroll(vp);renderVulnerabilities({reuse:true});return;}
 const rowRun=e.target.closest('[data-row-action]');if(rowRun){rowActionRun(rowRun.dataset.event,rowRun.dataset.rowAction);return;}
 const notify=e.target.closest('[data-notify]');if(notify){applyNotification(notify.dataset.notify);return;}
 const event=e.target.closest('[data-event]');if(event){eventDialog(event.dataset.event);return;}
 const action=e.target.closest('[data-action]');if(action){dialogAction(action.dataset.action);return;}
 const hours=e.target.closest('[data-hours]');if(hours){if(state.hours===+hours.dataset.hours)return;state.hours=+hours.dataset.hours;state.page=1;refresh();return;}
 const id=e.target.closest('button')?.id;
 if(id==='refresh'||id==='retry')refresh();
 if(id==='close-region'){panelOpen=false;$('#region-panel').hidden=true;$('#open-region').hidden=false;$('#open-region').focus();}
 if(id==='open-region'){panelOpen=true;render();$('#close-region')?.focus();}
 if(id==='zoom-in'){animateTo(rotation,Math.min(ZOOM_MAX,zoom+.3),300);}
 if(id==='zoom-out'){animateTo(rotation,Math.max(ZOOM_MIN,zoom-.3),300);}
 if(id==='zoom-reset'){animateTo(DEFAULT_ROTATION,DEFAULT_ZOOM,500);}
 if(id==='clear-filters'){Object.assign(state,{resource:'',severity:'',status:'',source:'',search:'',endOffset:0,hours:24,page:1});vulnTarget='';vulnFixable=false;vulnPage=1;selected.clear();syncControls();refresh();toast('대상·검색·위험도·상태·소스·시간 필터를 초기화했습니다.');}
 if(id==='auto-refresh')setAuto(!state.auto);
 if(id==='bulk-approve')bulkApprove();
 if(id==='export')api.export().catch(e=>toast(e.message));
 if(id==='export-vulns'){
  if(!vulnData||vulnDataKey!==vulnKey()||$('#vulns').hasAttribute('aria-busy')){toast('목록 갱신이 완료된 후 다시 내보내주세요.');return;}
  downloadCsv('vulnerabilities.csv',vulnerabilityCsv(vulnData,vulnTarget));
 }
 if(id==='logout'){rowJobs.stop();clearTimeout(pollTimer);setAuto(false);api.logout().catch(e=>toast(e.message));}
 const pager=e.target.closest('[data-page]');if(pager){state.page+=pager.dataset.page==='next'?1:-1;resetTableScroll(pager);render();}

});
window.addEventListener('popstate',async()=>{
 const wanted=applyUrl();
 syncControls();
 if(activeId!==wanted&&$('#event-dialog').open)closeDialog(true);
 const prior=activeId;activeId=wanted||null;
 await refresh();
 if(wanted&&activeId===wanted&&(!$('#event-dialog').open||prior!==wanted))eventDialog(wanted);
});
bindMapInteraction($('#world-map'),()=>({zoom,rotation}),value=>{zoom=value.zoom;rotation=value.rotation;scheduleCameraUpdate();},{onInteraction:camera.cancel});
if(window.ResizeObserver)new window.ResizeObserver(()=>{if(!$('#map-section').hidden)renderMarkersOnly();}).observe($('#map-canvas'));
$('#attack-filter').addEventListener('change',e=>{attackSelection=e.target.value;renderAttacks(selectEvents());});
document.addEventListener('change',e=>{
 if(e.target.id==='pick-all'){
  const on=e.target.checked;
  $$('.row-pick').forEach(box=>{box.checked=on;on?selected.add(box.dataset.pick):selected.delete(box.dataset.pick);});
  updateBulkCount();return;
 }
 if(e.target.id==='host'){state.resource=e.target.value;refresh();return;}
 if(e.target.id==='vuln-size'){vulnSize=+e.target.value;vulnPage=1;resetTableScroll(e.target);renderVulnerabilities({reuse:true});return;}
 if(e.target.id==='vuln-fixable'){vulnFixable=e.target.checked;vulnPage=1;renderVulnerabilities();return;}
 if(e.target.classList.contains('row-pick')){
  e.target.checked?selected.add(e.target.dataset.pick):selected.delete(e.target.dataset.pick);
  updateBulkCount();
 }
});
function updateBulkCount(){
 const boxes=$$('.row-pick'),visible=new Set(boxes.map(box=>box.dataset.pick));
 for(const id of selected)if(!visible.has(id))selected.delete(id);
 const count=boxes.filter(box=>selected.has(box.dataset.pick)).length;
 const total=$('#bulk-count');if(total)total.textContent=String(count);
 const all=$('#pick-all');if(all){all.checked=boxes.length>0&&count===boxes.length;all.indeterminate=count>0&&count<boxes.length;all.disabled=boxes.length===0;}
 const button=$('#bulk-approve');if(button)button.disabled=count===0||operationBusy;
}
function applyNotification(key){
 notifications.close();
 const map={'승인 대기':{view:'events',status:'승인 대기'},'재검증 실패':{view:'responses',status:'재검증 실패'},
            '재검증 대기':{view:'responses',status:'재검증 대기'},'임계치 경보 (CloudWatch)':{view:'infrastructure',status:'',source:'CloudWatch'}};
 const target=map[key];if(!target)return;
 state.view=target.view;state.status=target.status;state.source=target.source||'';state.resource='';selected.clear();
 $('#status').value=state.status;$('#source').value=state.source;
 state.page=1;refresh({push:true});
}
document.addEventListener('keydown',e=>{
 if(e.defaultPrevented||e.ctrlKey||e.metaKey||e.altKey||e.isComposing||$('#event-dialog').open||e.target.closest('input,select,textarea,[contenteditable="true"]'))return;
 if(e.key==='r'&&!e.metaKey&&!e.ctrlKey){e.preventDefault();refresh();}
 if(e.key==='/'){e.preventDefault();$('#search').focus();}
 const index='123456'.indexOf(e.key);
 if(e.key.length===1&&index>=0){const button=$$('nav [data-view]')[index];if(button){e.preventDefault();navigateView(button.dataset.view);}}
});
setAuto(false);
updateCamera();
// 주소에 담긴 상태로 시작한다. 새로고침·링크 공유 복구 지점.
const bootEvent=applyUrl();activeId=bootEvent||null;
syncControls();
refresh().then(()=>{if(bootEvent&&activeId===bootEvent)eventDialog(bootEvent);});



