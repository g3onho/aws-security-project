import {globeArtwork,bindMapInteraction,connectionMarkup,polygonPath,wrapLon,clampPhi,findCountryIndex,DEFAULT_ROTATION,DEFAULT_ZOOM,REGION_ZOOM,ZOOM_MIN,ZOOM_MAX} from './map.js?v=local-4';
import {regions,sources,statuses,severityColors} from './data.js?v=local-1';
import {state,selectEvents,api as storeApi,config,summary,DATA_AS_OF,metricsFor,servicesOf} from './store.js?v=local-1';
import {patchMarkup} from './rendering.js?v=local-2';
import {createMarkerLayer,createCameraController} from './map-ui.js?v=local-4';
import {createNotificationPopover} from './notifications.js?v=local-4';
import {vulnerabilityCsv,downloadCsv} from './downloads.js?v=local-4';
import {animateLayout} from './layout-motion.js?v=local-5';
import {createRequestActivity} from './request-activity.js?v=local-5';
const $=s=>document.querySelector(s);
const $$=s=>[...document.querySelectorAll(s)];
const activity=createRequestActivity($('#network-activity'));
// Track UI requests without changing either backend adapter or synchronous cache reads.
const api=Object.fromEntries(Object.entries(storeApi).map(([name,method])=>[
 name,name==='get'?method.bind(storeApi):(...args)=>activity.run(()=>method.apply(storeApi,args)),
]));
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const format=(time,short=false)=>time==null?'데이터 없음':new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(short?{}:{month:'2-digit',day:'2-digit'}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
// 구간이 하루를 넘으면 시:분만 찍힌 x축은 읽을 수 없다. 창 길이를 보고 날짜를 붙인다.
const formatAt=(time,span=0)=>time==null?'데이터 없음':new Intl.DateTimeFormat('ko-KR',{timeZone:'Asia/Seoul',...(span>24*3600000?{month:'2-digit',day:'2-digit'}:{}),hour:'2-digit',minute:'2-digit',hour12:false}).format(time);
const milliseconds=value=>value?Date.parse(value):null;
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
function badge(e){const c=severityColors[e.severity]||'#9baaa6';return `<span class="badge sev-pill" style="color:${c};background:${c}1f;border-color:${c}55"><i style="background:${c}"></i>${e.severity}</span>`+(e.severityBumped?` <span class="badge bumped" title="GuardDuty 위협과 Inspector CVE가 같은 자원에 있어 심각도를 한 단계 올렸습니다">↑상향</span>`:'');}
function statusBadge(status){return `<span class="status-badge" style="color:${status==='해결'?'#32d4be':status==='재검증 실패'?'#ef777f':status==='승인 대기'?'#d8ca78':status==='탐지됨'?'#8fb3c9':'#a9bcb1'}">${esc(status)}</span>`;}
// arn:aws:ec2:…:instance/i-0abc → i-0abc, AWS::IAM::AccessKey:ASIA… → ASIA… (전체 값은 title 로)
const shortResource=r=>String(r||'').split(/[/:]/).filter(Boolean).pop()||String(r||'');
const SOURCE_COLOR={GuardDuty:'#e7a064','Security Hub':'#8fb3c9',Config:'#d8ca78',WAF:'#ef777f',Inspector:'#a3c7b7'};
function sourceTag(source){const c=SOURCE_COLOR[source]||'#9baaa6';return `<span class="source-tag" style="color:${c};border-color:${c}55">${esc(source)}</span>`;}
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
 $('#attack-filter').innerHTML='<option value="all">전체 공격 흐름</option>'+attacks.map(e=>`<option value="${e.id}">${e.sourceSample?'[샘플] ':''}${esc(e.sourceIp)} · ${e.id}${e.sourceLocation?'':' · 위치 미상'}</option>`).join('');$('#attack-filter').value=attackSelection;
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
 const done=summary.resolved??rows.filter(e=>e.status==='해결').length;const rate=summary.resolutionRate??null;
 const counts=sources.map(source=>({source,count:rows.filter(e=>e.source===source).length}));const max=Math.max(1,...counts.map(s=>s.count));
 return `<div class="chart-grid"><section class="panel">${header('탐지 및 대응 현황','EVENT SUMMARY')}<div class="chart-body"><div class="gauges">${gauge(rate,'재검증 완료율')}</div><p class="gauge-note">재검증 완료 ${done} / ${summary.total??rows.length}건 · CPU·메모리는 인프라 모니터링에서 조회</p></div></section><section class="panel">${header('탐지 소스별 이벤트','DETECTION SOURCES')}<div class="chart-body source-bars">${counts.map(s=>`<div><div class="bar-heading"><span>${s.source}</span><span>${s.count}건</span></div><div class="bar-track"><div class="bar-fill" style="width:${s.count/max*100}%"></div></div></div>`).join('')}</div></section><section class="panel">${header('위험도 분포',`${rows.length} EVENTS`)}<div class="chart-body donut-body"><div class="donut-wrap">${canvas('severity-chart','위험도별 건수는 오른쪽 범례에 표시됩니다.')}<div class="donut-center"><b>${rows.length}</b><span>전체 이벤트</span></div></div><div class="donut-legend">${Object.entries(severityColors).map(([s,c])=>`<div><i style="background:${c}"></i><span>${s}</span><b>${rows.filter(e=>e.severity===s).length}</b></div>`).join('')}</div></div></section></div>`;
}
// ── 목록 표 ────────────────────────────────────────────────
const selected=new Set();

// 같은 점검이 자원마다 한 줄씩(예: S3 로깅 미설정 × 버킷 3개) 나오지 않게 제목으로 묶는다.
// 묶음 줄을 누르면 자원별 줄이 펼쳐지고, 자원 줄을 누르면 기존 상세 창이 열린다.
const openEventGroups=new Set();
const SEV_RANK=Object.keys(severityColors);
function eventGroups(rows){
 const groups=new Map();
 for(const e of rows){const key=e.source+'|'+e.title;groups.set(key,[...(groups.get(key)||[]),e]);}
 return [...groups].map(([key,items])=>({key,items,top:[...items].sort((a,b)=>SEV_RANK.indexOf(a.severity)-SEV_RANK.indexOf(b.severity))[0],at:Math.max(...items.map(e=>e.at))}));
}
function eventRow(e){return `<tr data-key="${esc(e.id)}"><td>${badge(e)}</td><td><button class="event-link" data-event="${esc(e.id)}">${esc(e.title)}<small><span class="scenario-tag">${esc(e.scenario)}</span><span class="resource-id" title="${esc(e.resource)}">${esc(shortResource(e.resource))}</span></small></button></td><td>${sourceTag(e.source)}</td><td>${format(e.at,state.hours<=24)}</td><td>${statusBadge(e.status)}</td></tr>`;}
function eventGroupRows(g){
 if(g.items.length===1)return eventRow(g.items[0]);
 const e=g.top,open=openEventGroups.has(g.key),statuses=[...new Set(g.items.map(x=>x.status))];
 return `<tr data-key="grp-${esc(g.key)}" class="event-group-row${open?' open':''}"><td>${badge(e)}</td><td><button class="event-link" data-event-group="${esc(g.key)}" aria-expanded="${open}"><span class="group-caret" aria-hidden="true">${open?'▾':'▸'}</span>${esc(e.title)}<small><span class="scenario-tag">${esc(e.scenario)}</span><span class="group-count">자원 ${g.items.length}개</span>${open?'':`<span class="resource-id">${g.items.slice(0,3).map(x=>esc(shortResource(x.resource))).join(', ')}${g.items.length>3?' 외':''}</span>`}</small></button></td><td>${sourceTag(e.source)}</td><td>${format(g.at,state.hours<=24)}</td><td>${statuses.length===1?statusBadge(statuses[0]):statusBadge('혼합')}</td></tr>`
  +(open?g.items.map(x=>`<tr data-key="sub-${esc(x.id)}" class="event-sub-row"><td>${badge(x)}</td><td><button class="event-link" data-event="${esc(x.id)}"><span class="resource-id" title="${esc(x.resource)}">${esc(shortResource(x.resource))}</span><small>${esc(x.resource)}</small></button></td><td></td><td>${format(x.at,state.hours<=24)}</td><td>${statusBadge(x.status)}</td></tr>`).join(''):'');
}
function table(rows,full=false){
 const groups=eventGroups(rows),total=rows.length,pages=Math.max(1,Math.ceil(groups.length/15));state.page=Math.min(state.page,pages);
 const page=groups.slice((state.page-1)*15,state.page*15);
 const title=state.view==='responses'?'대응 이력':state.view==='vulnerabilities'?'취약점 점검 결과':'최근 보안 이벤트';
 const tools='<button id="export" class="text-button">↓ CSV 내보내기</button>';
 return `<section class="panel ${full?'full-panel':''}">${header(title,tools)}${page.length?`<div class="table-scroll"><table><caption class="sr-only">현재 필터에 해당하는 ${total}개 이벤트</caption><thead><tr><th>위험도</th><th>이벤트 / 자원</th><th>탐지 소스</th><th>발생 시각 (KST)</th><th>상태</th></tr></thead><tbody>${page.map(eventGroupRows).join('')}</tbody></table></div>`:empty()}<div class="table-footer"><span>총 ${total}건 · 같은 제목 묶음 ${groups.length}줄 · 현재 필터 적용</span><span>${state.view==='overview'?'<button class="text-button" data-view="events">전체 이벤트 보기 →</button>':'이벤트를 누르면 표준 API가 제공하는 상세 필드를 볼 수 있습니다.'}</span></div><div class="table-pager"><button data-page="prev" ${state.page<=1?'disabled':''}>← 이전</button><span>${state.page} / ${pages}</span><button data-page="next" ${state.page>=pages?'disabled':''}>다음 →</button></div></section>`;
}
function responseCard(rows){const pending=rows.filter(e=>e.actionState==='PENDING_APPROVAL');return `<section class="panel">${header('조치 상태',`${pending.length} PENDING`)}<div class="response-body"><div class="response-summary"><div>관측 이벤트<b>${rows.length}</b></div><div>승인 대기 상태<b>${pending.length}</b></div></div><p class="muted">현재 조치 공급자가 비활성화되어 승인·실행을 접수하지 않습니다.</p></div></section>`;}
// ── 인프라 모니터링 ────────────────────────────────────────
// 7934104(v17) 화면 — 호스트 카드 · CPU/메모리 차트 · 임계치 초과 구간 · 3계층 상태 — 을
// 표준 API(/api/metrics 시계열, /api/infra/status 구성요소)에 맞춰 되살린 것.
// 호스트 선택은 화면 안에서만 바꾼다. state.resource 를 쓰면 이벤트·지표 조회 범위까지 좁아진다.
const SERVICE_TEXT={healthy:'정상',degraded:'저하',unhealthy:'장애',unknown:'확인 불가'};
const SERVICE_COLOR={healthy:'#32d4be',degraded:'#d8ca78',unhealthy:'#ef777f',unknown:'#8fa295'};
const periodLabel=s=>s==null?'—':s>=3600?`${s/3600}시간`:`${s/60}분`;
const pct=v=>v==null?'—':Math.round(v*10)/10+'%';
const metricKo=m=>m==='cpu'?'CPU':'메모리';
let infraHost='';
function servicePill(status){const c=SERVICE_COLOR[status]||SERVICE_COLOR.unknown;return `<span class="service-pill" style="color:${c}"><i style="background:${c}"></i>${SERVICE_TEXT[status]||esc(status)} <small>${esc(status)}</small></span>`;}
// 임계치를 넘은 연속 표본을 한 구간으로 묶는다.
function breachesOf(points,metric,limit){
 const out=[];let cur=null;
 for(const p of points){
  if(p.value!=null&&p.value>limit){cur=cur||{metric,from:p.at,to:p.at,peak:p.value,samples:0};cur.to=p.at;cur.peak=Math.max(cur.peak,p.value);cur.samples++;}
  else if(cur){out.push(cur);cur=null;}
 }
 if(cur)out.push(cur);
 return out;
}
function hostViews(m){
 const threshold=m?.thresholds||{cpu:80,memory:80},byId=new Map();
 for(const s of m?.series||[]){
  const h=byId.get(s.resource)||{resource:s.resource,name:s.name||s.resource,cpu:[],memory:[]};
  if(s.metric==='cpu'||s.metric==='memory')h[s.metric]=s.points.map(p=>({at:milliseconds(p.timestamp),value:p.value}));
  byId.set(s.resource,h);
 }
 return [...byId.values()].map(h=>{
  const stat=key=>{const v=h[key].map(p=>p.value).filter(x=>x!=null);return {now:v.length?v[v.length-1]:null,max:v.length?Math.max(...v):null,avg:v.length?v.reduce((a,b)=>a+b,0)/v.length:null,samples:v.length};};
  return {...h,threshold,stats:{cpu:stat('cpu'),memory:stat('memory')},
   breaches:[...breachesOf(h.cpu,'cpu',threshold.cpu),...breachesOf(h.memory,'memory',threshold.memory)].sort((a,b)=>a.from-b.from)};
 });
}
function selectedHost(hosts){return hosts.find(h=>h.resource===infraHost)||hosts[0];}
function hostPicker(hosts,sel){
 return `<label class="host-picker"><span>대상 호스트</span><select id="host">${hosts.map(h=>`<option value="${esc(h.resource)}"${h===sel?' selected':''}>${esc(h.name)} · ${esc(h.resource)}</option>`).join('')}</select></label>`;
}
function breachPanel(h,span){
 if(!h.breaches.length)return `<div class="context-note">선택 구간에 ${h.threshold.cpu}% 임계치를 넘은 표본이 없습니다. CPU 최대 ${pct(h.stats.cpu.max)} · 메모리 최대 ${pct(h.stats.memory.max)}.</div>`;
 return `<ul class="breach-list">${h.breaches.map(b=>`<li><span class="breach-metric" style="color:${b.metric==='cpu'?'#e7a064':'#ef777f'}">${metricKo(b.metric)}</span><span>${formatAt(b.from,span)} — ${formatAt(b.to,span)} KST</span><b>최고 ${pct(b.peak)}</b><small>표본 ${b.samples}개 · 임계치 ${h.threshold[b.metric]}%</small></li>`).join('')}</ul>`;
}
function hostGrid(hosts,sel){
 const bar=(v,limit)=>`<div class="host-bar"><div class="host-bar-fill" style="width:${Math.min(100,v||0)}%;background:${v>limit?'#e7a064':'#32d4be'}"></div><i style="left:${limit}%"></i></div>`;
 return `<div class="host-grid">${hosts.map(h=>{
  const over=h.breaches.length,on=h===sel;
  return `<button data-key="host-${esc(h.resource)}" class="host-card ${on?'selected':''} ${over?'over':''}" data-host="${esc(h.resource)}" aria-pressed="${on}">
   <div class="host-card-head"><strong>${esc(h.name)}</strong><small>EC2</small></div>
   <div class="host-metric"><span>CPU</span><b>${pct(h.stats.cpu.now)}</b></div>${bar(h.stats.cpu.now,h.threshold.cpu)}
   <div class="host-metric"><span>메모리</span><b>${pct(h.stats.memory.now)}</b></div>${bar(h.stats.memory.now,h.threshold.memory)}
   <div class="host-card-foot">${over?`<span class="over-flag">임계 초과 ${over}구간</span>`:'<span>임계 초과 없음</span>'}<small>${esc(h.resource)}</small></div>
  </button>`;}).join('')}</div>`;
}
function serviceFlow(svc,hosts){
 if(!svc)return `<div class="context-note">3계층 상태를 불러오지 못했습니다. 새로고침 후에도 같으면 백엔드 /api/infra/status 응답을 확인하세요.</div>`;
 const items=svc.components||[];
 if(!items.length)return empty('저장된 인프라 상태 증거가 없습니다.');
 const nameOf=id=>hosts.find(h=>h.resource===id)?.name||id;
 return `<div class="service-flow">${items.map((c,i)=>`${i?`<span class="service-arrow" style="color:${SERVICE_COLOR[c.status]||SERVICE_COLOR.unknown}">→</span>`:''}<div class="service-node ${c.status==='unhealthy'?'down':esc(c.status)}"><strong>${esc(c.name)}</strong>${servicePill(c.status)}<small>${esc(nameOf(c.resource))}</small></div>`).join('')}</div>
 <div class="table-scroll"><table class="service-table"><caption class="sr-only">계층별 점검 결과</caption><thead><tr><th>계층</th><th>자원</th><th>상태</th><th>판정 근거</th><th>관측 시각</th></tr></thead><tbody>${items.map(c=>`<tr><td>${esc(c.name)}</td><td>${esc(nameOf(c.resource))}<br><small class="muted">${esc(c.resource)}</small></td><td>${servicePill(c.status)}</td><td>${esc(c.detail||'—')}<br><small class="muted">${esc(c.source||'')}</small></td><td>${format(milliseconds(c.observedAt))}</td></tr>`).join('')}</tbody></table></div>`;
}
function infrastructure(){
 const m=metricsFor(),svc=servicesOf(),span=state.hours*3600000,hosts=hostViews(m);
 if(!hosts.length)return `<div class="view-intro"><span>CloudWatch · CPU / 메모리</span></div><section class="panel">${header('EC2 자원 사용률','대상 없음')}${empty('조회 기간에 수집된 EC2 지표가 없습니다.')}</section>
  <section class="panel full-panel">${header('3계층 서비스',svc?`${(svc.components||[]).length}개 구성요소`:'조회 실패')}${serviceFlow(svc,hosts)}</section>`;
 const h=selectedHost(hosts),overCpu=h.breaches.filter(b=>b.metric==='cpu').length,overMem=h.breaches.length-overCpu;
 const samples=hosts.reduce((a,x)=>a+x.stats.cpu.samples,0);
 return `<div class="view-intro"><span>운영 중인 서버 ${hosts.length}대 · ${periodLabel(m.periodSeconds)} 평균 · 표본 ${samples}개</span><span>최근 ${state.hours}시간 · 경보 임계치 <strong class="mint">${h.threshold.cpu}%</strong></span></div>
 <section class="panel">${header('운영 중인 서버',`${hosts.length}대 · 카드를 누르면 아래 상세 차트가 바뀝니다`)}${hostGrid(hosts,h)}
  <div class="context-note">리전에서 조회된 EC2 전체입니다. 메모리는 CloudWatch Agent 가 설치된 호스트만 수집됩니다.</div></section>
 <div class="infrastructure-grid">
  <section class="panel">${header(`상세 · ${esc(h.name)}`,hostPicker(hosts,h))}<div class="metric-large">${canvas('metrics-chart',`CPU ${pct(h.stats.cpu.now)}, 메모리 ${pct(h.stats.memory.now)}, 임계치 ${h.threshold.cpu}%`)}</div>
   <div class="metric-stats"><div><span>CPU 현재</span><b>${pct(h.stats.cpu.now)}</b></div><div><span>CPU 최대 / 평균</span><b>${pct(h.stats.cpu.max)} / ${pct(h.stats.cpu.avg)}</b></div><div><span>메모리 현재</span><b>${pct(h.stats.memory.now)}</b></div><div><span>메모리 최대 / 평균</span><b>${pct(h.stats.memory.max)} / ${pct(h.stats.memory.avg)}</b></div></div>
   <div class="context-note">${esc(h.resource)} — 선택 구간의 마지막 표본 기준입니다.</div></section>
  <section class="panel">${header('임계치 초과 구간',`CPU ${overCpu}회 / 메모리 ${overMem}회`)}${breachPanel(h,span)}
   <div class="context-note">CloudWatch 알람 조건은 5분 평균 2회 연속 초과입니다. 위 구간은 화면 표본 기준이라 알람 건수와 1:1이 아닙니다.</div></section>
  <section class="panel full-panel">${header('3계층 서비스',svc?`${(svc.components||[]).length}개 구성요소 · 수집된 상태`:'조회 실패')}${serviceFlow(svc,hosts)}</section>
 </div>`;
}
function drawInfrastructureChart(){
 const hosts=hostViews(metricsFor());if(!hosts.length)return;
 const h=selectedHost(hosts),span=state.hours*3600000,points=h.cpu.length>=h.memory.length?h.cpu:h.memory;
 const memAt=new Map(h.memory.map(p=>[p.at,p.value])),cpuAt=new Map(h.cpu.map(p=>[p.at,p.value])),t=h.threshold;
 const cpu=points.map(p=>cpuAt.get(p.at)??null),mem=points.map(p=>memAt.get(p.at)??null);
 drawChart('metrics-chart','line',{labels:points.map(p=>formatAt(p.at,span)),datasets:[
  {label:'CPU %',data:cpu,borderColor:'#32d4be',tension:.3,borderWidth:2,spanGaps:true,
   pointRadius:cpu.map(v=>v>t.cpu?3.5:0),pointBackgroundColor:cpu.map(v=>v>t.cpu?'#e7a064':'#32d4be')},
  {label:'메모리 %',data:mem,borderColor:'#a3c7b7',tension:.3,borderWidth:2,spanGaps:true,
   pointRadius:mem.map(v=>v>t.memory?3.5:0),pointBackgroundColor:mem.map(v=>v>t.memory?'#ef777f':'#a3c7b7')},
  {label:`${t.cpu}% 임계치`,data:points.map(()=>t.cpu),borderColor:'#e7a064',borderDash:[5,5],pointRadius:0,borderWidth:1}]},
  {plugins:{legend:{display:true,labels:{color:'#c4d7cb',boxWidth:12}}},scales:{y:{min:0,max:100,ticks:{color:'#8fa295'}},x:{ticks:{color:'#8fa295',maxTicksLimit:8}}}});
}
function visibleRows(){return selectEvents();}
// ── 조치 이력 ──────────────────────────────────────────────

function renderAudit(){
 return loadPanel($('#audit-log'),()=>api.history(),data=>{
  const audits=data.items.length?`<div class="table-scroll"><table><caption class="sr-only">조치 이력</caption><thead><tr><th>시각 (KST)</th><th>수행자</th><th>이벤트</th><th>판정</th><th>상태</th></tr></thead><tbody>${data.items.map(r=>`<tr><td>${format(milliseconds(r.createdAt))}</td><td>${esc(r.actor)}</td><td>${esc(r.eventId)}</td><td>${esc(r.decision)}</td><td>${esc(r.actionState)}</td></tr>`).join('')}</tbody></table></div>`:'<p class="muted">조회 기간에 기록된 조치가 없습니다.</p>';
  const jobs=data.jobs.length?`<h3>작업 상태</h3><div class="table-scroll"><table><thead><tr><th>작업 ID</th><th>이벤트</th><th>상태</th><th>오류</th></tr></thead><tbody>${data.jobs.map(job=>`<tr><td>${esc(job.jobId)}</td><td>${esc(job.eventId)}</td><td>${esc(job.status)}</td><td>${esc(job.error||'—')}</td></tr>`).join('')}</tbody></table></div>`:'';
  return audits+jobs+'<p class="muted">이력은 시간·리전·자원 범위로 조회합니다.</p>';
 },'조치 이력');
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
 $('#notifications').setAttribute('aria-label',`상태 바로가기 · ${total}건`);
 patchMarkup($('#notification-panel'),`<h3>관측 상태 ${total}건</h3>${groups.map(g=>`<button class="notification-row" data-notify="${esc(g.key)}" ${g.count?'':'disabled'}><span>${esc(g.key)}</span><b>${g.count}</b></button>`).join('')}<small>현재 리전·기간 필터 기준이며 발송 알림 기록은 아닙니다.</small>`);
}
// ── 침해사례 탭: 관측 이벤트의 시나리오별 묶음 ────────────

function renderIncidents(){
 const box=$('#incidents');if(!box)return;
 const events=selectEvents(),groups=new Map();for(const event of events){const key=event.scenario||'분류 없음';groups.set(key,[...(groups.get(key)||[]),event]);}
 patchMarkup(box,`<div class="view-intro"><span>표준 이벤트 API에서 관측된 시나리오</span><span class="view-summary">${groups.size}개 분류 · ${events.length}건</span></div>${[...groups].map(([name,items])=>`<section class="panel"><h2>${esc(name)}</h2><p>관측 이벤트 ${items.length}건</p>${items.map(e=>`<p><button class="event-link" data-event="${esc(e.id)}">${esc(e.title)} · ${esc(e.resource)}</button></p>`).join('')}</section>`).join('')||empty('조회 기간에 관측된 침해 이벤트가 없습니다.')}<div class="context-note">공격 재현 절차·플레이북 배선·단계별 완료 정보는 표준 API에서 제공되지 않습니다.</div>`);
}
// ── 취약점 점검 ────────────────────────────────────────────
let vulnTarget='',vulnPage=1,vulnSize=50,vulnFixable=false,vulnData=null,vulnDataKey='';
const vulnKey=()=>panelScope()+JSON.stringify([vulnTarget,vulnFixable,refreshSerial]);
function renderVulnerabilities({reuse=false}={}){
 const box=$('#vulns');if(!box)return;const key=vulnKey();
 if(reuse&&vulnData&&vulnDataKey===key){patchAnimated(box,vulnerabilityMarkup(vulnData));return;}
 return loadPanel(box,()=>api.vulnerabilities({target:vulnTarget,fixableOnly:vulnFixable}),data=>{vulnData=data;vulnDataKey=key;return vulnerabilityMarkup(data);},'취약점 목록');
}
// CVE 수천 건을 한 줄씩 나열하지 않고 "서버 × 패키지"로 묶는다. 실측(2026-09-23) 4933건 중
// 대부분이 서버마다 linux-image-aws 하나라, 한 줄 = 한 번의 업데이트로 사라지는 묶음이 된다.
const SEV_ORDER=['CRITICAL','HIGH','MEDIUM','LOW','INFORMATIONAL','UNTRIAGED'];
const SEV_KO={CRITICAL:'긴급',HIGH:'높음',MEDIUM:'보통',LOW:'낮음',INFORMATIONAL:'정보',UNTRIAGED:'미분류'};
const SEV_COLOR={CRITICAL:'#EF777F',HIGH:'#E7A064',MEDIUM:'#D8CA78',LOW:'#32D4BE',INFORMATIONAL:'#85B1D5',UNTRIAGED:'#8FA295'};
const VULN_PREVIEW=20;
const fixableNow=v=>!!v.fixedVersion&&!/pending/i.test(v.fixedVersion);
function sevChip(sev,n){const c=SEV_COLOR[sev]||SEV_COLOR.UNTRIAGED;return `<span class="sev-chip" style="color:${c};background:${c}1f;border-color:${c}55">${SEV_KO[sev]||esc(sev)} <b>${n}</b></span>`;}
// 같은 패키지가 여러 서버에 똑같이 걸리면(같은 AMI) 한 줄로 합치고, 토글 안에서 서버별로 보여준다.
// 개수는 CVE 종류(중복 제거) 기준 — 서버 5대 × 951건을 4755건으로 부풀리지 않는다.
function vulnGroups(rows){
 const groups=new Map();
 for(const v of rows){
  const key=v.package||'—';
  const g=groups.get(key)||{key,package:key,cves:new Map(),servers:new Map(),counts:{},maxCvss:null,fixable:0};
  const s=g.servers.get(v.resource)||{resource:v.resource,name:v.resourceName||v.resource,installed:v.installedVersion,count:0,fixable:0};
  s.count++;if(fixableNow(v))s.fixable++;g.servers.set(v.resource,s);
  const c=g.cves.get(v.cveId),host=s.name.replace(/^soar-sec-dev-/,'');
  if(c){c.servers++;c.hosts.push(host);}
  else{
   g.cves.set(v.cveId,{...v,servers:1,hosts:[host]});g.counts[v.severity]=(g.counts[v.severity]||0)+1;
   if(v.cvss!=null&&(g.maxCvss==null||v.cvss>g.maxCvss))g.maxCvss=v.cvss;
   if(fixableNow(v))g.fixable++;
  }
  groups.set(key,g);
 }
 for(const g of groups.values()){g.items=[...g.cves.values()];g.serverList=[...g.servers.values()].sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));}
 const rank=g=>SEV_ORDER.map(s=>g.counts[s]||0);
 return [...groups.values()].sort((a,b)=>{const ra=rank(a),rb=rank(b);for(let i=0;i<ra.length;i++)if(ra[i]!==rb[i])return rb[i]-ra[i];return (b.maxCvss??0)-(a.maxCvss??0);});
}
function sevBar(counts,total){return `<div class="sev-bar" aria-hidden="true">${SEV_ORDER.filter(s=>counts[s]).map(s=>`<i style="width:${counts[s]/total*100}%;background:${SEV_COLOR[s]}"></i>`).join('')}</div>`;}
function vulnGroupMarkup(g){
 const top=[...g.items].sort((a,b)=>(b.cvss??-1)-(a.cvss??-1)||SEV_ORDER.indexOf(a.severity)-SEV_ORDER.indexOf(b.severity)).slice(0,VULN_PREVIEW);
 const fix=g.fixable===g.items.length?`<span class="fix-state ok">업데이트 가능</span>`:g.fixable?`<span class="fix-state">일부 업데이트 가능 ${g.fixable}건</span>`:`<span class="fix-state wait">수정본 대기</span>`;
 const one=g.serverList.length===1?g.serverList[0]:null;
 const where=one?`<button class="link-button" data-vuln-target="${esc(one.resource)}" title="${esc(one.resource)}">${esc(one.name)}</button> · 설치 ${esc(one.installed||'—')}`
  :`<span class="server-count">서버 ${g.serverList.length}대</span> · ${g.serverList.slice(0,3).map(s=>esc(s.name.replace(/^soar-sec-dev-/,''))).join(', ')}${g.serverList.length>3?' 외':''}`;
 return `<details class="cve-group" data-key="vg-${esc(g.key)}"><summary>
  <div class="vg-main"><strong>${esc(g.package)}</strong><small>${where}</small></div>
  <div class="vg-count"><b>${g.items.length}</b><span>CVE 종류</span></div>
  <div class="vg-sev">${sevBar(g.counts,g.items.length)}<div class="vg-chips">${SEV_ORDER.filter(s=>g.counts[s]).map(s=>sevChip(s,g.counts[s])).join('')}</div></div>
  <div class="vg-meta"><span>최고 CVSS <b>${g.maxCvss??'—'}</b></span>${fix}</div></summary>
  ${one?'':`<div class="vg-servers"><h3>영향받는 서버 ${g.serverList.length}대</h3><ul>${g.serverList.map(s=>`<li><button class="link-button" data-vuln-target="${esc(s.resource)}" title="${esc(s.resource)}">${esc(s.name)}</button><span>설치 ${esc(s.installed||'—')}</span><span>CVE ${s.count}건</span>${s.fixable?`<span class="fix-state ok">업데이트 가능 ${s.fixable}</span>`:'<span class="fix-state wait">수정본 대기</span>'}</li>`).join('')}</ul></div>`}
  <div class="table-scroll"><table><thead><tr><th>심각도</th><th>CVSS</th><th>CVE</th><th>수정 버전</th><th>영향 서버</th></tr></thead><tbody>${top.map(v=>`<tr><td>${sevChip(v.severity,'')}</td><td>${v.cvss??'—'}</td><td>${esc(v.cveId||'—')}</td><td>${esc(v.fixedVersion||'수정본 없음')}</td><td class="cve-hosts">${v.hosts.sort().map(h=>`<span>${esc(h)}</span>`).join('')}</td></tr>`).join('')}</tbody></table></div>
  ${g.items.length>VULN_PREVIEW?`<p class="muted vg-more">CVSS 상위 ${VULN_PREVIEW}종만 표시 · 나머지 ${g.items.length-VULN_PREVIEW}종은 CVE CSV로 확인</p>`:''}
 </details>`;
}
function vulnerabilityMarkup(data){
 const rows=data.items,groups=vulnGroups(rows),pages=Math.max(1,Math.ceil(groups.length/(vulnSize||groups.length||1)));
 vulnPage=Math.min(vulnPage,pages);const size=vulnSize||groups.length||1,page=groups.slice((vulnPage-1)*size,vulnPage*size);
 const counts={};for(const v of rows)counts[v.severity]=(counts[v.severity]||0)+1;
 const servers=new Set(rows.map(v=>v.resource)).size,fixable=rows.filter(fixableNow).length;
 return `<div class="view-intro"><span>Inspector 실제 관측 결과 · 서버 ${servers}대 · 패키지 ${groups.length}개</span><span class="view-summary">CVE ${rows.length}건 (서버별 합계)</span></div>
 <div class="vuln-summary">${SEV_ORDER.filter(s=>counts[s]).map(s=>`<div style="border-color:${SEV_COLOR[s]}55"><span>${SEV_KO[s]}</span><b style="color:${SEV_COLOR[s]}">${counts[s]}</b></div>`).join('')}<div><span>지금 업데이트 가능</span><b class="mint">${fixable}</b></div><div><span>수정본 대기</span><b>${rows.length-fixable}</b></div></div>
 <section class="panel full-panel">${header('패키지별 취약점',`<label class="page-size">표시 <select id="vuln-size">${[25,50,100,200,0].map(n=>`<option value="${n}"${n===vulnSize?' selected':''}>${n?n+'개씩':'전체'}</option>`).join('')}</select></label><button id="export-vulns" class="text-button">↓ CVE CSV 내보내기</button>`)}
 <div class="vuln-toolbar">${vulnTarget?`<button class="text-button" data-vuln-target="">전체 서버 보기 ←</button>`:'<span class="muted-mini">패키지를 누르면 영향받는 서버와 CVE가 펼쳐집니다. 서버 이름을 누르면 그 서버만 봅니다.</span>'}<label class="vuln-check"><input type="checkbox" id="vuln-fixable"${vulnFixable?' checked':''}> 지금 업데이트 가능한 항목만</label></div>
 ${page.length?`<div class="cve-groups">${page.map(vulnGroupMarkup).join('')}</div>`:empty('조회 기간에 취약점 결과가 없습니다.')}
 <div class="table-footer"><span>패키지 ${groups.length}개 · CVE ${rows.length}건(서버별 합계)</span><span>정렬: 긴급 → 높음 개수, 최고 CVSS 순</span></div>
 <div class="table-pager"><button data-vuln-page="prev" ${vulnPage<=1?'disabled':''}>← 이전</button><span>${vulnPage} / ${pages}</span><button data-vuln-page="next" ${vulnPage>=pages?'disabled':''}>다음 →</button></div></section>`;
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
   drawInfrastructureChart();
  }else if(state.view==='vulnerabilities'){
   renderContent(`<div id="vulns" data-async-panel><p class="panel-loading">불러오는 중…</p></div>`);
   if(loadPanels)pending.push(renderVulnerabilities());
 }else if(state.view==='incidents'){
  renderContent('<div id="incidents" data-async-panel><p class="panel-loading">불러오는 중…</p></div>');
  if(loadPanels)pending.push(renderIncidents());
 }else {
  const visible=visibleRows();
  const intro=state.view==='responses'?'실행 결과와 재검증 결과를 구분하여 확인합니다.':'탐지 근거에서 대응과 재검증까지 추적합니다.';
  const head=`<div class="view-intro"><span>${intro}</span><span class="view-summary">전체 <strong>${visible.length}건</strong> 미해결 <strong>${visible.filter(e=>e.status!=='해결').length}건</strong></span></div>`;
   const before='';
  const after=state.view==='responses'
    ?`<section class="panel full-panel">${header('조치 이력','HISTORY')}<div id="audit-log" data-async-panel><p class="panel-loading">불러오는 중…</p></div></section>`:'';
  renderContent(head+before+table(visible,true)+after);
  if(state.view==='responses'&&loadPanels)pending.push(renderAudit());
 }
 renderNotifications(rows);
 $('#footer-asof').textContent=`기준 데이터 ${format(clockNow())} KST`;
 cleanCharts();
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

let detailSerial=0,operationBusy=false;
async function eventDialog(id,ask=false){
 notifications.close();
 const serial=++detailSerial;activeId=id;approval=ask;syncUrl(true);
 if(!$('#event-dialog').open)lastTrigger=document.activeElement;
 $('#dialog-content').innerHTML='<div class="dialog-header"><h2 id="dialog-title">이벤트 상세</h2><button data-action="close" aria-label="상세 닫기">×</button></div><div class="dialog-body" role="status">상세 정보를 불러오는 중…</div>';
 if(!$('#event-dialog').open)$('#event-dialog').showModal();
 try{const e=await api.detail(id);if(!currentDetail(id,serial))return;drawDetail(e);}
 catch(error){if(currentDetail(id,serial)){$('#dialog-content').innerHTML=`<div class="dialog-body"><h2 id="dialog-title">이벤트 상세</h2><p>${esc(error.message)}</p><button data-action="retry-detail">재시도</button><button data-action="close">닫기</button></div>`;}}
}
function currentDetail(id,serial){return serial===detailSerial&&activeId===id&&$('#event-dialog').open;}
function applyModeLabels(){
 $('#data-mode').textContent=config.dataSourceConnected?'실데이터':'데이터 소스 미연결';
 $('#aws-state').textContent=summary.health?.aws_connected?'AWS 연동 정상':'AWS 미연결';
 $('#env-label').textContent='실데이터 전용';
 $('#env-sub').textContent=config.writeEnabled?'조치 활성화':'읽기 전용';
}
function drawDetail(e){
 const measure=value=>value?.value==null?'측정값 없음':esc(value.value)+(value.unit?' '+esc(value.unit):'');
 patchMarkup($('#dialog-content'),`<div class="dialog-header"><div><div class="eyebrow">${esc(e.id)} / ${esc(e.scenario||'분류 없음')}</div><h2 id="dialog-title">${esc(e.title)}</h2></div><button class="dialog-close" data-action="close" aria-label="상세 닫기">×</button></div>
 <div class="dialog-body"><dl class="detail-meta"><div><dt>위험도</dt><dd>${badge(e)}</dd></div><div><dt>탐지 소스</dt><dd>${esc(e.source)}</dd></div><div><dt>대상 자원</dt><dd>${esc(e.resource)}</dd></div><div><dt>상태</dt><dd>${esc(e.status)}</dd></div><div><dt>발생 시각</dt><dd>${format(e.at)} KST</dd></div><div><dt>계정</dt><dd>${esc(e.accountId||'제공되지 않음')}</dd></div></dl>
 <section class="detail-section"><h3>조치 정보</h3><p>플레이북: ${esc(e.playbookId||'제공되지 않음')} · 버전 ${esc(e.playbookVersion||'—')}</p><p>기준: ${esc(e.criterion||'제공되지 않음')} · ${esc(e.criterionVersion||'—')}</p></section>
 <section class="detail-section"><h3>Before / After</h3><div class="comparison"><div><label>BEFORE</label><strong>${measure(e.beforeState)}</strong><small>${format(milliseconds(e.beforeState?.observedAt))}</small></div><div><label>AFTER</label><strong>${measure(e.afterState)}</strong><small>${format(milliseconds(e.afterState?.observedAt))}</small></div></div></section>
 <p class="muted">탐지 원문·공격 재현 절차·12항목 증적은 표준 이벤트 API에서 제공되지 않습니다.</p></div><div class="dialog-actions"><span>읽기 전용</span><button class="cancel-button" data-action="close">닫기</button></div>`);
}

function closeDialog(fromHistory=false){
 detailSerial++;activeId=null;approval=false;
 if(!fromHistory)syncUrl();
 if($('#event-dialog').open)$('#event-dialog').close();
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
async function dialogAction(action){if(action==='close')closeDialog();}
// ── 주소창 상태 동기화 ────────────────────────────────────
// 새로고침하면 필터가 초기화되던 문제. 화면·필터·열어둔 이벤트를 주소에 담아
// 복구와 링크 공유가 되게 한다. 뒤로가기는 **화면 전환과 상세 열기만** 쌓는다 —
// 검색어 한 글자마다 히스토리가 쌓이면 뒤로가기가 못 쓰게 된다.
const URL_DEFAULTS={view:'overview',region:'all',resource:'',hours:24,endOffset:0,severity:'',status:'',source:'',search:'',page:1};
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
 if(!['all',...regions.map(r=>r.id)].includes(state.region)&&!/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(state.region))state.region=URL_DEFAULTS.region;
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
  if(config.providerRegion&&![...$('#region').options].some(option=>option.value===config.providerRegion)){
   const option=document.createElement('option');option.value=config.providerRegion;option.textContent=config.providerRegion;$('#region').append(option);
  }
  $('#region').value=state.region;
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
 $('#status').insertAdjacentHTML('beforeend',statuses.map(s=>`<option>${s}</option>`).join(''));$('#source').insertAdjacentHTML('beforeend',sources.map(s=>`<option>${s}</option>`).join(''));
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
 const hostCard=e.target.closest('[data-host]');if(hostCard){if(infraHost===hostCard.dataset.host)return;infraHost=hostCard.dataset.host;render();return;}
 const vt=e.target.closest('[data-vuln-target]');if(vt){if(vulnTarget===vt.dataset.vulnTarget)return;vulnTarget=vt.dataset.vulnTarget;vulnPage=1;renderVulnerabilities();return;}
 const vp=e.target.closest('[data-vuln-page]');if(vp){vulnPage+=vp.dataset.vulnPage==='next'?1:-1;resetTableScroll(vp);renderVulnerabilities({reuse:true});return;}
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
 if(id==='export')api.export().catch(e=>toast(e.message));
 if(id==='export-vulns'){
  if(!vulnData||vulnDataKey!==vulnKey()||$('#vulns').hasAttribute('aria-busy')){toast('목록 갱신이 완료된 후 다시 내보내주세요.');return;}
  downloadCsv('vulnerabilities.csv',vulnerabilityCsv(vulnData,vulnTarget));
 }
 if(id==='logout'){setAuto(false);api.logout().catch(e=>toast(e.message));}
 const eventGroup=e.target.closest('[data-event-group]');if(eventGroup){const k=eventGroup.dataset.eventGroup;openEventGroups.has(k)?openEventGroups.delete(k):openEventGroups.add(k);render();return;}
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
 if(e.target.id==='host'){infraHost=e.target.value;render();return;}
 if(e.target.id==='vuln-size'){vulnSize=+e.target.value;vulnPage=1;resetTableScroll(e.target);renderVulnerabilities({reuse:true});return;}
 if(e.target.id==='vuln-fixable'){vulnFixable=e.target.checked;vulnPage=1;renderVulnerabilities();return;}
});
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



