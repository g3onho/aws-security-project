// 통합 관제 지도: 지구본·국가·리전 마커·공격 흐름·리전 패널. 카메라와 지도 상태는 이 모듈만 바꾼다.
import {globeArtwork,bindMapInteraction,connectionMarkup,polygonPath,wrapLon,clampPhi,findCountryIndex,DEFAULT_ROTATION,DEFAULT_ZOOM,REGION_ZOOM,ZOOM_MIN,ZOOM_MAX} from './globe.js?v=ui-1';
import {createMarkerLayer,createCameraController} from './interaction.js?v=ui-1';
import {regions,severityColors} from '../constants.js?v=ui-1';
import {$,state,selectors,selectEvents,setFilters,hooks} from '../context.js?v=ui-1';
import {esc,format} from '../components/format.js?v=ui-1';
import {patchAnimated,canvas} from '../components/panel.js?v=ui-1';
import {drawChart} from '../charts/charts.js?v=ui-1';
import {resetVulnerabilityView} from '../pages/vulnerabilities.js?v=ui-1';
import {clearSelection} from '../pages/events.js?v=ui-1';
let attackSelection='all';
let mapReady=false,zoom=DEFAULT_ZOOM,rotation=[...DEFAULT_ROTATION],panelOpen=true;
let worldFeatures=[],cachedAll=[],cachedMapped=[],rafPending=false,selectedCountryIndex=-1;
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
export async function loadMap(){
 const response=await fetch('/static/data/countries.geojson?v=local-1');if(!response.ok)throw Error('지도 데이터를 불러오지 못했습니다.');
 const data=await response.json();worldFeatures=data.features.filter(f=>f.properties.ADMIN!=='Antarctica');mapReady=true;
 updateSelectedCountry(state.region);
 renderCountries();
}
// v2.2: 선택된 리전이 속한 국가를 강조 표시하기 위해 점-폴리곤 판정으로 국가 인덱스를 계산.
// 한 국가에 리전이 여러 개(미국 4개, 일본 2개)여도 국가 단위로만 강조하므로 별도 분기 없이 동일하게 동작한다.
export function updateSelectedCountry(id){
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
export function updateCamera(){
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
export function renderMarkersOnly(){
 markerLayer.update({regions,events:cachedAll,selectedRegion:state.region,rotation,zoom});
}

function renderAttacksOnly(){
 $('#attack-paths').innerHTML=connectionMarkup(cachedMapped,regions,esc,rotation,zoom);
}
export function renderAttacks(rows){
 const attacks=rows.filter(e=>e.sourceIp);if(attackSelection!=='all'&&!attacks.some(e=>e.id===attackSelection))attackSelection='all';
 $('#attack-filter').innerHTML='<option value="all">전체 공격 흐름</option>'+attacks.map(e=>`<option value="${e.id}">${e.sourceSample?'[샘플] ':''}${esc(e.sourceIp)} · ${e.id}${e.sourceLocation?'':' · 위치 미상'}</option>`).join('');$('#attack-filter').value=attackSelection;
 const chosen=attackSelection==='all'?attacks:attacks.filter(e=>e.id===attackSelection);
 cachedMapped=chosen.filter(e=>e.sourceLocation&&regions.some(r=>r.id===e.region&&r.lon!==undefined));
 renderAttacksOnly();
 $('#attack-summary').textContent=`${cachedMapped.length}개 흐름 · 위치 미상 ${chosen.length-cachedMapped.length}건`;
}

export function chooseRegion(id,move=true){
 const changed=state.region!==id||state.resource!=='';
 setFilters({region:id,resource:''});$('#region').value=id;panelOpen=true;
 updateSelectedCountry(id);if(mapReady)renderCountries();
 if(move){const r=regions.find(r=>r.id===id);animateTo(r?.lon!==undefined?[r.lon,clampPhi(r.lat)]:DEFAULT_ROTATION,r?.lon!==undefined?REGION_ZOOM:DEFAULT_ZOOM);}
 if(!changed){if(state.view==='overview')mapRender(selectEvents());return;}
 resetVulnerabilityView();clearSelection();setFilters({page:1});hooks.refresh();
}
export function mapRender(rows){
 if(!mapReady)return;
 cachedAll=selectEvents({ignoreRegion:true});renderAttacks(rows);
 renderMarkersOnly();
 $('#region-panel').hidden=!panelOpen;$('#open-region').hidden=panelOpen;
 const r=regions.find(r=>r.id===state.region);const unresolved=rows.filter(e=>e.status!=='해결').length;
 patchAnimated($('#region-panel'),`<button id="close-region" class="region-close" aria-label="지역 상세 닫기">×</button><div class="region-kicker">SELECTED REGION</div><h3 class="region-title">${r?.en||'ALL REGIONS'}</h3><div class="region-code">${r?.id==='global'?'글로벌 서비스 / 위치 미상':r?`${r.name} · ${r.id}`:'전체 AWS 리전'}</div><div class="region-total"><strong>${String(rows.length).padStart(2,'0')}</strong><span>탐지 이벤트</span></div><div class="region-stats"><span>미해결 <b>${unresolved}</b></span><span>영향 자원 <b>${new Set(rows.map(e=>e.resource)).size}</b></span></div><div class="spark">${canvas('region-spark',`현재 시간 범위의 이벤트 ${rows.length}건 추세`)}</div><div class="region-events">${rows.slice(0,2).map(e=>`<button data-event="${e.id}"><i style="background:${severityColors[e.severity]}"></i>${esc(e.title)}</button>`).join('')||'<span class="muted">데이터 없음</span>'}</div><button class="nongeo-button" data-region="global">글로벌 / 위치 미상 ${cachedAll.filter(e=>e.region==='global').length}건 ↗</button>`);
 const end=selectors.asOf()-state.endOffset*3600000,start=end-state.hours*3600000,values=Array(12).fill(0);rows.forEach(e=>values[Math.min(11,Math.floor((e.at-start)/(end-start)*12))]++);
 drawChart('region-spark','line',{labels:values.map((_,i)=>format(start+(i+.5)*(end-start)/12,true)),datasets:[{label:'탐지 건수',data:values,borderColor:'#32d4be',backgroundColor:'#32d4be10',fill:true,pointRadius:0,tension:.35,borderWidth:1.5}]},{scales:{x:{display:false},y:{display:false,beginAtZero:true}}});
}
export function isMapReady(){return mapReady;}
export function cancelCamera(){camera.cancel();}
export function closeRegionPanel(){panelOpen=false;$('#region-panel').hidden=true;$('#open-region').hidden=false;$('#open-region').focus();}
export function openRegionPanel(){panelOpen=true;hooks.render();$('#close-region')?.focus();}
export function zoomIn(){animateTo(rotation,Math.min(ZOOM_MAX,zoom+.3),300);}
export function zoomOut(){animateTo(rotation,Math.max(ZOOM_MIN,zoom-.3),300);}
export function zoomReset(){animateTo(DEFAULT_ROTATION,DEFAULT_ZOOM,500);}
export function bindMap(){
bindMapInteraction($('#world-map'),()=>({zoom,rotation}),value=>{zoom=value.zoom;rotation=value.rotation;scheduleCameraUpdate();},{onInteraction:camera.cancel});
if(window.ResizeObserver)new window.ResizeObserver(()=>{if(!$('#map-section').hidden)renderMarkersOnly();}).observe($('#map-canvas'));
$('#attack-filter').addEventListener('change',e=>{attackSelection=e.target.value;renderAttacks(selectEvents());});
}
