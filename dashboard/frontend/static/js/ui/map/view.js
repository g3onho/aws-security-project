// 통합 관제 지도: 지구본·국가·리전 마커·공격 흐름·리전 패널. 카메라와 지도 상태는 이 모듈만 바꾼다.
import {globeArtwork,bindMapInteraction,connectionMarkup,polygonPath,wrapLon,clampPhi,findCountryIndex,DEFAULT_ROTATION,DEFAULT_ZOOM,REGION_ZOOM,ZOOM_MIN,ZOOM_MAX} from './globe.js?v=v42';
import {createMarkerLayer,createCameraController} from './interaction.js?v=v42';
import {regions,severityColors} from '../constants.js?v=v42';
import {$,state,summary,selectEvents,setFilters,hooks} from '../context.js?v=v42';
import {esc} from '../components/format.js?v=v42';
import {patchAnimated} from '../components/panel.js?v=v42';
import {resetVulnerabilityView} from '../pages/vulnerabilities.js?v=v42';
import {clearSelection} from '../pages/events.js?v=v42';
let attackSelection='all';
let mapReady=false,zoom=DEFAULT_ZOOM,rotation=[...DEFAULT_ROTATION],panelOpen=true;
let worldFeatures=[],cachedAll=[],cachedMapped=[],rafPending=false,selectedCountryIndex=-1;
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
export async function loadMap(){
 const response=await fetch('/static/data/countries.geojson?v=v42');if(!response.ok)throw Error('지도 데이터를 불러오지 못했습니다.');
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
 $('#attack-filter').innerHTML='<option value="all">전체 공격 흐름</option>'+attacks.map(e=>`<option value="${e.id}">${esc(e.sourceIp)} · ${e.id}${e.sourceLocation?'':' · 위치 미상'}</option>`).join('');$('#attack-filter').value=attackSelection;
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
 const r=regions.find(r=>r.id===state.region);
 // 지역 패널(v20.5): 탐지 이벤트(선택 기간) · 취약 현황(열린 취약점) 두 카드. 각 카드 = 큰 숫자 + 위험도 구성 막대.
 const eventSev=Object.fromEntries(EVENT_SEVERITIES.map(([key])=>[key,rows.filter(e=>e.severity===key).length]));
 const ov=summary.openVulnerabilities,vuln=ov==null?null:r?(ov.byRegion?.[r.id]||{total:0,bySeverity:{}}):ov;
 patchAnimated($('#region-panel'),`<button id="close-region" class="region-close" aria-label="지역 상세 닫기">×</button><div class="region-kicker">SELECTED REGION</div><div class="region-heading"><h3 class="region-title">${r?.en||'ALL REGIONS'}</h3><div class="region-code">${r?.id==='global'?'글로벌 서비스 / 위치 미상':r?`${r.name} · ${r.id}`:'전체 AWS 리전'}</div></div>
 <div class="region-cards">${regionCard('탐지 이벤트',`최근 ${PERIOD_LABEL[state.hours]||state.hours+'시간'}`,rows.length,EVENT_SEVERITIES,eventSev,{fixed:true,view:'events',target:'보안 이벤트'})}${regionCard('취약 현황','열린 취약점',vuln==null?null:VULN_SEVERITIES.reduce((a,[key])=>a+(vuln.bySeverity?.[key]||0),0),VULN_SEVERITIES,vuln?.bySeverity||{},{fixed:true,view:'vulnerabilities',target:'취약점 점검'})}</div>`);
}
const PERIOD_LABEL={0.25:'15분',1:'1시간',24:'1일',168:'1주일'};
const EVENT_SEVERITIES=[['Critical','긴급'],['High','높음'],['Medium','보통'],['Low','낮음']];
const VULN_SEVERITIES=[['CRITICAL','긴급'],['HIGH','높음'],['MEDIUM','보통'],['LOW','낮음']];   // 지역 카드의 취약 현황은 이 네 등급만 보인다
// 이벤트·취약점 화면과 같은 위험도 색. 미분류는 무채색.
const SEV_COLOR={긴급:severityColors.Critical,높음:severityColors.High,보통:severityColors.Medium,낮음:severityColors.Low,정보:severityColors.Informational,미분류:severityColors.Unknown};
// fixed: 0건 등급도 범례에 둔다(탐지 이벤트 — 긴급·높음·보통·낮음 한 줄 고정).
// 카드 전체가 해당 화면으로 가는 버튼(data-view → app.js 공통 클릭 처리). 평소엔 카드처럼 보이고 올렸을 때만 드러난다.
function regionCard(title,sub,total,order,counts,{fixed=false,view,target}={}){
 const all=order.map(([key,label])=>({label,count:counts[key]||0})),parts=all.filter(p=>p.count);
 const sum=parts.reduce((a,p)=>a+p.count,0);
 const bar=sum?parts.map(p=>`<span class="rc-seg" style="flex:${p.count};background:${SEV_COLOR[p.label]}" title="${p.label} ${p.count.toLocaleString('ko-KR')}건"></span>`).join(''):'<span class="rc-seg rc-none"></span>';
 const legend=(fixed?all:parts).map(p=>`<span class="rc-item${p.count?'':' zero'}"><i style="background:${SEV_COLOR[p.label]}"></i>${p.label}<b>${p.count.toLocaleString('ko-KR')}</b></span>`).join('');
 return `<button type="button" class="region-card" data-view="${view}" aria-label="${title} ${total==null?'조회 실패':total+'건'} — ${target} 화면으로 이동"><span class="rc-head"><span>${title}</span><small>${sub}<span class="rc-go" aria-hidden="true">→</span></small></span>
 <strong class="rc-total">${total==null?'—':total.toLocaleString('ko-KR')}</strong><span class="rc-bar" aria-hidden="true">${bar}</span>
 <span class="rc-legend${fixed?' one-line':''}">${legend||'<span class="rc-item rc-empty">없음</span>'}</span></button>`;
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
