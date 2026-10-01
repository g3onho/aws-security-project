// 대시보드 시작점: 화면 조립(render)·새로고침(refresh)·사용자 입력 연결만 한다.
// 화면별 표시는 ui/pages, 공통 부품은 ui/components, 차트는 ui/charts, 지도는 ui/map, 주소창은 ui/router(설계 2.1).
import {regions,sources,statuses,periodStops} from './ui/constants.js?v=v46';
import {periodTrackMarkup} from './ui/components/period-track.js?v=v46';
import {$,$$,api,activity,storeApi,state,summary,config,selectors,selectEvents,setFilters,notifications,ui,hooks} from './ui/context.js?v=v46';
import {esc,format} from './ui/components/format.js?v=v46';
import {header,renderContent,resetTableScroll,panelScope,toast} from './ui/components/panel.js?v=v46';
import {cleanCharts} from './ui/charts/charts.js?v=v46';
import {eventCsv,downloadCsv} from './ui/components/downloads.js?v=v46';
import {eventDialog,closeDialog,dialogAction} from './ui/components/dialog.js?v=v46';
import {renderNotifications,applyNotification} from './ui/components/shortcuts.js?v=v46';
import {titles,syncUrl,applyUrl} from './ui/router.js?v=v46';
import {loadMap,isMapReady,updateSelectedCountry,updateCamera,chooseRegion,mapRender,cancelCamera,closeRegionPanel,openRegionPanel,zoomIn,zoomOut,zoomReset,bindMap} from './ui/map/view.js?v=v46';
import {overviewCharts,responseCard} from './ui/pages/overview.js?v=v46';
import {patchMarkup} from './ui/components/rendering.js?v=v46';
import {table,eventTrendWidget,visibleRows,clearSelection,toggleEventGroup} from './ui/pages/events.js?v=v46';
import {infrastructure,drawInfrastructureChart,selectHost,hostViews} from './ui/pages/infrastructure.js?v=v46';
import './ui/components/remediate-bulk.js?v=v46';
import {loadEventResponse,eventResponseCard} from './ui/components/event-response.js?v=v46';
import {renderAudit} from './ui/pages/history.js?v=v46';
import {renderDrills} from './ui/pages/drills.js?v=v46';
import {renderHoneypot,honeypotTimes} from './ui/pages/honeypot.js?v=v46';
import {initAssistant} from './ui/components/assistant.js?v=v46';
import {initPageExports,syncPageExports} from './ui/components/page-exports.js?v=v46';
import {renderVulnerabilities,selectVulnTarget,selectVulnFilter,stepVulnPage,setVulnSize,resetVulnerabilityView,exportVulnerabilities} from './ui/pages/vulnerabilities.js?v=v46';
function render({loadPanels=false}={}){
 const pending=[];

 const rows=selectEvents();const [title,en]=titles[state.view];$('#page-title').innerHTML=`${title} <span>${en}</span>`;document.title=`AWS Security Operations · ${title}`;
 document.body.classList.toggle('view-events',state.view==='events');
 $$('nav [data-view]').forEach(b=>{b.classList.toggle('active',b.dataset.view===state.view);b.setAttribute('aria-current',b.dataset.view===state.view?'page':'false');});
 $('#map-section').hidden=state.view!=='overview';
 syncPageExports();
 if(state.view!=='honeypot')ui.operationBusy=false;   // 허니팟 변경 양식을 열어 둔 채 다른 화면으로 가도 자동 새로고침이 막히지 않게
 // 취약점은 현재 상태라 기간을 쓰지 않는다 — 기간 막대를 숨긴다(v20.5).
 $('.timeline').hidden=state.view==='vulnerabilities'||state.view==='drills';
 $('.filters').hidden=state.view==='drills'||state.view==='honeypot';
 $('#severity').hidden=['vulnerabilities','events'].includes(state.view);
 $('#status').hidden=state.view==='vulnerabilities';
 const end=rangeEnd();
 renderTrack(end);
 $$('[data-hours]').forEach(b=>{b.classList.toggle('active',+b.dataset.hours===state.hours);b.setAttribute('aria-pressed',String(+b.dataset.hours===state.hours));});
 syncTimeRange();
 if(state.view==='overview'){renderContent(overviewCharts()+eventTrendWidget(rows));mapRender(rows);
   if(loadPanels)pending.push(loadEventResponse().then(()=>{const box=$('#overview-response-box');if(box)patchMarkup(box,responseCard());}));}
  else if(state.view==='infrastructure'){
   renderContent(infrastructure());
   drawInfrastructureChart();
  }else if(state.view==='vulnerabilities'){
   renderContent(`<div id="vulns" data-async-panel><p class="panel-loading">불러오는 중…</p></div>`);
   if(loadPanels)pending.push(renderVulnerabilities());
 }else if(state.view==='responses'){
  // 탐지 목록이 아니라 조치 기록을 보여준다(v20). 설명 문구는 패널 안에 둔다(v23).
  renderContent(eventResponseCard()+`<section class="panel full-panel">${header('조치 이력','선택 기간에 마지막으로 발생한 기록')}<div id="audit-log" data-async-panel><p class="panel-loading">불러오는 중…</p></div></section>`);
  if(loadPanels)pending.push(loadEventResponse());   // 대응 현황 카드: 기간 막대와 조치 이력 카드 사이
  if(loadPanels)pending.push(renderAudit().then(()=>renderTrack()));   // 1주일 이력이 오면 트랙을 이력 수로 다시 그린다
 }else if(state.view==='drills'){
  renderContent(`<div id="drills" data-async-panel><p class="panel-loading">불러오는 중…</p></div>`);
  if(loadPanels)pending.push(renderDrills());
 }else if(state.view==='honeypot'){
  // 허니팟(v25): 기간은 기간 버튼을 따르고, 데이터는 허니팟 API 로만 읽는다(공용 events·summary 로드를 기다리지 않는다).
  renderContent(`<div id="honeypot" data-async-panel><p class="panel-loading">불러오는 중…</p></div>`);
  if(loadPanels)pending.push(renderHoneypot().then(()=>renderTrack()));
 }else {
  const visible=visibleRows();
  const head=state.view==='events'?'':`<div class="view-intro"><span>실행 결과와 재검증 결과를 구분하여 확인합니다.</span><span class="view-summary">전체 <strong>${visible.length}건</strong> 미해결 <strong>${visible.filter(e=>e.status!=='해결').length}건</strong></span></div>`;
  const after=state.view==='responses'
    ?`<section class="panel full-panel">${header('조치 이력','HISTORY')}<div id="audit-log" data-async-panel><p class="panel-loading">불러오는 중…</p></div></section>`:'';
  renderContent(head+table(visible,true)+after);
  if(state.view==='events'&&loadPanels)pending.push(loadEventResponse());
  if(state.view==='responses'&&loadPanels)pending.push(renderAudit().then(()=>renderTrack()));
 }
 renderNotifications();
 $('#footer-asof').textContent=`기준 데이터 ${format(summary.asOf)} KST`;
 cleanCharts();
 syncUrl();
 return Promise.all(pending);
}
// 상단 계정 표시는 계정 이름만 쓴다(역할 문구 없음). 권한은 서버가 강제한다.
function rangeEnd(){return summary.queryTo||Date.now();}
// 기간 트랙(v20.5): 지금 → 15분·1시간·1일·1주일 누적 곡선. 지점 = 기간 버튼. 화면마다 세는 대상이 다르다.
//  통합 관제·보안 이벤트 = 탐지 / 인프라 = 임계 초과 구간(끝 시각 기준 → 기간과 겹치는 구간, 화면 표와 같은 수) / 조치 이력 = 이력(마지막 발생 시각)
const historyAt=row=>Date.parse(row.lastSeenAt||row.createdAt);   // 서버 조치 이력 기간 기준과 같다
function trackSource(){
 if(state.view==='infrastructure')return {noun:'임계 초과',unit:'구간',times:selectors.metricWeek()?hostViews(selectors.metricWeek()).flatMap(h=>h.breaches.map(b=>b.to)):null};
 if(state.view==='honeypot')return {noun:'미끼 세션',unit:'개',times:honeypotTimes()};
 if(state.view==='responses'){const week=selectors.historyWeek();return {noun:'조치 이력',unit:'건',times:week?week.map(historyAt):null};}
 return {noun:'탐지',unit:'건',times:(selectors.week()||selectEvents()).map(e=>e.at)};
}
function renderTrack(end=rangeEnd()){
 const span=state.hours*3600000,{noun,unit,times}=trackSource(),from=end-span;
 const count=times==null?null:times.filter(t=>t!=null&&t>=from&&t<end).length;
 $('#time-label').innerHTML=`${format(from)} — ${format(end)} KST<br>최근 ${periodStops[periodIndex()].label} · ${noun} <strong>${count??'…'}</strong>${unit}`;
 $('#period-track').innerHTML=periodTrackMarkup(times,state.hours,end,{noun,unit});
}
// 기간은 기간 버튼(15분·1시간·1일·1주일)으로만 고른다. 되감기는 없다 — 항상 지금 기준(v20.5).
const periodIndex=()=>Math.max(0,periodStops.findIndex(stop=>stop.hours===state.hours));
function syncTimeRange(){if(state.endOffset)setFilters({endOffset:0});}
function applyModeLabels(){
 // v42: 상단 우측에 AWS 연동 상태를 항상 보인다(연동 중 · 미연동). 아직 상태를 받지 못했으면 '확인 중'으로 두고 연동됨으로 단정하지 않는다.
 const mode=$('#data-mode'),aws=$('#aws-state'),dataOk=!!config().dataSourceConnected,known=summary.health!=null,awsOk=!!summary.health?.aws_connected;
 mode.textContent=dataOk?'':'데이터 소스 미연결';mode.hidden=dataOk;
 const state=!known?'unknown':awsOk?'on':'off';
 aws.hidden=false;aws.dataset.state=state;
 aws.textContent={unknown:'AWS 확인 중',on:'AWS 연동 중',off:'AWS 미연동'}[state];
}
function setAuto(on){
 const button=$('#auto-refresh');
 button.textContent=on?'자동 새로고침 30초':'자동 새로고침 꺼짐';
 button.setAttribute('aria-pressed',String(on));
 button.classList.toggle('active',on);
 // 타이머는 Store 가 하나만 관리한다(탭이 숨으면 멈춤). 화면은 상세 창·작업 중·불러오는 중일 때 건너뛰라고만 알린다.
 storeApi.setAutoRefresh(on,{refresh:()=>refresh(),canRun:()=>!$('#event-dialog').open&&!$('#report-dialog').open&&!ui.operationBusy&&!$('#content').hasAttribute('aria-busy')});
}
function navigateView(view){
 if(!titles[view]||state.view===view)return;
 cancelCamera();
 notifications.close();clearSelection();
 if(ui.activeId)closeDialog(true);
 setFilters({view,resource:'',page:1});
 syncPageExports();   // 데이터가 오기 전에도 이 화면에 맞는 버튼만 보이게
 window.scrollTo({top:0,behavior:'auto'});
 refresh({push:true});
}
function syncControls(){
 syncPageExports();
 $('#region').value=state.region;
 ['severity','status','source','search'].forEach(key=>{const el=$('#'+key);if(el)el.value=state[key];});
 updateSelectedCountry(state.region);
}
// v42: 취약점은 수천 건이라 처음 열 때 가장 오래 걸린다. 첫 화면을 다 그린 뒤 한 번만 뒤에서 미리 받아 두면 탭을 열 때 캐시를 쓴다.
// 실패해도 조용히 넘어간다(탭을 열면 그때 다시 받고 오류를 보인다). 첫 화면 요청과 겹치지 않게 잠시 뒤에 시작한다.
let vulnWarmed=false;
function warmVulnerabilities(){
 if(vulnWarmed||state.view==='vulnerabilities')return;
 vulnWarmed=true;
 setTimeout(()=>{Promise.resolve(storeApi.vulnerabilities({})).catch(()=>{vulnWarmed=false;});},1500);
}
async function refresh(options={}){
 clearTimeout(searchTimer);
 syncTimeRange();
 syncUrl(options.push===true);
 const serial=++ui.refreshSerial,scope=panelScope(),box=$('#load-state'),content=$('#content');
 const endActivity=activity.begin();
 box.hidden=true;box.className='load-state';
 $('#refresh').disabled=true;content.setAttribute('aria-busy','true');
 $$('[data-async-panel]').forEach(panel=>panel.removeAttribute('aria-busy'));
 try{
  // 보안 시나리오(1차)는 실데이터 공급자가 필요 없는 카탈로그다. 공용 데이터 로드(events·summary)가
  // 미연결(503)로 실패해도 화면이 막히지 않도록 세션 확인 후 바로 렌더한다.
  if(state.view==='drills'||state.view==='honeypot'){
   await api.init();
   if(serial!==ui.refreshSerial||scope!==panelScope())return;
   await api.refreshHealth().catch(()=>{});   // 실패해도 화면은 계속 그린다(연동 표시는 '확인 중')
   await render({loadPanels:true});
   if(serial!==ui.refreshSerial)return;
   box.hidden=true;content.removeAttribute('data-stale');
   $('#session-user').textContent=config().user.name;
   applyModeLabels();
   $('#worker-state').textContent=state.view==='honeypot'?'허니팟 · 조회와 차단 IP 관리':'';
   $('#updated').textContent=state.view==='honeypot'?`갱신 ${format(Date.now(),true)} KST`:'카탈로그 조회';
   return;
  }
  const [loaded]=await Promise.all([api.load(),isMapReady()?Promise.resolve():loadMap()]);
  if(serial!==ui.refreshSerial||scope!==panelScope()||loaded===false)return;
  $('#region').value=state.region;
  await render({loadPanels:true});
  if(serial!==ui.refreshSerial)return;
  box.hidden=true;content.removeAttribute('data-stale');
  $('#updated').textContent=`갱신 ${format(summary.collectedAt,true)} KST`;
  $('#session-user').textContent=config().user.name;
  applyModeLabels();
  warmVulnerabilities();
  // v23: '조치 실행 비활성 · 조회 전용' 고정 문구는 뺐다(대시보드는 조회 전용이고 자동 조치는 SOAR 가 한다). 경고만 보인다.
  $('#worker-state').textContent=summary.warnings?.length?'⚠ '+summary.warnings.join(' · '):'';
 }catch(e){
  if(serial!==ui.refreshSerial||e.name==='AbortError')return;
  applyModeLabels();
  if(config().user)$('#session-user').textContent=config().user.name;
  content.setAttribute('data-stale','true');box.hidden=false;box.classList.add('error');
  box.innerHTML=`${esc(e.message)}${content.hasChildNodes()?' · 이전 데이터를 표시하고 있습니다.':''} <button id="retry">다시 시도</button>`;
 }finally{
  endActivity();
  if(serial===ui.refreshSerial){$('#refresh').disabled=false;content.removeAttribute('aria-busy');}
 }
}
$('#region').innerHTML='<option value="all">전체 리전</option>'+regions.map(r=>`<option value="${r.id}">${r.name}${r.id==='global'?'':` · ${r.id}`}</option>`).join('');$('#region').value=state.region;
let searchTimer;
 $('#status').insertAdjacentHTML('beforeend',statuses.map(s=>`<option>${s}</option>`).join(''));$('#source').insertAdjacentHTML('beforeend',sources.map(s=>`<option>${s}</option>`).join(''));
['severity','status','source'].forEach(key=>$(`#${key}`).addEventListener('change',e=>{setFilters({[key]:e.target.value,page:1});refresh();}));
$('#region').addEventListener('change',e=>chooseRegion(e.target.value));
$('#search').addEventListener('input',e=>{setFilters({search:e.target.value,page:1});clearTimeout(searchTimer);searchTimer=setTimeout(refresh,220);});
$('#event-dialog').addEventListener('cancel',e=>{e.preventDefault();closeDialog();});
$('#event-dialog').addEventListener('close',()=>{
 // closeDialog owns cleanup synchronously; a queued close event can belong to
 // an older dialog while browser history is already opening the next event.
 if($('#event-dialog').open||ui.activeId)return;
 const target=ui.lastTrigger?.isConnected&&!ui.lastTrigger.closest('[hidden]')?ui.lastTrigger:$('#page-title');
 if(!target.hasAttribute('tabindex')&&target.tagName==='H1')target.tabIndex=-1;
 target.focus();
});
$('#event-dialog').addEventListener('click',e=>{if(e.target===$('#event-dialog')){const r=e.target.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)closeDialog();}});
document.addEventListener('keydown',e=>{const attack=e.target.closest('.attack-connection');if(attack&&['Enter',' '].includes(e.key)){e.preventDefault();eventDialog(attack.dataset.event);return;}const marker=e.target.closest('.marker');if(marker&&['Enter',' '].includes(e.key)){e.preventDefault();const id=marker.dataset.region;chooseRegion(id);$(`#markers [data-region="${id}"]`)?.focus();}});
document.addEventListener('click',e=>{
 const view=e.target.closest('button[data-view]');if(view){navigateView(view.dataset.view);return;}
 const region=e.target.closest('[data-region]');if(region){chooseRegion(region.dataset.region);return;}
 const hostCard=e.target.closest('[data-host]');if(hostCard){if(!selectHost(hostCard.dataset.host))return;render();return;}
 const vt=e.target.closest('[data-vuln-target]');if(vt){selectVulnTarget(vt.dataset.vulnTarget);return;}
 const vf=e.target.closest('[data-vuln-filter]');if(vf){selectVulnFilter(vf.dataset.vulnFilter);return;}
 const eventSeverity=e.target.closest('[data-event-severity]');if(eventSeverity){const value=eventSeverity.dataset.eventSeverity;setFilters({severity:state.severity.toUpperCase()===value.toUpperCase()?'':value,page:1});syncControls();refresh();return;}
 const vp=e.target.closest('[data-vuln-page]');if(vp){stepVulnPage(vp,vp.dataset.vulnPage);return;}
 const notify=e.target.closest('[data-notify]');if(notify){applyNotification(notify.dataset.notify);return;}
 const copy=e.target.closest('[data-copy]');
 if(copy){const text=copy.dataset.copy,done=()=>{copy.textContent='복사됨';copy.classList.add('copied');setTimeout(()=>{copy.textContent='복사';copy.classList.remove('copied');},1500);};
  const fallback=()=>{const area=document.createElement('textarea');area.value=text;area.setAttribute('readonly','');area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();try{document.execCommand('copy');done();}catch{copy.textContent='복사 실패';}area.remove();};
  if(navigator.clipboard?.writeText)navigator.clipboard.writeText(text).then(done,fallback);else fallback();return;}
 const event=e.target.closest('[data-event]');if(event){eventDialog(event.dataset.event);return;}
 const action=e.target.closest('[data-action]');if(action){dialogAction(action.dataset.action);return;}
 const hours=e.target.closest('[data-hours]');if(hours){if(state.hours===+hours.dataset.hours)return;setFilters({hours:+hours.dataset.hours,page:1});refresh();return;}
 const id=e.target.closest('button')?.id;
 if(id==='refresh'||id==='retry'){storeApi.invalidateVulnerabilities();refresh();}
 if(id==='close-region')closeRegionPanel();
 if(id==='open-region')openRegionPanel();
 if(id==='zoom-in')zoomIn();
 if(id==='zoom-out')zoomOut();
 if(id==='zoom-reset')zoomReset();
 if(id==='clear-filters'){setFilters({resource:'',severity:'',status:'',source:'',search:'',endOffset:0,hours:24,page:1});resetVulnerabilityView({clearFilter:true});clearSelection();syncControls();refresh();toast('대상·검색·위험도·상태·소스·시간 필터를 초기화했습니다.');}
 if(id==='auto-refresh')setAuto(!state.auto);
 if(id==='export')api.exportEvents().then(({items})=>downloadCsv('events.csv',eventCsv(items))).catch(e=>toast(e.message));
 if(id==='export-vulns')exportVulnerabilities();
 if(id==='logout'){setAuto(false);api.logout().catch(e=>toast(e.message));}
 const eventGroup=e.target.closest('[data-event-group]');if(eventGroup){toggleEventGroup(eventGroup.dataset.eventGroup);render();return;}
 const groupRow=e.target.closest('tr.event-group-row');if(groupRow&&!e.target.closest('a,button,select,input,label')){toggleEventGroup(groupRow.dataset.key.replace(/^grp-/,''));render();return;}
 const pager=e.target.closest('[data-page]');if(pager){setFilters({page:state.page+(pager.dataset.page==='next'?1:-1)});resetTableScroll(pager);render();}

});
window.addEventListener('popstate',async()=>{
 const wanted=applyUrl();
 syncControls();
 if(ui.activeId!==wanted&&$('#event-dialog').open)closeDialog(true);
 const prior=ui.activeId;ui.activeId=wanted||null;
 await refresh();
 if(wanted&&ui.activeId===wanted&&(!$('#event-dialog').open||prior!==wanted))eventDialog(wanted);
});
bindMap();
document.addEventListener('change',e=>{
 if(e.target.id==='host'){selectHost(e.target.value);render();return;}
 if(e.target.id==='vuln-size'){setVulnSize(e.target,+e.target.value);return;}
});
document.addEventListener('keydown',e=>{
 if(e.defaultPrevented||e.ctrlKey||e.metaKey||e.altKey||e.isComposing||$('#event-dialog').open||$('#report-dialog').open||e.target.closest('input,select,textarea,[contenteditable="true"]'))return;
 if(e.key==='r'&&!e.metaKey&&!e.ctrlKey){e.preventDefault();storeApi.invalidateVulnerabilities();refresh();}
 if(e.key==='/'){e.preventDefault();$('#search').focus();}
 const index='1234567'.indexOf(e.key);
 if(e.key.length===1&&index>=0){const button=$$('nav [data-view]')[index];if(button){e.preventDefault();navigateView(button.dataset.view);}}
});
setAuto(false);
updateCamera();
// 주소에 담긴 상태로 시작한다. 새로고침·링크 공유 복구 지점.
const bootEvent=applyUrl();ui.activeId=bootEvent||null;
syncControls();
refresh().then(()=>{if(bootEvent&&ui.activeId===bootEvent)eventDialog(bootEvent);});
// 화면 모듈이 부르는 render·refresh 를 연결한다(순환 import 방지).
hooks.render=options=>render(options);hooks.refresh=options=>refresh(options);
// 대시보드 도우미(v27): 조회 전용 채팅. 처음 열 때만 상태를 조회한다(자동 호출·비용 없음).
initAssistant();
// 화면 우측 상단 [로그 저장]·[AI 요약 보고서](v28). 상태 조회만 하고 모델은 버튼을 눌렀을 때만 부른다.
initPageExports();
