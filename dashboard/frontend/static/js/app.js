// 대시보드 시작점: 화면 조립(render)·새로고침(refresh)·사용자 입력 연결만 한다.
// 화면별 표시는 ui/pages, 공통 부품은 ui/components, 차트는 ui/charts, 지도는 ui/map, 주소창은 ui/router(설계 2.1).
import {regions,sources,statuses,periodStops} from './ui/constants.js?v=ui-1';
import {periodTrackMarkup} from './ui/components/period-track.js?v=ui-1';
import {$,$$,api,activity,storeApi,state,summary,config,selectors,selectEvents,setFilters,notifications,ui,hooks} from './ui/context.js?v=ui-1';
import {esc,format} from './ui/components/format.js?v=ui-1';
import {header,renderContent,resetTableScroll,panelScope,toast} from './ui/components/panel.js?v=ui-1';
import {cleanCharts} from './ui/charts/charts.js?v=ui-1';
import {eventCsv,downloadCsv} from './ui/components/downloads.js?v=ui-1';
import {eventDialog,closeDialog,dialogAction} from './ui/components/dialog.js?v=ui-1';
import {renderNotifications,applyNotification} from './ui/components/shortcuts.js?v=ui-1';
import {titles,syncUrl,applyUrl} from './ui/router.js?v=ui-1';
import {loadMap,isMapReady,updateSelectedCountry,updateCamera,chooseRegion,mapRender,cancelCamera,closeRegionPanel,openRegionPanel,zoomIn,zoomOut,zoomReset,bindMap} from './ui/map/view.js?v=ui-1';
import {overviewCharts} from './ui/pages/overview.js?v=ui-1';
import {table,visibleRows,clearSelection,toggleEventGroup} from './ui/pages/events.js?v=ui-1';
import {infrastructure,drawInfrastructureChart,selectHost,hostViews} from './ui/pages/infrastructure.js?v=ui-1';
import {renderAudit} from './ui/pages/history.js?v=ui-1';
import {renderDrills} from './ui/pages/drills.js?v=ui-1';
import {renderVulnerabilities,selectVulnTarget,stepVulnPage,setVulnSize,setVulnFixable,resetVulnerabilityView,exportVulnerabilities} from './ui/pages/vulnerabilities.js?v=ui-1';
function render({loadPanels=false}={}){
 const pending=[];

 const rows=selectEvents();const [title,en]=titles[state.view];$('#page-title').innerHTML=`${title} <span>${en}</span>`;document.title=`AWS Security Operations · ${title}`;
 $$('nav [data-view]').forEach(b=>{b.classList.toggle('active',b.dataset.view===state.view);b.setAttribute('aria-current',b.dataset.view===state.view?'page':'false');});
 $('#map-section').hidden=state.view!=='overview';
 // 취약점은 현재 상태라 기간을 쓰지 않는다 — 기간 막대를 숨긴다(v20.5).
 $('.timeline').hidden=state.view==='vulnerabilities'||state.view==='drills';
 $('.filters').hidden=state.view==='drills';
 const span=state.hours*3600000,end=clockNow()-state.endOffset*3600000;
 renderTrack(end);
 $$('[data-hours]').forEach(b=>{b.classList.toggle('active',+b.dataset.hours===state.hours);b.setAttribute('aria-pressed',String(+b.dataset.hours===state.hours));});
 syncTimeRange();
 if(state.view==='overview'){renderContent(overviewCharts(rows)+table(rows));mapRender(rows);}
  else if(state.view==='infrastructure'){
   renderContent(infrastructure());
   drawInfrastructureChart();
  }else if(state.view==='vulnerabilities'){
   renderContent(`<div id="vulns" data-async-panel><p class="panel-loading">불러오는 중…</p></div>`);
   if(loadPanels)pending.push(renderVulnerabilities());
 }else if(state.view==='responses'){
  // 탐지 목록이 아니라 조치 기록을 보여준다(v20).
  renderContent(`<div class="view-intro"><span>자동조치 판정과 수동 조치 기록입니다(선택 기간에 마지막으로 발생한 기록, 최대 30일 보존). '실행 완료'는 재검증 전 상태이며 해결을 뜻하지 않습니다.</span></div><section class="panel full-panel">${header('대응 이력','HISTORY')}<div id="audit-log" data-async-panel><p class="panel-loading">불러오는 중…</p></div></section>`);
  if(loadPanels)pending.push(renderAudit().then(()=>renderTrack()));   // 1주일 이력이 오면 트랙을 이력 수로 다시 그린다
 }else if(state.view==='drills'){
  renderContent(`<div id="drills" data-async-panel><p class="panel-loading">불러오는 중…</p></div>`);
  if(loadPanels)pending.push(renderDrills());
 }else {
  const visible=visibleRows();
  const intro=state.view==='responses'?'실행 결과와 재검증 결과를 구분하여 확인합니다.':'탐지 근거에서 대응과 재검증까지 추적합니다.';
  const head=`<div class="view-intro"><span>${intro}</span><span class="view-summary">전체 <strong>${visible.length}건</strong> 미해결 <strong>${visible.filter(e=>e.status!=='해결').length}건</strong></span></div>`;
   const before='';
  const after=state.view==='responses'
    ?`<section class="panel full-panel">${header('조치 이력','HISTORY')}<div id="audit-log" data-async-panel><p class="panel-loading">불러오는 중…</p></div></section>`:'';
  renderContent(head+before+table(visible,true)+after);
  if(state.view==='responses'&&loadPanels)pending.push(renderAudit().then(()=>renderTrack()));
 }
 renderNotifications(rows);
 $('#footer-asof').textContent=`기준 데이터 ${format(clockNow())} KST`;
 cleanCharts();
 syncUrl();
 return Promise.all(pending);
}
function clockNow(){return summary.asOf||Date.now();}
// 기간 트랙(v20.5): 지금 → 15분·1시간·1일·1주일 누적 곡선. 지점 = 기간 버튼. 화면마다 세는 대상이 다르다.
//  통합 관제·보안 이벤트 = 탐지 / 인프라 = 임계 초과 구간(끝 시각 기준 → 기간과 겹치는 구간, 화면 표와 같은 수) / 대응 이력 = 이력(마지막 발생 시각)
const historyAt=row=>Date.parse(row.lastSeenAt||row.createdAt);   // 서버 대응 이력 기간 기준과 같다
function trackSource(){
 if(state.view==='infrastructure')return {noun:'임계 초과',unit:'구간',times:selectors.metricWeek()?hostViews(selectors.metricWeek()).flatMap(h=>h.breaches.map(b=>b.to)):null};
 if(state.view==='responses'){const week=selectors.historyWeek();return {noun:'대응 이력',unit:'건',times:week?week.map(historyAt):null};}
 return {noun:'탐지',unit:'건',times:(selectors.week()||selectEvents()).map(e=>e.at)};
}
function renderTrack(end=clockNow()-state.endOffset*3600000){
 const span=state.hours*3600000,{noun,unit,times}=trackSource(),from=end-span;
 const count=times==null?null:times.filter(t=>t!=null&&t>=from&&t<=end).length;
 $('#time-label').innerHTML=`${format(from)} — ${format(end)} KST<br>최근 ${periodStops[periodIndex()].label} · ${noun} <strong>${count??'…'}</strong>${unit}`;
 $('#period-track').innerHTML=periodTrackMarkup(times,state.hours,end,{noun,unit});
}
// 기간은 기간 버튼(15분·1시간·1일·1주일)으로만 고른다. 되감기는 없다 — 항상 지금 기준(v20.5).
const periodIndex=()=>Math.max(0,periodStops.findIndex(stop=>stop.hours===state.hours));
function syncTimeRange(){if(state.endOffset)setFilters({endOffset:0});}
function applyModeLabels(){
 $('#data-mode').textContent=config().dataSourceConnected?'실데이터':'데이터 소스 미연결';
 $('#aws-state').textContent=summary.health?.aws_connected?'AWS 연동 정상':'AWS 미연결';
 $('#env-label').textContent='실데이터 전용';
 $('#env-sub').textContent=config().writeEnabled?'조치 활성화':'읽기 전용';
}
function setAuto(on){
 const button=$('#auto-refresh');
 button.textContent=on?'자동 새로고침 30초':'자동 새로고침 꺼짐';
 button.setAttribute('aria-pressed',String(on));
 button.classList.toggle('active',on);
 // 타이머는 Store 가 하나만 관리한다(탭이 숨으면 멈춤). 화면은 상세 창·작업 중·불러오는 중일 때 건너뛰라고만 알린다.
 storeApi.setAutoRefresh(on,{refresh:()=>refresh(),canRun:()=>!$('#event-dialog').open&&!ui.operationBusy&&!$('#content').hasAttribute('aria-busy')});
}
function navigateView(view){
 if(!titles[view]||state.view===view)return;
 cancelCamera();
 notifications.close();clearSelection();
 if(ui.activeId)closeDialog(true);
 setFilters({view,resource:'',page:1});
 window.scrollTo({top:0,behavior:'auto'});
 refresh({push:true});
}
function syncControls(){
 $('#region').value=state.region;
 ['severity','status','source','search'].forEach(key=>{const el=$('#'+key);if(el)el.value=state[key];});
 updateSelectedCountry(state.region);
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
  // 공격·대응 실습(1차)은 실데이터 공급자가 필요 없는 카탈로그다. 공용 데이터 로드(events·summary)가
  // 미연결(503)로 실패해도 화면이 막히지 않도록 세션 확인 후 바로 렌더한다.
  if(state.view==='drills'){
   await api.init();
   if(serial!==ui.refreshSerial||scope!==panelScope())return;
   await render({loadPanels:true});
   if(serial!==ui.refreshSerial)return;
   box.hidden=true;content.removeAttribute('data-stale');
   $('#session-user').textContent=config().user.name+' · '+(config().role==='operator'?'조치 담당':'조회 전용');
   applyModeLabels();
   $('#worker-state').textContent='공격·대응 실습 · 관측·구조(1차)';
   $('#updated').textContent='카탈로그 조회';
   return;
  }
  const [loaded]=await Promise.all([api.load(),isMapReady()?Promise.resolve():loadMap()]);
  if(serial!==ui.refreshSerial||scope!==panelScope()||loaded===false)return;
  $('#region').value=state.region;
  await render({loadPanels:true});
  if(serial!==ui.refreshSerial)return;
  box.hidden=true;content.removeAttribute('data-stale');
  $('#updated').textContent=`갱신 ${format(summary.collectedAt,true)} KST`;
  $('#session-user').textContent=config().user.name+' · '+(config().role==='operator'?'조치 담당':'조회 전용');
  applyModeLabels();
  $('#worker-state').textContent=(summary.health.checks.worker==='ok'?'작업 처리기 정상':'조치 실행 비활성 · 조회 전용')+(summary.warnings?.length?' · ⚠ '+summary.warnings.join(' · '):'');
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
 const view=e.target.closest('[data-view]');if(view){navigateView(view.dataset.view);return;}
 const region=e.target.closest('[data-region]');if(region){chooseRegion(region.dataset.region);return;}
 const hostCard=e.target.closest('[data-host]');if(hostCard){if(!selectHost(hostCard.dataset.host))return;render();return;}
 const vt=e.target.closest('[data-vuln-target]');if(vt){selectVulnTarget(vt.dataset.vulnTarget);return;}
 const vp=e.target.closest('[data-vuln-page]');if(vp){stepVulnPage(vp,vp.dataset.vulnPage);return;}
 const notify=e.target.closest('[data-notify]');if(notify){applyNotification(notify.dataset.notify);return;}
 const event=e.target.closest('[data-event]');if(event){eventDialog(event.dataset.event);return;}
 const action=e.target.closest('[data-action]');if(action){dialogAction(action.dataset.action);return;}
 const hours=e.target.closest('[data-hours]');if(hours){if(state.hours===+hours.dataset.hours)return;setFilters({hours:+hours.dataset.hours,page:1});refresh();return;}
 const id=e.target.closest('button')?.id;
 if(id==='refresh'||id==='retry')refresh();
 if(id==='close-region')closeRegionPanel();
 if(id==='open-region')openRegionPanel();
 if(id==='zoom-in')zoomIn();
 if(id==='zoom-out')zoomOut();
 if(id==='zoom-reset')zoomReset();
 if(id==='clear-filters'){setFilters({resource:'',severity:'',status:'',source:'',search:'',endOffset:0,hours:24,page:1});resetVulnerabilityView({keepFixable:false});clearSelection();syncControls();refresh();toast('대상·검색·위험도·상태·소스·시간 필터를 초기화했습니다.');}
 if(id==='auto-refresh')setAuto(!state.auto);
 if(id==='export')api.exportEvents().then(({items})=>downloadCsv('events.csv',eventCsv(items))).catch(e=>toast(e.message));
 if(id==='export-vulns')exportVulnerabilities();
 if(id==='logout'){setAuto(false);api.logout().catch(e=>toast(e.message));}
 const eventGroup=e.target.closest('[data-event-group]');if(eventGroup){toggleEventGroup(eventGroup.dataset.eventGroup);render();return;}
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
 if(e.target.id==='vuln-fixable'){setVulnFixable(e.target.checked);return;}
});
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
const bootEvent=applyUrl();ui.activeId=bootEvent||null;
syncControls();
refresh().then(()=>{if(bootEvent&&ui.activeId===bootEvent)eventDialog(bootEvent);});
// 화면 모듈이 부르는 render·refresh 를 연결한다(순환 import 방지).
hooks.render=options=>render(options);hooks.refresh=options=>refresh(options);
