// 상단 상태 바로가기(v23): 자동 조치 실패·수동 대응 필요·CloudWatch 경보. 발송 알림 기록이 아니라 현재 필터 기준 관측 건수.
// (예전의 '승인 대기'는 모든 탐지가 들어가 실제 승인 대기와 달랐고, 재검증 항목은 채울 경로가 없어 뺐다.)
import {$,state,setFilters,notifications,hooks,summary} from '../context.js?v=v43';
import {esc} from './format.js?v=v43';
import {patchMarkup} from './rendering.js?v=v43';
import {clearSelection} from '../pages/events.js?v=v43';
const GROUPS=[
 {key:'자동 조치 실패',count:()=>summary.automation?.failed??0,view:'responses'},
 {key:'수동 대응 필요',count:()=>summary.automation?.manual??0,view:'responses'},
 {key:'경보 발생 (CloudWatch)',count:()=>summary.alarms?.alarm??0,view:'infrastructure'},
];
function notificationItems(){return GROUPS.map(g=>({...g,count:g.count()}));}
export function renderNotifications(){
 const groups=notificationItems();
 const total=groups.reduce((sum,g)=>sum+g.count,0);
 $('#notification-count').hidden=!total;
 $('#notification-count').textContent=total>99?'99+':String(total||'');
 $('#notifications').setAttribute('aria-label',`상태 바로가기 · ${total}건`);
 patchMarkup($('#notification-panel'),`<h3>확인할 상태 ${total}건</h3>${groups.map(g=>`<button class="notification-row" data-notify="${esc(g.key)}" ${g.count?'':'disabled'}><span>${esc(g.key)}</span><b>${g.count}</b></button>`).join('')}<small>현재 리전·기간 필터 기준이며 발송 알림 기록은 아닙니다.</small>`);
}
export function applyNotification(key){
 notifications.close();
 const target=GROUPS.find(g=>g.key===key);if(!target)return;
 setFilters({view:target.view,status:'',source:'',resource:''});clearSelection();
 $('#status').value=state.status;$('#source').value=state.source;
 setFilters({page:1});hooks.refresh({push:true});
}
