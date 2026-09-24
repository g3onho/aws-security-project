// 상단 상태 바로가기(승인 대기·재검증·임계치). 발송 알림 기록이 아니라 현재 필터 기준 관측 건수.
import {$,state,setFilters,notifications,hooks} from '../context.js?v=ui-1';
import {esc} from './format.js?v=ui-1';
import {patchMarkup} from './rendering.js?v=ui-1';
import {clearSelection} from '../pages/events.js?v=ui-1';
function notificationItems(rows){
 const groups=[
  {key:'승인 대기',filter:e=>e.status==='승인 대기',view:'events',status:'승인 대기'},
  {key:'재검증 실패',filter:e=>e.status==='재검증 실패',view:'responses',status:'재검증 실패'},
  {key:'재검증 대기',filter:e=>e.status==='재검증 대기',view:'responses',status:'재검증 대기'},
  {key:'임계치 경보 (CloudWatch)',filter:e=>e.source==='CloudWatch'&&e.status!=='해결',view:'infrastructure',status:''},
 ].map(g=>({...g,count:rows.filter(g.filter).length}));
 return groups;
}
export function renderNotifications(rows){
 const groups=notificationItems(rows);
 const total=rows.filter(event=>groups.some(group=>group.filter(event))).length;
 $('#notification-count').hidden=!total;
 $('#notification-count').textContent=total>99?'99+':String(total||'');
 $('#notifications').setAttribute('aria-label',`상태 바로가기 · ${total}건`);
 patchMarkup($('#notification-panel'),`<h3>관측 상태 ${total}건</h3>${groups.map(g=>`<button class="notification-row" data-notify="${esc(g.key)}" ${g.count?'':'disabled'}><span>${esc(g.key)}</span><b>${g.count}</b></button>`).join('')}<small>현재 리전·기간 필터 기준이며 발송 알림 기록은 아닙니다.</small>`);
}
export function applyNotification(key){
 notifications.close();
 const map={'승인 대기':{view:'events',status:'승인 대기'},'재검증 실패':{view:'responses',status:'재검증 실패'},
            '재검증 대기':{view:'responses',status:'재검증 대기'},'임계치 경보 (CloudWatch)':{view:'infrastructure',status:'',source:'CloudWatch'}};
 const target=map[key];if(!target)return;
 setFilters({view:target.view,status:target.status,source:target.source||'',resource:''});clearSelection();
 $('#status').value=state.status;$('#source').value=state.source;
 setFilters({page:1});hooks.refresh({push:true});
}
