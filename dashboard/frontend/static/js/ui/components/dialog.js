// 이벤트 상세 창. 열린 이벤트 ID 는 ui.activeId(주소창 동기화와 공유).
import {$,api,notifications,ui} from '../context.js?v=ui-1';
import {esc,format,milliseconds} from './format.js?v=ui-1';
import {badge} from './badges.js?v=ui-1';
import {patchMarkup} from './rendering.js?v=ui-1';
import {syncUrl} from '../router.js?v=ui-1';
let detailSerial=0;
export async function eventDialog(id,ask=false){
 notifications.close();
 const serial=++detailSerial;ui.activeId=id;ui.approval=ask;syncUrl(true);
 if(!$('#event-dialog').open)ui.lastTrigger=document.activeElement;
 $('#dialog-content').innerHTML='<div class="dialog-header"><h2 id="dialog-title">이벤트 상세</h2><button data-action="close" aria-label="상세 닫기">×</button></div><div class="dialog-body" role="status">상세 정보를 불러오는 중…</div>';
 if(!$('#event-dialog').open)$('#event-dialog').showModal();
 try{const e=await api.detail(id);if(!currentDetail(id,serial))return;drawDetail(e);}
 catch(error){if(currentDetail(id,serial)){$('#dialog-content').innerHTML=`<div class="dialog-body"><h2 id="dialog-title">이벤트 상세</h2><p>${esc(error.message)}</p><button data-action="retry-detail">재시도</button><button data-action="close">닫기</button></div>`;}}
}
function currentDetail(id,serial){return serial===detailSerial&&ui.activeId===id&&$('#event-dialog').open;}
export function drawDetail(e){
 const measure=value=>value?.value==null?'측정값 없음':esc(value.value)+(value.unit?' '+esc(value.unit):'');
 patchMarkup($('#dialog-content'),`<div class="dialog-header"><div><div class="eyebrow">${esc(e.id)} / ${esc(e.scenario||'분류 없음')}</div><h2 id="dialog-title">${esc(e.title)}</h2></div><button class="dialog-close" data-action="close" aria-label="상세 닫기">×</button></div>
 <div class="dialog-body"><dl class="detail-meta"><div><dt>위험도</dt><dd>${badge(e)}</dd></div><div><dt>탐지 소스</dt><dd>${esc(e.source)}</dd></div><div><dt>대상 자원</dt><dd>${esc(e.resource)}</dd></div><div><dt>상태</dt><dd>${esc(e.status)}</dd></div><div><dt>발생 시각</dt><dd>${format(e.at)} KST</dd></div><div><dt>계정</dt><dd>${esc(e.accountId||'제공되지 않음')}</dd></div></dl>
 <section class="detail-section"><h3>조치 정보</h3><p>플레이북: ${esc(e.playbookId||'제공되지 않음')} · 버전 ${esc(e.playbookVersion||'—')}</p><p>기준: ${esc(e.criterion||'제공되지 않음')} · ${esc(e.criterionVersion||'—')}</p></section>
 <section class="detail-section"><h3>Before / After</h3><div class="comparison"><div><label>BEFORE</label><strong>${measure(e.beforeState)}</strong><small>${format(milliseconds(e.beforeState?.observedAt))}</small></div><div><label>AFTER</label><strong>${measure(e.afterState)}</strong><small>${format(milliseconds(e.afterState?.observedAt))}</small></div></div></section>
 <p class="muted">탐지 원문·공격 재현 절차·12항목 증적은 표준 이벤트 API에서 제공되지 않습니다.</p></div><div class="dialog-actions"><span>읽기 전용</span><button class="cancel-button" data-action="close">닫기</button></div>`);
}

export function closeDialog(fromHistory=false){
 detailSerial++;ui.activeId=null;ui.approval=false;
 if(!fromHistory)syncUrl();
 if($('#event-dialog').open)$('#event-dialog').close();
}
export async function dialogAction(action){if(action==='close')closeDialog();}
