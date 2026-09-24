// 침해사례: 관측 이벤트를 시나리오별로 묶는다.
import {$,selectEvents} from '../context.js?v=ui-1';
import {esc} from '../components/format.js?v=ui-1';
import {empty} from '../components/panel.js?v=ui-1';
import {patchMarkup} from '../components/rendering.js?v=ui-1';
// ── 침해사례 탭: 관측 이벤트의 시나리오별 묶음 ────────────

export function renderIncidents(){
 const box=$('#incidents');if(!box)return;
 const events=selectEvents(),groups=new Map();for(const event of events){const key=event.scenario||'분류 없음';groups.set(key,[...(groups.get(key)||[]),event]);}
 patchMarkup(box,`<div class="view-intro"><span>표준 이벤트 API에서 관측된 시나리오</span><span class="view-summary">${groups.size}개 분류 · ${events.length}건</span></div>${[...groups].map(([name,items])=>`<section class="panel"><h2>${esc(name)}</h2><p>관측 이벤트 ${items.length}건</p>${items.map(e=>`<p><button class="event-link" data-event="${esc(e.id)}">${esc(e.title)} · ${esc(e.resource)}</button></p>`).join('')}</section>`).join('')||empty('조회 기간에 관측된 침해 이벤트가 없습니다.')}<div class="context-note">공격 재현 절차·플레이북 배선·단계별 완료 정보는 표준 API에서 제공되지 않습니다.</div>`);
}
