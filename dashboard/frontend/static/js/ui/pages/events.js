// 보안 이벤트 표: 같은 제목 묶음, 펼치기, 페이지.
import {severityColors} from '../constants.js?v=ui-1';
import {state,setFilters,selectEvents} from '../context.js?v=ui-1';
import {esc,format,shortResource} from '../components/format.js?v=ui-1';
import {badge,statusBadge,sourceTag} from '../components/badges.js?v=ui-1';
import {header,empty} from '../components/panel.js?v=ui-1';
import {autoChip} from '../components/remediation.js?v=ui-1';
// ── 목록 표 ────────────────────────────────────────────────
const selected=new Set();

// 같은 점검이 자원마다 한 줄씩(예: S3 로깅 미설정 × 버킷 3개) 나오지 않게 제목으로 묶는다.
// 묶음 줄을 누르면 자원별 줄이 펼쳐지고, 자원 줄을 누르면 기존 상세 창이 열린다.
const openEventGroups=new Set();
const SEV_RANK=Object.keys(severityColors);
export function eventGroups(rows){
 const groups=new Map();
 for(const e of rows){const key=e.source+'|'+e.title;groups.set(key,[...(groups.get(key)||[]),e]);}
 return [...groups].map(([key,items])=>({key,items,top:[...items].sort((a,b)=>SEV_RANK.indexOf(a.severity)-SEV_RANK.indexOf(b.severity))[0],at:Math.max(...items.map(e=>e.at))}));
}
// 자동 조치 대상(설정 기준 예상)이면 제목 아래에 표시한다 — 목록에서 "SOAR 가 고치는 탐지"를 바로 구분.
function eventRow(e){return `<tr data-key="${esc(e.id)}"><td>${badge(e)}</td><td><button class="event-link" data-event="${esc(e.id)}">${esc(e.title)}<small><span class="scenario-tag">${esc(e.scenario)}</span>${autoChip(e.autoRemediation,{short:true})}<span class="resource-id" title="${esc(e.resource)}">${esc(shortResource(e.resource))}</span></small></button></td><td>${sourceTag(e.source)}</td><td>${format(e.at,state.hours<=24)}</td><td>${statusBadge(e.status)}</td></tr>`;}
function eventGroupRows(g){
 if(g.items.length===1)return eventRow(g.items[0]);
 const e=g.top,open=openEventGroups.has(g.key),statuses=[...new Set(g.items.map(x=>x.status))];
 return `<tr data-key="grp-${esc(g.key)}" class="event-group-row${open?' open':''}"><td>${badge(e)}</td><td><button class="event-link" data-event-group="${esc(g.key)}" aria-expanded="${open}"><span class="group-caret" aria-hidden="true">${open?'▾':'▸'}</span>${esc(e.title)}<small><span class="scenario-tag">${esc(e.scenario)}</span>${autoChip(e.autoRemediation,{short:true})}<span class="group-count">자원 ${g.items.length}개</span>${open?'':`<span class="resource-id">${g.items.slice(0,3).map(x=>esc(shortResource(x.resource))).join(', ')}${g.items.length>3?' 외':''}</span>`}</small></button></td><td>${sourceTag(e.source)}</td><td>${format(g.at,state.hours<=24)}</td><td>${statuses.length===1?statusBadge(statuses[0]):statusBadge('혼합')}</td></tr>`
  +(open?g.items.map(x=>`<tr data-key="sub-${esc(x.id)}" class="event-sub-row"><td>${badge(x)}</td><td><button class="event-link" data-event="${esc(x.id)}"><span class="resource-id" title="${esc(x.resource)}">${esc(shortResource(x.resource))}</span><small>${esc(x.resource)}</small></button></td><td></td><td>${format(x.at,state.hours<=24)}</td><td>${statusBadge(x.status)}</td></tr>`).join(''):'');
}
export function table(rows,full=false){
 const groups=eventGroups(rows),total=rows.length,pages=Math.max(1,Math.ceil(groups.length/15));if(state.page>pages)setFilters({page:pages});
 const page=groups.slice((state.page-1)*15,state.page*15);
 const title=state.view==='responses'?'조치 이력':state.view==='vulnerabilities'?'취약점 점검 결과':'최근 보안 이벤트';
 const tools='<button id="export" class="text-button">↓ CSV 내보내기</button>';
 return `<section class="panel ${full?'full-panel':''}">${header(title,tools)}${page.length?`<div class="table-scroll"><table><caption class="sr-only">현재 필터에 해당하는 ${total}개 이벤트</caption><thead><tr><th>위험도</th><th>이벤트 / 자원</th><th>탐지 소스</th><th>발생 시각 (KST)</th><th>상태</th></tr></thead><tbody>${page.map(eventGroupRows).join('')}</tbody></table></div>`:empty()}<div class="table-footer"><span>총 ${total}건 · 같은 제목 묶음 ${groups.length}줄 · 현재 필터 적용</span><span>${state.view==='overview'?'<button class="text-button" data-view="events">전체 이벤트 보기 →</button>':'이벤트를 누르면 문제·위험·고치는 법과 자동 조치 기록을 볼 수 있습니다.'}</span></div><div class="table-pager"><button data-page="prev" ${state.page<=1?'disabled':''}>← 이전</button><span>${state.page} / ${pages}</span><button data-page="next" ${state.page>=pages?'disabled':''}>다음 →</button></div></section>`;
}
export function visibleRows(){return selectEvents();}
export function clearSelection(){selected.clear();}
export function toggleEventGroup(k){openEventGroups.has(k)?openEventGroups.delete(k):openEventGroups.add(k);}
