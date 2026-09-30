// 이벤트 상세 창. 열린 이벤트 ID 는 ui.activeId(주소창 동기화와 공유).
// v23: 무엇이 문제인지(팀 설명) → 왜 위험한지 → 어떻게 고치는지 → AWS 원문 → 자동 조치 여부 → 조치 기록 순서.
import {$,api,notifications,ui} from '../context.js?v=v45';
import {esc,format,milliseconds,withCode} from './format.js?v=v45';
import {badge} from './badges.js?v=v45';
import {patchMarkup} from './rendering.js?v=v45';
import {syncUrl} from '../router.js?v=v45';
import {autoChip} from './remediation.js?v=v45';
import {flowBlock,eventStages,FLOW_NOTE_EVENT} from '../pages/flow-map.js?v=v45';
import {remediationSection,loadRemediation,stopRemediation} from './remediate.js?v=v45';
let detailSerial=0;
let historyCache={id:null,data:null};
function flowSection(e){
 const history=historyCache.id===e.id?historyCache.data:null;
 return `<section class="detail-section"><h3>경로 지도 <small class="source-note">이 탐지가 아키텍처 어디까지 갔는지</small></h3><div id="event-flow" class="event-flow" data-key="event-flow">${flowBlock(eventStages(e,history),FLOW_NOTE_EVENT)}</div></section>`;
}
export async function eventDialog(id,ask=false){
 notifications.close();
 if(historyCache.id!==id)historyCache={id:null,data:null};
 const serial=++detailSerial;ui.activeId=id;ui.approval=ask;syncUrl(true);
 if(!$('#event-dialog').open)ui.lastTrigger=document.activeElement;
 $('#dialog-content').innerHTML='<div class="dialog-header"><h2 id="dialog-title">이벤트 상세</h2><button data-action="close" aria-label="상세 닫기">×</button></div><div class="dialog-body" role="status">상세 정보를 불러오는 중…</div>';
 if(!$('#event-dialog').open)$('#event-dialog').showModal();
 try{const e=await api.detail(id);if(!currentDetail(id,serial))return;drawDetail(e);loadEventHistory(e,serial);loadRemediation(id,()=>currentDetail(id,serial));}
 catch(error){if(currentDetail(id,serial)){$('#dialog-content').innerHTML=`<div class="dialog-body"><h2 id="dialog-title">이벤트 상세</h2><p>${esc(error.message)}</p><button data-action="retry-detail">재시도</button><button data-action="close">닫기</button></div>`;}}
}
function currentDetail(id,serial){return serial===detailSerial&&ui.activeId===id&&$('#event-dialog').open;}
function guidanceSection(g){
 if(!g)return `<section class="detail-section"><h3>무엇이 문제인가</h3><p class="muted">팀 설명표에 없는 탐지입니다. 아래 AWS 원문을 확인하세요.</p></section>`;
 return `<section class="detail-section guidance"><h3>무엇이 문제인가 <small class="source-note">팀 설명</small>${g.scenario?` <span class="scenario-tag">${esc(g.scenario)}</span>`:''}</h3>
  <p><strong>${esc(g.title)}</strong> — ${withCode(g.problem)}</p>
  <h3>왜 위험한가</h3><p>${withCode(g.risk)}</p>
  <h3>어떻게 고치나</h3><ul class="fix-list">${(g.fix||[]).map(f=>`<li>${withCode(f)}</li>`).join('')}</ul>
  ${g.where?`<p class="where"><span>고치는 곳</span>${withCode(g.where)}</p>`:''}${g.note?`<p class="muted-mini">${esc(g.note)}</p>`:''}</section>`;
}
function awsSection(e){
 const r=e.remediation;
 if(!e.description&&!r)return '';
 return `<section class="detail-section aws-original"><h3>AWS 원문 <small class="source-note">${esc(e.source||'')}${e.controlId?` · ${esc(e.controlId)}`:''}${e.findingType?` · ${esc(e.findingType)}`:''}</small></h3>
  ${e.description?`<p>${esc(e.description)}</p>`:''}${r?.text?`<p class="muted-mini">조치 안내: ${withCode(r.text)}</p>`:''}
  ${r?.url?`<p><a class="doc-link" href="${esc(r.url)}" target="_blank" rel="noreferrer">AWS 조치 문서 열기 ↗</a></p>`:''}</section>`;
}
function autoSection(a,wide=false){
 if(!a)return `<section class="detail-section${wide?' wide':''}"><h3>자동 조치</h3><p class="muted">자동 조치 판정 정보가 없습니다.</p></section>`;
 return `<section class="detail-section${wide?' wide':''}"><h3>자동 조치 ${autoChip(a)}</h3><p>${esc(a.reason)}</p>
  ${a.playbookId?`<p class="muted-mini">플레이북 ${esc(a.playbookId)}${a.action?` · ${esc(a.action)}`:''}</p>`:''}${a.condition?`<p class="muted-mini">조건: ${esc(a.condition)}</p>`:''}
  <p class="muted-mini">${esc(a.basis||'')}</p></section>`;
}
export function drawDetail(e){
 const related=(e.relatedCves||[]).length?`<section class="detail-section related"><h3>같은 자원의 CVE (상관분석)</h3><p>${e.relatedCves.map(c=>`<span class="scenario-tag">${esc(c)}</span>`).join(' ')}</p></section>`:'';
 patchMarkup($('#dialog-content'),`<div class="dialog-header"><div><div class="eyebrow">${esc(e.controlId||e.id)} / ${esc(e.scenario||'분류 없음')}</div><h2 id="dialog-title">${esc(e.guidance?.title||e.title)}</h2>${e.guidance?`<p class="dialog-subtitle">${esc(e.title)}</p>`:''}</div><button class="dialog-close" data-action="close" aria-label="상세 닫기">×</button></div>
 <div class="dialog-body"><dl class="detail-meta"><div><dt>위험도</dt><dd>${badge(e)}</dd></div><div><dt>탐지 소스</dt><dd>${esc(e.source)}</dd></div><div><dt>대상 자원</dt><dd>${esc(e.resource)}</dd></div><div><dt>상태</dt><dd>${esc(e.status)}</dd></div><div><dt>발생 시각</dt><dd>${format(e.at)} KST</dd></div><div><dt>계정</dt><dd>${esc(e.accountId||'제공되지 않음')}</dd></div></dl>
 ${flowSection(e)}${guidanceSection(e.guidance)}${awsSection(e)}${autoSection(e.autoRemediation,!awsSection(e))}${related}${remediationSection()}
 <p class="muted">팀 설명은 이 프로젝트 기준 해설이고 AWS 원문과 따로 표시합니다. 자동 조치 여부는 현재 설정으로 본 예상이며, 실제로 한 일은 조치 이력 페이지가 기준입니다.</p></div><div class="dialog-actions"><span>탐지 상세 · 조치는 '대시보드 조치' 영역에서 확인 후 실행합니다</span><button class="cancel-button" data-action="close">닫기</button></div>`);
}
// 경로 지도가 쓰는 자동 조치 기록만 읽는다. 조치 이력 자체는 조치 이력 페이지에서 본다.
async function loadEventHistory(e,serial){
 try{const data=await api.eventHistory(e.id);if(!currentDetail(e.id,serial))return;historyCache={id:e.id,data};const flow=$('#event-flow');if(flow)patchMarkup(flow,flowBlock(eventStages(e,data),FLOW_NOTE_EVENT));}
 catch(error){/* 경로 지도는 기록 없이도 그려진다 */}
}

export function closeDialog(fromHistory=false){
 detailSerial++;stopRemediation();ui.activeId=null;ui.approval=false;
 if(!fromHistory)syncUrl();
 if($('#event-dialog').open)$('#event-dialog').close();
}
export async function dialogAction(action){if(action==='close')closeDialog();}
