// 보안 이벤트의 '수동 대응 N건' 팝업: 수동 대응 대상을 모아 보고, 고른 것을 사유 하나로 한 번에 실행한다.
// '직접 조치' 모드는 대시보드로 조치할 수 없는 항목을 목록으로만 보여 준다(고르기·실행 없음).
// 각 건은 단건 조치와 같은 서버 경로(미리보기 → 실행)를 쓴다. 서버가 건마다 권한·범위·현재 상태를 다시 확인하고,
// 실행 가능 여부는 건마다 서버가 알려 준 값만 따른다. 실행은 접수일 뿐 해결이 아니다(재검증 결과는 조치 이력).
import {$,api} from '../context.js?v=v46';
import {esc,shortResource} from './format.js?v=v46';
import {badge} from './badges.js?v=v46';
import {classify,REASON,autoAttempts} from './event-response.js?v=v46';
import {remediationErrorText,recordTitle,automationState} from './remediation.js?v=v46';
import {format,milliseconds} from './format.js?v=v46';
const bulk={items:[],serial:0,running:false,keys:new Map(),mode:'manual'};
const CONCURRENCY=4;   // 미리보기(읽기) 동시 요청 수. 실행은 한 건씩 순서대로 보낸다.
const newKey=()=>{const bytes=new Uint8Array(16);if(globalThis.crypto?.getRandomValues)globalThis.crypto.getRandomValues(bytes);else bytes.forEach((_,i)=>{bytes[i]=Math.floor(Math.random()*256);});return 'rb-'+[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');};
const RESULT={pending:['대기','muted'],accepted:['실행 접수 · 재검증 대기','run'],already:['이미 기준 충족 · 실행 안 함','ok'],failed:['실패','bad'],running:['보내는 중…','run']};
function planNote(item){
 if(item.result){const [label,tone]=RESULT[item.result.kind];return `<span class="auto-chip ${tone}">${esc(label)}</span>${item.result.text?`<small class="bulk-note bad">${esc(item.result.text)}</small>`:''}`;}
 if(item.loading)return '<small class="bulk-note">현재 상태 확인 중…</small>';
 if(item.error)return `<small class="bulk-note bad">${esc(item.error)}</small>`;
 const p=item.plan;
 if(p.alreadyCompliant)return '<span class="auto-chip ok">현재 기준 충족</span><small class="bulk-note">실행할 필요가 없습니다.</small>';
 if(!p.canExecute)return `<small class="bulk-note bad">${esc(p.blockedReason||'지금은 실행할 수 없습니다.')}</small>`;
 return `<small class="bulk-note">${esc(p.change||'')}</small>`;
}
const runnable=item=>!item.loading&&!item.error&&item.plan?.canExecute&&!item.plan.alreadyCompliant&&(!item.result||item.result.kind==='failed');
function render(){
 const box=$('#bulk-content');if(!box)return;
 if(bulk.mode==='direct'){renderDirect(box);return;}
 if(bulk.mode==='auto'){renderAuto(box);return;}
 const field=$('#bulk-reason'),reason=field?.value||'',focused=document.activeElement===field,at=field?.selectionStart;
 const canWrite=bulk.items.some(i=>i.plan?.canWrite===true);
 // 체크박스를 절대 못 누르는 건(이미 기준 충족 + 정책상 대시보드가 손대면 안 되는 것) 전부
 // '양호' 섹션으로 뺀다(2026-09-30 사용자 요청) — 실제 사유(태그 없음 등)는 접었을 때 안 보이지만
 // 펼치면 그대로 남아 있어, 위험이 사라진 게 아니라 '대시보드로는 조치 안 함'이라는 걸 알 수 있다.
 // 대시보드로는 조치하지 않는 '조치 제외'는 수동 대응이 아니므로 이 목록에서 뺀다(2026-10-02 사용자 피드백). 기준을 이미 충족한 '양호'만 접어 둔다.
 const settled=i=>i.plan&&!i.loading&&!i.error&&!runnable(i)&&!i.result;
 const compliant=bulk.items.filter(i=>settled(i)&&i.plan.alreadyCompliant);
 const excludedCount=bulk.items.filter(i=>settled(i)&&!i.plan.alreadyCompliant).length;
 const pending=bulk.items.filter(i=>!settled(i));
 const selected=pending.filter(i=>i.checked&&runnable(i)).length,loading=pending.some(i=>i.loading);
 const rows=pending.map(i=>`<li class="bulk-item${runnable(i)?'':' off'}" data-key="bulk-${esc(i.e.id)}"><label><input type="checkbox" data-bulk-check="${esc(i.e.id)}"${i.checked&&runnable(i)?' checked':''}${runnable(i)&&!bulk.running?'':' disabled'}>
  <span class="rem-sev">${badge(i.e)}</span><span class="rem-what"><strong>${esc(i.e.guidance?.title||i.e.title)}</strong><small><span class="resource-id" title="${esc(i.e.resource)}">${esc(shortResource(i.e.resource))}</span> · ${esc(i.e.dashboardAction.title)}</small><span class="auto-chip ${REASON[i.reason]?.[1]||'muted'}">${esc(REASON[i.reason]?.[0]||'')}</span></span></label><div class="bulk-state">${planNote(i)}</div></li>`).join('');
 const compliantRows=compliant.map(i=>{
  return `<li class="bulk-item off" data-key="bulk-${esc(i.e.id)}"><span class="rem-sev">${badge(i.e)}</span><span class="rem-what"><strong>${esc(i.e.guidance?.title||i.e.title)}</strong><small><span class="resource-id" title="${esc(i.e.resource)}">${esc(shortResource(i.e.resource))}</span> · ${esc(i.e.dashboardAction.title)}</small><small class="bulk-note">실행할 필요 없음</small></span><span class="auto-chip ok">양호</span></li>`;
 }).join('');
 const compliantSummary=`양호 ${compliant.length}건`;
 const compliantSection=compliant.length?`<details class="bulk-compliant"><summary>${compliantSummary}</summary><ul class="bulk-list">${compliantRows}</ul></details>`:'';
 const done=pending.filter(i=>i.result);
 const ok=done.filter(i=>['accepted','already'].includes(i.result.kind)).length,bad=done.filter(i=>i.result.kind==='failed').length;
 const summary=done.length&&!bulk.running?`<p class="rem-note ${bad?'warn':'ok'}">${ok}건 처리(접수 또는 이미 충족)${bad?` · ${bad}건 실패`:''}. 접수는 해결이 아닙니다 — 재검증 결과는 조치 이력에서 확인하세요.${bad?' 실패한 건은 사유를 그대로 두고 다시 실행하면 이미 접수된 건은 중복 실행되지 않습니다.':''}</p>`:'';
 box.innerHTML=`<div class="dialog-header"><div><div class="eyebrow">보안 이벤트</div><h2 id="bulk-title">수동 대응 ${pending.length}건</h2><p class="dialog-subtitle">대시보드에서 조치할 수 있는 미조치 항목입니다(수동 대응 필요 · 자동 조치가 실패했거나 실행 뒤에도 열려 있는 것 포함). 고른 항목을 사유 하나로 한 번에 실행합니다.${compliant.length?` 이미 양호한 ${compliant.length}건은 아래에 접어 뒀습니다.`:''}${excludedCount?` 대시보드로 조치하지 않는 ${excludedCount}건은 수동 대응이 아니므로 제외했습니다.`:''}</p></div><button class="dialog-close" data-bulk="close" aria-label="닫기">×</button></div>
  <div class="dialog-body">${canWrite||loading?'':'<p class="rem-note warn">이 계정은 조치를 실행할 수 없습니다(조회 전용이거나 실행 권한이 없습니다).</p>'}
  <p class="rem-warn"><strong>실행을 누르면 고른 항목이 바로 실행됩니다.</strong> 건마다 서버가 권한·범위·현재 상태를 다시 확인하며, 실행 뒤 같은 기준으로 자동 재검증합니다.</p>
  <div class="bulk-tools"><button type="button" class="text-button" data-bulk="all"${bulk.running?' disabled':''}>실행 가능한 항목 모두 선택</button><button type="button" class="text-button" data-bulk="none"${bulk.running?' disabled':''}>선택 해제</button><span class="muted-mini">선택 ${selected}건</span></div>
  <ul class="bulk-list">${rows}</ul>
  ${compliantSection}
  <label class="rem-field" for="bulk-reason">실행 사유 <small>(필수 · 500자 이내 · 선택한 모든 건의 조치 이력에 남습니다)</small></label><textarea id="bulk-reason" maxlength="500" rows="2" placeholder="예: 서비스에 영향이 없음을 확인함">${esc(reason)}</textarea>${summary}</div>
  <div class="dialog-actions"><span>${bulk.running?'순서대로 보내는 중입니다. 창을 닫아도 이미 보낸 건은 계속 진행됩니다.':''}</span><button class="cancel-button" data-bulk="close">닫기</button><button class="primary-button" id="bulk-run" data-bulk="run"${selected&&reason.trim()&&!bulk.running?'':' disabled'}>${bulk.running?'실행 중…':`일괄 조치 · 선택 ${selected}건`}</button></div>`;
 if(focused){const f=$('#bulk-reason');f.focus();if(at!=null)f.setSelectionRange(at,at);}
}
function renderDirect(box){
 const rows=bulk.items.map(i=>`<li class="bulk-item direct" data-key="direct-${esc(i.e.id)}"><div class="direct-main"><span class="rem-sev">${badge(i.e)}</span><span class="rem-what"><strong>${esc(i.e.guidance?.title||i.e.title)}</strong><small><span class="resource-id" title="${esc(i.e.resource)}">${esc(shortResource(i.e.resource))}</span></small>${i.e.guidance?.fix?.[0]?`<small class="bulk-note">고치는 법: ${esc(i.e.guidance.fix[0])}</small>`:''}</span></div><button type="button" class="text-button" data-event="${esc(i.e.id)}">상세 보기</button></li>`).join('');
 box.innerHTML=`<div class="dialog-header"><div><div class="eyebrow">보안 이벤트</div><h2 id="bulk-title">직접 조치 ${bulk.items.length}건</h2><p class="dialog-subtitle">대시보드로 조치할 수 없는 항목입니다. AWS 에서 직접 조치하면 이벤트가 목록에서 사라집니다.</p></div><button class="dialog-close" data-bulk="close" aria-label="닫기">×</button></div>
  <div class="dialog-body"><ul class="bulk-list">${rows}</ul></div><div class="dialog-actions"><span></span><button class="cancel-button" data-bulk="close">닫기</button></div>`;
}
// 자동 대응 목록: 자동 조치를 시도한 기록(읽기 전용). 실행 성공은 해결이 아니다 — 이벤트가 목록에서 사라지는지로 확인한다.
function renderAuto(box){
 const rows=bulk.items.map(({r})=>`<li class="bulk-item direct" data-key="auto-${esc(r.id)}"><div class="direct-main"><span class="rem-what"><small>${esc(format(milliseconds(r.lastSeenAt||r.createdAt)))}</small></span><span class="rem-what"><strong>${recordTitle(r)}</strong><small><span class="resource-id" title="${esc(r.resource||'')}">${esc(r.resource?shortResource(r.resource):'—')}</span></small></span></div><span>${automationState(r.automationStatus)}${r.eventId&&api.get(r.eventId)?` <button type="button" class="text-button" data-event="${esc(r.eventId)}">탐지 보기</button>`:''}</span></li>`).join('');
 box.innerHTML=`<div class="dialog-header"><div><div class="eyebrow">조치 이력</div><h2 id="bulk-title">자동 대응 ${bulk.items.length}건</h2><p class="dialog-subtitle">정책에 따라 자동으로 조치를 시도한 기록입니다. 실행 성공은 해결이 아닙니다.</p></div><button class="dialog-close" data-bulk="close" aria-label="닫기">×</button></div>
  <div class="dialog-body"><ul class="bulk-list">${rows}</ul></div><div class="dialog-actions"><span></span><button class="cancel-button" data-bulk="close">닫기</button></div>`;
}
async function loadPlans(serial){
 const queue=[...bulk.items];
 const worker=async()=>{
  while(queue.length){
   const item=queue.shift();
   try{const plan=await api.remediationPlan(item.e.id);if(serial!==bulk.serial)return;item.plan=plan;}
   catch(error){if(serial!==bulk.serial||error.name==='AbortError')return;item.error=`상태를 읽지 못했습니다: ${remediationErrorText(error)}`;}
   item.loading=false;render();
  }
 };
 await Promise.all(Array.from({length:CONCURRENCY},worker));
}
function open(mode){
 const c=classify(),list=mode==='direct'?c.direct.map(e=>({e,reason:null})):mode==='auto'?autoAttempts():c.actionable;
 if(!list.length)return;
 bulk.serial++;bulk.running=false;bulk.mode=['direct','auto'].includes(mode)?mode:'manual';
 bulk.items=bulk.mode==='auto'?list.map(r=>({r})):list.map(({e,reason})=>({e,reason,loading:bulk.mode==='manual',plan:null,error:null,checked:false,result:null}));
 render();$('#bulk-dialog').showModal();if(bulk.mode==='manual')loadPlans(bulk.serial);
}
async function run(){
 const reasonEl=$('#bulk-reason'),text=reasonEl.value.trim();if(!text||bulk.running)return;
 const targets=bulk.items.filter(i=>i.checked&&runnable(i));if(!targets.length)return;
 bulk.running=true;const serial=bulk.serial;
 for(const item of targets){
  // 같은 건·같은 사유의 재시도는 같은 키(이미 접수된 실행을 다시 만들지 않는다). 사유가 바뀌면 새 요청.
  const stamp=item.e.id+'\n'+text;if(!bulk.keys.has(stamp))bulk.keys.set(stamp,newKey());
  item.result={kind:'running'};render();
  try{
   const r=await api.remediate(item.e.id,{reason:text,playbookId:item.plan.playbookId},bulk.keys.get(stamp));
   item.result={kind:r.state==='ALREADY_COMPLIANT'?'already':'accepted'};
  }catch(error){item.result={kind:'failed',text:remediationErrorText(error)||'실행하지 못했습니다.'};}
  if(serial!==bulk.serial)return;
 }
 bulk.running=false;
 // 실패한 건은 다시 고를 수 있게 결과를 비우고 메시지만 남긴다(접수된 건은 결과가 남아 다시 실행되지 않는다).
 render();
}
document.addEventListener('click',event=>{
 const t=event.target.closest?.('[data-bulk-open],[data-bulk]');if(!t)return;
 if(t.hasAttribute('data-bulk-open')){open(t.getAttribute('data-bulk-open'));return;}
 const a=t.dataset.bulk;
 if(a==='close'){$('#bulk-dialog').close();return;}
 if(a==='all'){bulk.items.forEach(i=>{if(runnable(i))i.checked=true;});render();return;}
 if(a==='none'){bulk.items.forEach(i=>{i.checked=false;});render();return;}
 if(a==='run')run();
});
document.addEventListener('change',event=>{
 const c=event.target.closest?.('[data-bulk-check]');if(!c)return;
 const item=bulk.items.find(i=>i.e.id===c.dataset.bulkCheck);if(item){item.checked=c.checked;render();}
});
document.addEventListener('input',event=>{
 if(event.target?.id!=='bulk-reason')return;
 const run=$('#bulk-run');if(run)run.disabled=!event.target.value.trim()||bulk.running||!bulk.items.some(i=>i.checked&&runnable(i));
});
// 직접 조치 목록에서 상세를 열면 팝업을 먼저 닫는다(상세는 앱의 기존 열기 동작이 처리).
document.addEventListener('click',event=>{if(event.target.closest?.('#bulk-dialog [data-event]'))$('#bulk-dialog').close();},true);
