// 탐지 상세의 '대시보드 조치'(v29): 미리보기 → 확인창에서 바로 실행 → 진행 상태 → 자동 재검증 결과.
// 계획(문서·대상)은 서버가 만든다. 이 화면은 사유와 '이 계획을 보고 눌렀다'는 playbookId 만 보낸다.
import {$,api,storeApi} from '../context.js?v=v44';
import {esc,format,milliseconds} from './format.js?v=v44';
import {patchMarkup} from './rendering.js?v=v44';
import {remediationState,remediationDetail,REMEDIATION_ACTIVE,remediationErrorText} from './remediation.js?v=v44';
const POLL_MS=3000;
const view={eventId:null,plan:null,timer:null,serial:0};
const newKey=()=>{const bytes=new Uint8Array(16);if(globalThis.crypto?.getRandomValues)globalThis.crypto.getRandomValues(bytes);else bytes.forEach((_,i)=>{bytes[i]=Math.floor(Math.random()*256);});return 'rm-'+[...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');};
export const remediationSection=()=>`<section class="detail-section wide rem-section"><h3>대시보드 조치 <small class="source-note">확인 후 바로 실행 · 실행 뒤 같은 기준으로 자동 재검증</small></h3><div id="event-remediation" data-key="event-remediation"><p class="muted">조치 가능 여부를 확인하는 중…</p></div></section>`;
export function stopRemediation(){clearTimeout(view.timer);view.timer=null;view.serial++;view.eventId=null;view.plan=null;}
const target=()=>$('#event-remediation');
const hideSection=()=>{const box=target();if(box)box.closest('.rem-section')?.setAttribute('hidden','');};
function facts(plan,{current=true}={}){
 const now=plan.current?.text||plan.currentError||'현재 상태를 읽지 못했습니다.';
 return `<dl class="rem-facts"><div><dt>바꾸는 내용</dt><dd>${esc(plan.change)}</dd></div>${current?`<div><dt>현재 상태 (조치 전)</dt><dd>${esc(now)}</dd></div>`:''}<div><dt>재검증 기준</dt><dd>${esc(plan.criterion)}</dd></div></dl>`;
}
function runItem(r,plan){
 const recheck=['NOT_RESOLVED','VERIFY_ERROR'].includes(r.state)&&plan.canWrite===true?`<button class="link-button" data-rem="recheck" data-id="${esc(r.id)}">재검증 다시 읽기</button>`:'';
 return `<li class="rem-run"><div class="eh-head"><span>${esc(format(milliseconds(r.createdAt)))}</span><strong>${esc(r.actor)}</strong>${remediationState(r.state)}${recheck}</div>${r.reason?`<p class="muted-mini">사유: ${esc(r.reason)}</p>`:''}${remediationDetail(r)}</li>`;
}
function markup(plan){
 const runs=(plan.latest||[]).length?`<h4 class="rem-sub">실행 기록 <small>이 탐지에 대해 대시보드에서 실행한 것</small></h4><ul class="rem-runs">${plan.latest.map(r=>runItem(r,plan)).join('')}</ul>`:'';
 if(!plan.supported)return `<p class="muted">이 탐지는 대시보드에서 실행할 수 없습니다. ${esc(plan.reason||'')}</p>${runs}`;
 const active=(plan.latest||[]).some(r=>REMEDIATION_ACTIVE.includes(r.state));
 const note=plan.alreadyCompliant?'<p class="rem-note ok">지금 상태가 이미 재검증 기준을 만족합니다. 실행할 필요가 없어 실행 버튼을 잠갔습니다.</p>':'';
 const why=plan.blockedReason?`<p class="rem-note warn">${esc(plan.blockedReason)}</p>`:'';
 const override=!plan.canExecute&&!!plan.blockOverridable&&!!plan.blockedReason;   // 막혔지만 위험을 확인하면 실행할 수 있는 건
 return `<div class="rem-card"><div class="rem-head"><strong>${esc(plan.title)}</strong><code>${esc(plan.playbookId)}</code>${plan.alreadyCompliant?'<span class="auto-chip ok">현재 기준 충족</span>':`<span class="auto-chip ${plan.category==='auto-eligible'?'run':'warn'}">${plan.category==='auto-eligible'?'자동 조치 대상 · 미실행':'수동 대응 필요 건'}</span>`}</div>
  ${facts(plan)}${note}${why}<div class="rem-actions"><button class="primary-button${override?' rem-override':''}" data-rem="open"${(plan.canExecute||override)&&!active&&!plan.alreadyCompliant?'':' disabled'}${override?` title="${esc(plan.blockedReason)}"`:''}>${override?'조치 실행 (위험 확인 필요)':'대시보드에서 조치 실행'}</button>${plan.mode==='demo'?'<span class="muted-mini">데모 모드 — 실제 AWS 를 호출하지 않습니다.</span>':''}</div></div>${runs}`;
}
function render(plan){
 view.plan=plan;
 const box=target();if(!box)return;
 if(!plan.eligible&&!(plan.latest||[]).length){hideSection();return;}
 box.closest('.rem-section')?.removeAttribute('hidden');
 patchMarkup(box,markup(plan));
}
async function poll(eventId,serial){
 if(serial!==view.serial)return;
 try{
  const list=await storeApi.remediations(eventId);if(serial!==view.serial)return;
  if(list.items.some(r=>REMEDIATION_ACTIVE.includes(r.state))){render({...view.plan,latest:list.items});view.timer=setTimeout(()=>poll(eventId,serial),POLL_MS);return;}
  render(await storeApi.remediationPlan(eventId));                  // 끝났으면 현재 상태·실행 가능 여부를 다시 읽는다
 }catch(error){
  if(serial===view.serial&&view.plan){render({...view.plan,blockedReason:`진행 상태를 읽지 못했습니다: ${remediationErrorText(error)}`});view.timer=setTimeout(()=>poll(eventId,serial),POLL_MS*3);}
 }
}
export async function loadRemediation(eventId,isCurrent){
 stopRemediation();const serial=view.serial;view.eventId=eventId;
 try{
  const plan=await api.remediationPlan(eventId);if(serial!==view.serial||!isCurrent())return;
  render(plan);
  if((plan.latest||[]).some(r=>REMEDIATION_ACTIVE.includes(r.state)))view.timer=setTimeout(()=>poll(eventId,serial),POLL_MS);
 }catch(error){
  if(serial!==view.serial||!isCurrent()||error.name==='AbortError')return;
  const box=target();if(box)patchMarkup(box,`<p class="panel-error" role="status">조치 정보를 불러오지 못했습니다: ${esc(remediationErrorText(error))}</p>`);
 }
}
// ── 확인창 ──────────────────────────────────────────────────────────────
function openConfirm(plan){
 const dialog=$('#remediate-dialog'),reasonKey={key:newKey(),reason:''};
 // 막혔지만 위험을 확인하면 넘길 수 있는 건(서비스용 SG 등): 이유를 먼저 보여주고 한 번 더 묻는다.
 // 서버도 acknowledgeRisk 없이는 409 로 막으므로, 이 플래그는 화면 장식이 아니라 실제 동의 표시다.
 const override=!plan.canExecute&&!!plan.blockOverridable&&!!plan.blockedReason;
 const risk=override?`<div class="rem-risk" role="alert"><p class="rem-risk-why"><strong>이 대상은 기본적으로 조치를 막아 둡니다.</strong><br>${esc(plan.blockedReason)}</p>
  <p class="rem-risk-ask"><strong>정말 조치하시겠습니까?</strong> 그대로 실행하면 서비스가 끊길 수 있습니다. 실행 사유와 함께 조치 이력·감사 기록에 '위험 확인' 으로 남습니다.</p></div>`:'';
 $('#remediate-content').innerHTML=`<div class="dialog-header"><div><div class="eyebrow">조치 실행 확인</div><h2 id="remediate-title">${esc(plan.title)}</h2><p class="dialog-subtitle">${esc(plan.playbookId)}</p></div><button class="dialog-close" data-rem="cancel" aria-label="닫기">×</button></div>
  <div class="dialog-body">${risk}<p class="rem-warn"><strong>확인을 누르면 바로 실행됩니다.</strong> 실행이 끝나면 같은 기준으로 자동 재검증하고, 통과해야 '해결 확인'으로 표시합니다.</p>
  <dl class="rem-facts"><div><dt>대상 자원</dt><dd>${esc(plan.target?.resource||'—')}</dd></div><div><dt>계정 · 리전</dt><dd>${esc(plan.accountId||plan.target?.accountId||'—')} · ${esc(plan.target?.region||'—')}</dd></div></dl>${facts(plan)}
  <label class="rem-field" for="rem-reason">실행 사유 <small>(필수 · 500자 이내 · 조치 이력에 남습니다)</small></label><textarea id="rem-reason" maxlength="500" rows="3" placeholder="예: 서비스에 영향이 없음을 확인함"></textarea>
  <p id="rem-error" class="panel-error" role="alert" hidden></p></div>
  <div class="dialog-actions"><span>${plan.mode==='demo'?'데모 모드 — 실제 AWS 를 호출하지 않습니다.':`AWS 계정 ${esc(plan.accountId||'')} 에서 실행됩니다.`}</span><button class="cancel-button" data-rem="cancel">취소</button><button class="primary-button${override?' rem-override':''}" id="rem-run" data-rem="run" disabled>${override?'위험을 확인했고 조치합니다':'실행'}</button></div>`;
 const run=$('#rem-run'),reason=$('#rem-reason'),error=$('#rem-error');
 reason.addEventListener('input',()=>{run.disabled=!reason.value.trim();});
 run.addEventListener('click',async()=>{
  const text=reason.value.trim();if(!text)return;
  if(text!==reasonKey.reason){reasonKey.key=newKey();reasonKey.reason=text;}   // 같은 사유의 재시도는 같은 키(중복 실행 방지), 바뀌면 새 요청
  run.disabled=true;run.textContent='실행 중…';error.hidden=true;
  try{
   const body=override?{reason:text,playbookId:plan.playbookId,acknowledgeRisk:true}:{reason:text,playbookId:plan.playbookId};
   const result=await api.remediate(plan.eventId,body,reasonKey.key);
   dialog.close();
   render({...view.plan,latest:[result,...(view.plan?.latest||[]).filter(r=>r.id!==result.id)],canExecute:false,blockedReason:'방금 실행한 조치의 진행 상태를 갱신하고 있습니다.'});
   clearTimeout(view.timer);view.timer=setTimeout(()=>poll(plan.eventId,view.serial),result.state==='ALREADY_COMPLIANT'?0:POLL_MS/2);
  }catch(failure){
   error.textContent=failure.message||'실행하지 못했습니다.';error.hidden=false;run.disabled=!reason.value.trim();run.textContent=override?'위험을 확인했고 조치합니다':'실행';
  }
 });
 dialog.showModal();reason.focus();
}
document.addEventListener('click',async event=>{
 const button=event.target.closest?.('[data-rem]');if(!button)return;
 const action=button.dataset.rem;
 if(action==='cancel'){$('#remediate-dialog').close();return;}
 if(action==='open'&&view.plan)openConfirm(view.plan);
 if(action==='recheck'){
  button.disabled=true;
  try{await storeApi.remediationRecheck(button.dataset.id);render(await storeApi.remediationPlan(view.eventId));}
  catch(error){button.disabled=false;button.textContent=`다시 읽지 못했습니다: ${error.message}`;}
 }
});
