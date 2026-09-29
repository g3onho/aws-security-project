// 대시보드 도우미(챗봇, v27) — 조회 전용. 화면 어디서나 오른쪽 아래 버튼으로 연다.
// UI 는 Store action(api.assistant*)만 부른다. 답변·도구 이름은 서버·모델이 만든 문자열이므로 전부 esc() 를 거쳐 텍스트로만 그린다
// (마크다운·HTML 해석 없음). 도우미는 변경 도구가 없다 — 조치는 화면의 기존 버튼(권한·CSRF·멱등키 검증)으로만 한다.
import {$,api,state} from '../context.js?v=q6-ui-1-l1';
import {esc} from './format.js?v=q6-ui-1';

const SUGGEST={
 overview:['지금 가장 심각한 보안 이벤트가 뭐야?','자동 조치는 얼마나 됐어?','열린 취약점 요약해줘'],
 events:['미해결 이벤트 중 급한 것부터 알려줘','최근 24시간 이벤트를 심각도별로 정리해줘'],
 vulnerabilities:['치명적·높음 취약점을 요약해줘','고칠 수 있는(fixedVersion) 것부터 알려줘'],
 infrastructure:['이상한 인프라 상태가 있어?','경보(알람) 상태를 알려줘'],
 responses:['최근 조치 중 실패한 게 있어?','자동으로 처리된 건 뭐야?'],
 drills:['공격 실습은 어디까지 준비돼 있어?','최근 실습 결과를 알려줘'],
 honeypot:['허니팟이 잘 동작하고 있어?','차단된 IP 는 뭘 했던 공격자야?','왜 자동 차단이 안 됐는지 알려줘'],
};
const KEEP_TURNS=5;                                   // 서버로 보내는 이전 대화 상한(질문·답 5쌍 + 새 질문)
const TOOL_KO={overview:'요약',list_events:'이벤트',list_vulnerabilities:'취약점',action_history:'조치 이력',infra_status:'인프라',
 honeypot_status:'허니팟 상태',honeypot_stats:'허니팟 통계',honeypot_sessions:'허니팟 세션',honeypot_session_detail:'세션 상세',
 honeypot_timeline:'공격 타임라인',blocklist:'차단 목록'};

const S={open:false,busy:false,turns:[],status:null,error:'',mounted:false};

const spark='<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l2.2 6.3L21 10l-6.3 2.2L12 19l-2.2-6.8L3 10l6.8-1.7z"/><path d="M19 3v4M17 5h4"/></svg>';

function toolChips(tools){
 const seen=new Set();
 return (tools||[]).map(t=>{
  const label=(TOOL_KO[t.name]||t.name)+(t.args?.ip?` · ${t.args.ip}`:'');
  return seen.has(label)?'':(seen.add(label),`<span class="as-chip" title="도우미가 조회한 항목(읽기 전용)">${esc(label)}</span>`);
 }).join('');
}
const text=value=>esc(value).replace(/\n/g,'<br>');

function bubbles(){
 const rows=S.turns.map(t=>`<div class="as-msg as-user"><span>${text(t.q)}</span></div>${t.a==null?'':
  `<div class="as-msg as-bot" data-truncated="${t.truncated?'true':'false'}"><span>${text(t.a)}</span>${t.tools?.length?`<div class="as-tools">${toolChips(t.tools)}</div>`:''}${t.truncated?'<small class="as-warn">답변이 길어 잘렸을 수 있습니다. 질문을 좁혀 보세요.</small>':''}</div>`}`).join('');
 return rows+(S.busy?'<div class="as-msg as-bot as-typing" aria-label="조회 중"><span><i></i><i></i><i></i></span></div>':'');
}
function suggestions(){
 if(S.turns.length||S.busy)return '';
 const list=SUGGEST[state.view]||SUGGEST.overview;
 return `<div class="as-suggest" aria-label="예시 질문">${list.map(q=>`<button type="button" class="as-sug" data-as-ask="${esc(q)}">${esc(q)}</button>`).join('')}</div>`;
}
function body(){
 if(!S.status)return '<p class="as-note">상태를 확인하는 중…</p>';
 if(S.status.error)return `<p class="as-note as-bad">도우미 상태를 읽지 못했습니다: ${esc(S.status.error)}</p>`;
 if(!S.status.enabled)return `<p class="as-note as-bad"><b>AI 도우미를 쓸 수 없습니다.</b><br>서버에서 꺼져 있거나(ASSISTANT_ENABLED), AWS 연결·Bedrock 권한(IAM)이 없습니다. 담당자에게 알려 주세요.</p>`;
 const intro=S.turns.length?'':`<div class="as-intro"><b>무엇이든 물어보세요</b><span>이 대시보드의 이벤트·취약점·조치 이력·허니팟·인프라를 조회해서 답합니다. <em>읽기 전용</em>이라 차단·해제·승인은 하지 못합니다.</span></div>`;
 return `${intro}<div class="as-log" role="log" aria-live="polite" aria-relevant="additions">${bubbles()}</div>${S.error?`<p class="as-note as-bad" role="alert">${esc(S.error)}</p>`:''}${suggestions()}`;
}
function paint(){
 const panel=$('#assistant-panel');if(!panel)return;
 const can=Boolean(S.status?.enabled);
 panel.hidden=!S.open;
 $('#assistant-fab').setAttribute('aria-expanded',S.open?'true':'false');
 panel.querySelector('.as-body').innerHTML=body();
 const input=panel.querySelector('.as-input'),send=panel.querySelector('.as-send');
 input.disabled=!can||S.busy;send.disabled=!can||S.busy;
 const log=panel.querySelector('.as-scroll');if(log)log.scrollTop=log.scrollHeight;
}
async function loadStatus(){
 try{S.status=(await api.assistantStatus()).data;}catch(error){S.status={error:error.message};}
 paint();
}
export function toggleAssistant(open=!S.open){
 S.open=open;paint();
 if(S.open){if(!S.status)loadStatus();$('#assistant-panel .as-input')?.focus();}
 else $('#assistant-fab')?.focus();
}
async function ask(question){
 const q=String(question||'').trim();
 if(!q||S.busy||!S.status?.enabled)return;
 const history=S.turns.filter(t=>t.a!=null).slice(-KEEP_TURNS).flatMap(t=>[{role:'user',content:t.q},{role:'assistant',content:t.a}]);
 const turn={q,a:null};S.turns.push(turn);S.busy=true;S.error='';paint();
 try{
  const out=await api.assistantChat([...history,{role:'user',content:q}]);
  turn.a=String(out.answer||'');turn.tools=out.toolsUsed||[];turn.truncated=out.truncated===true;
 }catch(error){
  S.turns.pop();                                     // 실패한 질문은 대화 기록에 남기지 않는다(다음 질문의 맥락을 오염시키지 않게)
  S.error=error.message||'답변을 받지 못했습니다.';
  const input=$('#assistant-panel .as-input');if(input)input.value=q;
 }finally{S.busy=false;paint();}
}
export function resetAssistant(){S.turns=[];S.error='';paint();}

export function initAssistant(){
 if(S.mounted||!document.body)return;
 S.mounted=true;
 document.body.insertAdjacentHTML('beforeend',`<button type="button" id="assistant-fab" class="as-fab" aria-controls="assistant-panel" aria-expanded="false" aria-label="AI 도우미 열기">${spark}<span>AI</span></button>
 <section id="assistant-panel" class="as-panel" role="dialog" aria-label="AI 도우미" hidden>
  <header class="as-head"><span class="as-title">${spark}<b>AI 도우미</b><em>조회 전용</em></span>
   <span><button type="button" class="as-icon" data-as-reset title="새 대화" aria-label="새 대화">↺</button><button type="button" class="as-icon" data-as-close title="닫기" aria-label="닫기">✕</button></span></header>
  <div class="as-scroll"><div class="as-body"></div></div>
  <form class="as-form"><textarea class="as-input" rows="2" maxlength="2000" placeholder="예: 10.0.2.55 는 뭘 했어?" aria-label="질문"></textarea><button type="submit" class="as-send">보내기</button></form>
  <p class="as-foot">답변은 참고용입니다. 질문과 조회 결과는 AWS Bedrock 으로 전송됩니다. 비밀번호·키는 조회하지 않습니다.</p>
 </section>`);
 const panel=$('#assistant-panel');
 $('#assistant-fab').addEventListener('click',()=>toggleAssistant());
 panel.addEventListener('click',e=>{
  if(e.target.closest('[data-as-close]'))toggleAssistant(false);
  else if(e.target.closest('[data-as-reset]'))resetAssistant();
  else{const sug=e.target.closest('[data-as-ask]');if(sug)ask(sug.dataset.asAsk);}
 });
 const input=panel.querySelector('.as-input');
 panel.querySelector('.as-form').addEventListener('submit',e=>{e.preventDefault();const q=input.value;input.value='';ask(q);});
 input.addEventListener('keydown',e=>{if(e.key==='Enter'&&!e.shiftKey&&!e.isComposing){e.preventDefault();panel.querySelector('.as-form').requestSubmit();}});
 panel.addEventListener('keydown',e=>{if(e.key==='Escape'){e.stopPropagation();toggleAssistant(false);}});
 paint();
}
