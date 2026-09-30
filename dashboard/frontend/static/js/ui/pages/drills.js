// 보안 시나리오: 시나리오 표가 화면의 뼈대이고, 선택 없이 [전부 실행] 한 번으로 준비된 모든 시나리오를 실행한다.
// 실행은 백엔드 POST /api/drills/run-all/start(SSM)이며 WRITE_ENABLED 가 꺼져 있으면 403 이다.
import {$,api} from '../context.js?v=v43';
import {esc,format,milliseconds} from '../components/format.js?v=v43';
import {loadPanel,header} from '../components/panel.js?v=v43';
import {openReport} from '../components/report.js?v=v43';
import {flowBlock,scenarioStages,FLOW_NOTE_SCENARIO} from './flow-map.js?v=v43';

// runnable 을 prep-needed 와 같은 색으로 통일한다 — 시나리오 표는 [전부 실행] 대상만 보여주므로(RUN_ALL_SECS 필터)
// 전부 "실행 가능"이고, 이 표 밖에서는 이 색이 안 쓰인다.
const SUPPORT_COLOR={runnable:'#9d5b22','prep-needed':'#9d5b22','observe-only':'#00579e','design-needed':'#93a7b7'};
// 백엔드 DrillService.start_all 이 한 번에 실행하는 시나리오(SEC-06B 는 SEC-08 지리 공격 실행에 함께 들어 있다).
const RUN_ALL_SECS=['SEC-01','SEC-02','SEC-03','SEC-04','SEC-06A','SEC-07','SEC-08','SEC-06B','SEC-09','SEC-10'];
// [전부 실행] 카드에 보여줄 시나리오별 공격·점검 방법(백엔드 DrillService.start_all 이 쓰는 도구 기준).
const RUN_METHODS=[
 ['SEC-01','SSH 과다 공개','전용 실습 SG 에 0.0.0.0/0:22 재현 → asr_trigger 직접 호출로 즉시 자동 회수'],
 ['SEC-02','포트·헤더 점검','nmap 으로 열린 포트를 스캔하고 curl 로 응답 보안 헤더를 확인'],
 ['SEC-03','DB 포트 노출 비교','db-auto-sg(자동 회수)·db-manual-sg(알림만)에 0.0.0.0/0:3306 재현 후 비교'],
 ['SEC-04','이미지 CVE','Trivy 로 컨테이너 이미지의 알려진 취약점(CVE)을 스캔'],
 ['SEC-06A','DB 무차별 대입','파리 내부 공격자 EC2 에서 hydra 로 테스트 DB 계정에 반복 로그인 시도, 자동 차단 시연'],
 ['SEC-07','비밀값 스캔','코드·이미지에 합성 테스트 비밀값이 남아 있는지 스캔'],
 ['SEC-08/06B','지리 공격','5개 리전 공격자 EC2 가 nmap 스캔 → hydra SSH·웹 무차별 대입 → ZAP·sqlmap 으로 DVWA 공격'],
 ['SEC-09','감사 로그 상태','CloudTrail·Config·VPC Flow Logs 수집 상태를 즉시 조회(조회 전용)'],
 ['SEC-10','부하','stress-ng 로 파리 EC2(대시보드 제외)에 CPU·메모리 부하'],
 ['HONEYPOT','내부 침투','파리(홈 리전) 공격자 EC2 에서 미끼 서버로 SSH 접속 시도, 자동 차단 시연']];
const RUN_SEC_OF={'SEC-06B':'SEC-08'};
// 새로고침해도 진행 중인 실행을 잃지 않도록 runId 만 저장한다(진행표는 서버에서 다시 받는다). 저장소 접근은 항상 try/catch.
const RUN_ALL_LS_KEY='drills-run-all-id';
const saveRunAllId=id=>{try{localStorage.setItem(RUN_ALL_LS_KEY,id);}catch{}};
const clearRunAllId=()=>{try{localStorage.removeItem(RUN_ALL_LS_KEY);}catch{}};
const loadRunAllId=()=>{try{return localStorage.getItem(RUN_ALL_LS_KEY);}catch{return null;}};
let resumed=false;
const RUN_STATUS_KO={Pending:'대기',InProgress:'실행 중',Delayed:'지연',Success:'완료',Cancelled:'취소',TimedOut:'시간초과',Failed:'실패',Cancelling:'취소 중',Unknown:'알 수 없음'};
const TERMINAL=new Set(['Success','Cancelled','TimedOut','Failed']);
const RUNNING=new Set(['Pending','InProgress','Delayed','Cancelling']);

let catalog=null,runs=null;
const run={runId:null,items:[],skipped:[],busy:false,error:null,timer:null,done:false};
// [보고서 추출] 상태. 누를 때마다 서버에서 리전별 SEC-08 로그를 읽어 파일 하나로 바로 내려받는다(아직 안 끝난 리전은 빠지고, 다시 누르면 채워진다).
const report={runId:null,regions:null,loading:false,error:null};
// 진행 팝업: 실행을 시작하면 열리고, 닫아도 실행은 계속된다(버튼 [실행 중 · 진행 보기]로 다시 연다). 실행 이력의 [보고서]는 같은 팝업에 그 실행을 연다.
let shown=null,dlgOpen=false;   // shown = 팝업이 보여주는 실행(진행 중인 run 이거나 이력에서 연 past)
function downloadJson(filename,obj){
 const blob=new Blob([JSON.stringify(obj,null,2)],{type:'application/json'});
 const url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),1000);
}

function supportPill(support,label){
 const c=SUPPORT_COLOR[support]||SUPPORT_COLOR['design-needed'];
 return `<span class="service-pill" style="color:${c}"><i style="background:${c}"></i>${esc(label)} <small>${esc(support)}</small></span>`;
}

function environmentStrip(env){
 const provider=env.dataSourceConnected?'연결됨':'미연결';
 const isolation=env.isolationVerified==='unknown'?'확인 불가':esc(env.isolationVerified||'확인 불가');
 const execution=env.dataSourceConnected?'전부 실행 가능':'경로 미연결';
 return `<div class="drill-context-strip" role="status"><span><b>실행</b> ${execution}</span><span><b>데이터 소스</b> ${provider}</span><span><b>리전</b> ${esc(env.region||'—')}</span><span><b>격리</b> ${isolation}</span></div>`;
}

// 시나리오별 실행 결과: 이번 [전부 실행]에서 해당 SEC 항목들의 상태를 하나로 요약한다.
function resultOf(id){
 const sec=RUN_SEC_OF[id]||id;
 const mine=run.items.filter(item=>item.sec===sec);
 if(!mine.length){
  if(run.skipped.some(text=>text.includes(id)||text.includes(sec)))return '<span class="muted">건너뜀</span>';
  return `<span class="muted">${run.runId?'대상 없음':'실행 전'}</span>`;
 }
 const states=mine.map(item=>item.status);
 const label=states.some(s=>s==='Failed'||s==='TimedOut')?'실패':states.some(s=>RUNNING.has(s))?'실행 중':states.every(s=>s==='Success')?'완료':states.some(s=>s==='Cancelled')?'취소':'알 수 없음';
 return `<strong>${label}</strong> <small class="muted">${mine.length}건</small>`;
}
let flowId=null;   // 경로 지도 팝업에 열려 있는 시나리오 ID
function scenarioRow(s){
 const obs=s.observation==='connected'?'연결됨':'미연결';
 return `<tr><td class="drill-scenario-main"><strong>${esc(s.id)}</strong><span>${esc(s.purpose)}</span>
  <button type="button" class="flow-toggle" data-flow-toggle="${esc(s.id)}" aria-haspopup="dialog">경로 지도 보기</button></td>
  <td class="drill-scenario-evidence"><span><b>관측</b> ${s.sources.map(esc).join(' · ')}</span><span><b>대응</b> ${esc(s.response)}</span></td>
  <td class="drill-scenario-status"><div>${supportPill(s.support,s.supportLabel)}</div><small>관측 ${obs}</small></td>
  <td class="drill-scenario-result">${resultOf(s.id)}</td></tr>`;
}
// 경로 지도는 보안 이벤트 상세와 같은 큰 팝업으로 연다(표 안에서 펼치면 좁아서 글씨가 잘린다).
function paintFlowDialog(){
 const box=$('#flow-dialog');if(!box)return;
 const s=flowId&&catalog?.scenarios.find(x=>x.id===flowId);
 if(!s){if(box.open)box.close();return;}
 $('#flow-dialog-content').innerHTML=`<div class="dialog-header"><div><div class="eyebrow">${esc(s.id)} / 경로 지도</div><h2 id="flow-dialog-title">${esc(s.purpose)}</h2></div><button type="button" class="dialog-close" data-flow-close aria-label="경로 지도 닫기">×</button></div>
  <div class="dialog-body"><div id="flow-${esc(s.id)}" class="scenario-flow">${flowBlock(scenarioStages(s,run.items),FLOW_NOTE_SCENARIO)}</div></div>
  <div class="dialog-actions"><span>읽기 전용</span><button type="button" class="cancel-button" data-flow-close>닫기</button></div>`;
 if(!box.open)box.showModal();
}
function closeFlow(){
 const id=flowId;flowId=null;
 const box=$('#flow-dialog');if(box&&box.open)box.close();
 const again=[...document.querySelectorAll('[data-flow-toggle]')].find(b=>b.dataset.flowToggle===id);if(again)again.focus();
}
function scenarioTable(){
 return `<div class="table-scroll"><table class="drill-scenario-table"><caption class="sr-only">보안 시나리오 카탈로그</caption>
  <thead><tr><th>시나리오</th><th>확인 자료와 대응</th><th>지원 상태</th><th>실행 결과</th></tr></thead>
  <tbody>${catalog.scenarios.filter(s=>RUN_ALL_SECS.includes(s.id)).map(scenarioRow).join('')}</tbody></table></div>`;
}

function runPanel(){
 const env=catalog.environment||{};
 const ready=env.dataSourceConnected===true;
 const geoLine=env.webScanReady===true?'지리 공격 포함':'지리 공격자 미배포 — SEC-08/06B 건너뜀';
 const elig=ready?`<div class="drill-eligibility"><span class="drill-elig-dot" style="background:#0b8577"></span>실행 가능 · ${esc(geoLine)}</div>`
  :`<div class="drill-eligibility"><span class="drill-elig-dot"></span>실행 불가 · 데이터 소스 미연결</div>`;
 const attr=ready&&!run.busy?'data-run-all-start':'disabled';
 return `<div class="drill-config"><h3>전부 실행</h3>
  <p class="muted">준비된 시나리오를 한 번에 실행합니다. 대상이 없으면 건너뛰고 사유를 남깁니다. 진행과 보고서는 팝업에서 봅니다.</p>
  <ul class="drill-run-list">${RUN_METHODS.map(([id,name,how])=>`<li><b>${esc(id)}</b><span><em>${esc(name)}</em><small>${esc(how)}</small></span></li>`).join('')}</ul>
  ${elig}
  <div class="drill-actions">
   ${run.busy
    ?`<button type="button" class="primary-button" data-run-open aria-haspopup="dialog">실행 중 · 진행 보기</button>`
    :`<button type="button" class="primary-button" ${attr}>전부 실행</button>${run.runId?`<button type="button" class="cancel-button" data-run-open aria-haspopup="dialog">최근 실행 보기</button>`:''}`}
  </div>
  ${run.error?`<p class="panel-error" role="alert">${esc(run.error)}</p>`:''}
</div>`;
}

// ── 진행 팝업 ──────────────────────────────────────────────
const isAtk=v=>v.items.some(item=>item.sec==='SEC-08');
function progressBar(v){
 const total=v.items.length,done=v.items.filter(item=>TERMINAL.has(item.status)).length;
 const failed=v.items.filter(item=>item.status==='Failed'||item.status==='TimedOut').length;
 const pct=total?Math.round(done/total*100):0;
 return `<div class="run-meter" role="progressbar" aria-valuemin="0" aria-valuemax="${total}" aria-valuenow="${done}" aria-label="실행 진행률"><i style="width:${pct}%"></i></div>
  <p class="run-meter-text"><b>${done}/${total}</b> 항목 종료${failed?` · <span class="bad-text">실패·시간초과 ${failed}</span>`:''}</p>`;
}
function reportBlock(v){
 if(report.runId!==v.runId||!report.regions)return '';
 const entries=Object.entries(report.regions);
 if(!entries.length)return `<div class="detail-section"><h3>공격 보고서</h3><p class="muted">이 실행에는 SEC-08 공격 로그가 없습니다.</p></div>`;
 return `<div class="detail-section"><h3>공격 보고서(리전별)</h3><ul class="run-report-list">${entries.map(([label,r])=>
  `<li><b>${esc(label)}</b><span class="${r.ready?'ok-text':'muted'}">${r.ready?'✓ 로그 확보':esc(r.reason||'준비 안 됨')}</span></li>`).join('')}</ul></div>`;
}
function runDialogHtml(v){
 const active=v===run,live=active&&run.busy&&!run.done;
 const rows=v.items.map((item,i)=>{
  const state=RUN_STATUS_KO[item.status]||esc(item.status||'—');
  const out=item.output?`<details data-k="${i}"><summary>출력 보기</summary><pre class="drill-attack-output">${esc(item.output)}</pre></details>`:(item.detail?`<small class="muted">${esc(item.detail)}</small>`:'');
  return `<tr><td>${esc(item.label||item.sec||'—')}</td><td><span class="run-state" data-state="${esc(String(item.status||'').toLowerCase())}">${state}</span></td><td>${out}</td></tr>`;
 }).join('');
 const skipped=v.skipped.length?`<p class="muted">건너뜀: ${v.skipped.map(esc).join(', ')}</p>`:'';
 const note=v.loading?'불러오는 중…':live?'진행 중 · 5초마다 자동 갱신합니다. 창을 닫아도 실행은 계속됩니다.':(v.items.length&&v.items.every(item=>TERMINAL.has(item.status))?'모든 항목이 종료됐습니다.':'');
 const canReport=isAtk(v)&&!report.loading&&!v.loading;
 return `<div class="dialog-header"><div><div class="eyebrow">RUN ALL / ${active?'실험 진행':'실행 보고서'}</div><h2 id="run-dialog-title">${active?'실험 진행':'실행 보고서'}</h2>
   <p class="muted run-id-line">실행 ID: ${esc(v.runId||'발급 중…')}</p></div><button type="button" class="dialog-close" data-run-close aria-label="팝업 닫기">×</button></div>
  <div class="dialog-body run-dialog-body">${progressBar(v)}<p class="muted">${esc(note)}</p>${skipped}
   <div class="table-scroll"><table><caption class="sr-only">실행 항목</caption><thead><tr><th>항목</th><th>상태</th><th>결과</th></tr></thead>
   <tbody>${rows||`<tr><td colspan="3" class="muted">${v.loading?'불러오는 중…':'실행 항목을 기다리는 중입니다.'}</td></tr>`}</tbody></table></div>
   ${reportBlock(v)}
   ${v.error?`<p class="panel-error" role="alert">${esc(v.error)}</p>`:''}${report.runId===v.runId&&report.error?`<p class="panel-error" role="alert">${esc(report.error)}</p>`:''}</div>
  <div class="dialog-actions"><span>${isAtk(v)?'보고서는 SEC-08 공격 로그를 리전 구분 없이 파일 하나(atk-report-*.json)로 내려받습니다. 끝나지 않은 리전은 빠지니, 끝난 뒤 다시 누르세요.':'이 실행에는 SEC-08 공격 로그가 없어 받을 보고서가 없습니다.'}</span>
   <button type="button" class="cancel-button" data-run-refresh ${v.loading?'disabled':''}>상태 새로고침</button>
   <button type="button" class="subtle-button accent" data-run-ai ${v.loading||!v.runId?'disabled':''} title="이 실행의 결과를 AI 가 요약한 보고서(PDF 저장 가능)">AI 요약 보고서</button>
   <button type="button" class="primary-button" data-report-extract ${canReport?'':'disabled'}>${report.loading&&report.runId===v.runId?'추출 중…':'보고서 추출'}</button>
   <button type="button" class="cancel-button" data-run-close>닫기</button></div>`;
}
function paintRunDialog(){
 const box=$('#run-dialog');if(!box)return;
 if(!dlgOpen||!shown){if(box.open)box.close();return;}
 const body=box.querySelector('.dialog-body'),top=body?body.scrollTop:0;
 const opened=[...box.querySelectorAll('details[open]')].map(d=>d.dataset.k);
 $('#run-dialog-content').innerHTML=runDialogHtml(shown);
 opened.forEach(k=>{const d=box.querySelector(`details[data-k="${k}"]`);if(d)d.open=true;});
 const nb=box.querySelector('.dialog-body');if(nb)nb.scrollTop=top;
 if(!box.open)box.showModal();
}
function closeRunDialog(){dlgOpen=false;const box=$('#run-dialog');if(box&&box.open)box.close();}
function openRunDialog(v){shown=v;dlgOpen=true;paintRunDialog();}

function runsSection(){
 if(!runs||!runs.items.length){
  return `<section class="panel full-panel">${header('실행 이력','RUN HISTORY')}
   <div class="run-empty"><strong>기록된 실행이 없습니다</strong><span>위의 [전부 실행]을 누르면 실행 ID·유형·SEC 항목·상태가 이곳에 남고, 줄마다 [보고서]로 그 실행의 보고서를 받을 수 있습니다.</span></div></section>`;
 }
 const rows=runs.items.map(r=>{
  const secs=(r.secs&&r.secs.length)?r.secs.join(' · '):(r.type||'—');
  return `<tr><td class="run-id">${esc(r.runId||'—')}</td><td>${esc(r.title||r.type||'—')}</td><td>${esc(secs)}</td><td><span class="run-state" data-state="${esc(String(r.state||'').toLowerCase())}">${esc(r.state||'—')}</span></td><td>${format(milliseconds(r.createdAt))}</td>
   <td>${r.type==='run-all'&&r.runId?`<button type="button" class="link-button" data-run-report="${esc(r.runId)}" aria-haspopup="dialog">보고서</button>`:'<span class="muted">—</span>'}</td></tr>`;
 }).join('');
 return `<section class="panel full-panel">${header('실행 이력','RUN HISTORY')}
  <div class="table-scroll run-history"><table><caption class="sr-only">실행 이력</caption>
  <thead><tr><th>실행 ID</th><th>유형</th><th>SEC 항목</th><th>상태</th><th>접수 시각 (KST)</th><th>보고서</th></tr></thead>
  <tbody>${rows}</tbody></table></div></section>`;
}

function paint(){
 return `<section class="panel full-panel drill-workspace">${header('보안 시나리오','SCENARIOS')}
  ${environmentStrip(catalog.environment)}${runPanel()}${scenarioTable()}</section>${runsSection()}`;
}
function rerender(){const box=$('#drills');if(box)box.innerHTML=paint();if(flowId)paintFlowDialog();if(dlgOpen)paintRunDialog();}

async function refreshHistory(){try{runs=await api.drills();}catch(error){/* 이력 갱신 실패는 진행 표시를 막지 않는다 */}}
async function poll(){
 run.timer=null;
 if(!run.runId)return;
 try{
  const status=await api.runAllStatus(run.runId);
  run.items=status.items||[];
  run.skipped=status.skipped||run.skipped;
  run.done=run.items.length>0&&run.items.every(item=>TERMINAL.has(item.status));
 }catch(error){
  run.error=error.message;
  if(String(error.message||'').includes('찾을 수 없')){clearRunAllId();run.busy=false;rerender();return;}   // 실행 기록이 없다(만료 등) — 재시도해도 소용없다
 }
 if(run.done){clearRunAllId();run.busy=false;await refreshHistory();rerender();return;}
 rerender();
 if($('#drills'))run.timer=setTimeout(poll,5000);   // 다른 화면으로 가면 멈추고, 돌아오면 renderDrills 가 다시 시작한다
}
async function start(){
 if(run.busy)return;
 run.busy=true;run.error=null;run.done=false;run.items=[];run.skipped=[];run.runId=null;
 report.runId=null;report.regions=null;report.error=null;   // 새 실행이면 이전 보고서는 버린다
 rerender();openRunDialog(run);
 try{
  const result=await api.startRunAll({});
  run.runId=result.runId;saveRunAllId(result.runId);
  run.skipped=result.skipped||[];
  run.items=(result.launched||[]).map(item=>({sec:item.sec,label:null,status:'Pending'}));
  await refreshHistory();rerender();
  run.timer=setTimeout(poll,3000);
 }catch(error){run.busy=false;run.error=error.message;closeRunDialog();rerender();}
}
async function extractReport(){
 const id=shown&&shown.runId;if(!id||report.loading)return;
 report.loading=true;report.runId=id;report.regions=null;report.error=null;rerender();
 try{
  const result=await api.runAllReport(id);
  report.regions=result.regions||{};
  const readyCount=Object.values(report.regions).filter(r=>r.ready).length;
  if(readyCount>0){
   downloadJson(`atk-report-${id}.json`,{runId:id,generatedAt:new Date().toISOString(),...result});
  }else{
   report.error=Object.keys(report.regions).length?'아직 완료된 리전이 없습니다 — 공격이 끝난 뒤 다시 눌러주세요.':'이 실행에는 SEC-08 공격 로그가 없습니다.';
  }
 }catch(error){report.error=error.message;}
 report.loading=false;rerender();
}
// 이력에서 연 지난 실행: 상태를 한 번 읽어 와서 같은 팝업에 보여준다(진행 중인 실행이면 그 객체를 그대로 연다).
async function loadPast(v){
 v.loading=true;v.error=null;if(shown===v)paintRunDialog();
 try{
  const status=await api.runAllStatus(v.runId);
  v.items=status.items||[];v.skipped=status.skipped||[];
  v.done=v.items.length>0&&v.items.every(item=>TERMINAL.has(item.status));
 }catch(error){v.error=error.message;}
 v.loading=false;if(shown===v)paintRunDialog();
}
async function openPast(runId){
 if(run.runId===runId){openRunDialog(run);return;}
 if(report.runId!==runId){report.runId=null;report.regions=null;report.error=null;}
 const past={runId,items:[],skipped:[],done:false,loading:true,error:null};
 openRunDialog(past);
 await loadPast(past);
}
function refreshShown(){
 if(!shown)return;
 if(shown===run){if(run.timer){clearTimeout(run.timer);run.timer=null;}poll();}else loadPast(shown);
}
function onRunDialogClick(e){
 const box=e.currentTarget;
 if(e.target.closest('[data-run-ai]')){if(shown&&shown.runId)openReport('drill-run',{runId:shown.runId});return;}
 if(e.target===box||e.target.closest('[data-run-close]')){closeRunDialog();return;}
 if(e.target.closest('[data-run-refresh]')){refreshShown();return;}
 if(e.target.closest('[data-report-extract]')){extractReport();}
}
function onClick(e){
 if(e.target.closest('[data-run-all-start]')){start();return;}
 if(e.target.closest('[data-run-open]')){openRunDialog(run);return;}
 const past=e.target.closest('[data-run-report]');
 if(past){openPast(past.dataset.runReport);return;}
 const toggle=e.target.closest('[data-flow-toggle]');
 if(toggle){flowId=toggle.dataset.flowToggle;paintFlowDialog();}
}

// 새로고침 직후 한 번만: 저장된 runId 가 있으면 새로 시작하지 않고 그 실행 상태를 이어 본다.
function resumeRunAll(){
 if(resumed)return;resumed=true;
 const runId=loadRunAllId();if(!runId)return;
 run.runId=runId;run.busy=true;run.error=null;run.done=false;
 poll();
}
export function renderDrills(){
 const box=$('#drills');
 if(box&&!box._drillsBound){box.addEventListener('click',onClick);box._drillsBound=true;}
 const fd=$('#flow-dialog');
 if(fd&&!fd._flowBound){
  fd._flowBound=true;
  fd.addEventListener('click',e=>{if(e.target.closest('[data-flow-close]')||e.target===fd)closeFlow();});
  fd.addEventListener('cancel',e=>{e.preventDefault();closeFlow();});
 }
 const rd=$('#run-dialog');
 if(rd&&!rd._runBound){
  rd._runBound=true;
  rd.addEventListener('click',onRunDialogClick);
  rd.addEventListener('close',()=>{dlgOpen=rd.open;});   // Esc 로 닫아도 상태를 맞춘다(close 는 비동기라, 그 사이 다시 열렸으면 열린 채로 둔다)
 }
 resumeRunAll();
 return loadPanel(box,
  async()=>{const [c,r]=await Promise.all([api.drillsCatalog(),api.drills()]);catalog=c;runs=r;return {catalog:c,runs:r};},
  ()=>{
   if(run.runId&&!run.done&&!run.timer)run.timer=setTimeout(poll,0);   // 진행 중이던 실행을 이어서 갱신
   return paint();
  },'보안 시나리오');
}
