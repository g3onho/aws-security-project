// 보안 시나리오: 시나리오 표가 화면의 뼈대이고, 선택 없이 [전부 실행] 한 번으로 준비된 모든 시나리오를 실행한다.
// 실행은 백엔드 POST /api/drills/run-all/start(SSM)이며 WRITE_ENABLED 가 꺼져 있으면 403 이다.
import {$,api} from '../context.js?v=ui-1';
import {esc,format,milliseconds} from '../components/format.js?v=ui-1';
import {loadPanel,header} from '../components/panel.js?v=ui-1';

const SUPPORT_COLOR={runnable:'#087a68','prep-needed':'#9d5b22','observe-only':'#00579e','design-needed':'#526e84'};
// 백엔드 DrillService.start_all 이 한 번에 실행하는 시나리오(SEC-06B 는 SEC-08 지리 공격 실행에 함께 들어 있다).
const RUN_ALL_SECS=['SEC-02','SEC-04','SEC-07','SEC-08','SEC-06B','SEC-10'];
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
 if(!RUN_ALL_SECS.includes(id))return '<span class="muted">전부 실행 대상 아님</span>';
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
function scenarioRow(s){
 const obs=s.observation==='connected'?'연결됨':'미연결';
 return `<tr><td class="drill-scenario-main"><strong>${esc(s.id)}</strong><span>${esc(s.purpose)}</span></td>
  <td class="drill-scenario-evidence"><span><b>관측</b> ${s.sources.map(esc).join(' · ')}</span><span><b>대응</b> ${esc(s.response)}</span></td>
  <td class="drill-scenario-status"><div>${supportPill(s.support,s.supportLabel)}</div><small>관측 ${obs}</small></td>
  <td class="drill-scenario-result">${resultOf(s.id)}</td></tr>`;
}
function scenarioTable(){
 return `<div class="table-scroll"><table class="drill-scenario-table"><caption class="sr-only">보안 시나리오 카탈로그</caption>
  <thead><tr><th>시나리오</th><th>확인 자료와 대응</th><th>지원 상태</th><th>실행 결과</th></tr></thead>
  <tbody>${catalog.scenarios.map(scenarioRow).join('')}</tbody></table></div>`;
}

function runPanel(){
 const env=catalog.environment||{};
 const ready=env.dataSourceConnected===true;
 const geoLine=env.webScanReady===true?'지리별 웹 공격(SEC-08/06B) 포함 · 미국·싱가포르·시드니·뭄바이·도쿄':'지리별 공격자 미배포 — SEC-08/06B 는 건너뜁니다(terraform enable_geo_attackers)';
 const elig=ready?`<div class="drill-eligibility"><span class="drill-elig-dot" style="background:#32d4be"></span>실행 가능 · ${esc(geoLine)}</div>`
  :`<div class="drill-eligibility"><span class="drill-elig-dot"></span>실행 불가 · 데이터 소스 미연결</div>`;
 const attr=ready&&!run.busy?'data-run-all-start':'disabled';
 return `<div class="drill-config"><h3>전부 실행</h3>
  <p class="muted">시나리오를 고르지 않고 준비된 모든 시나리오를 한 번에 실행합니다: SEC-02(서비스 포트·헤더), SEC-04(Trivy 이미지 CVE), SEC-07(비밀값 스캔), SEC-08/06B(DVWA·SSH 지리 공격: nmap·hydra·ZAP·sqlmap), SEC-10(서울 EC2 부하·대시보드 제외), HONEYPOT(내부 침투: 서울 공격자 EC2 → 미끼서버 SSH, 자동 차단 시연). 대상이 없는 항목은 건너뛰고 사유를 남깁니다.</p>
  ${elig}
  <div class="drill-actions"><button type="button" class="primary-button" ${attr}>${run.busy?'실행 중…':'전부 실행'}</button></div>
  ${run.error?`<p class="panel-error" role="alert">${esc(run.error)}</p>`:''}</div>`;
}

function progressSection(){
 if(!run.runId&&!run.items.length)return '';
 const rows=run.items.map(item=>{
  const state=RUN_STATUS_KO[item.status]||esc(item.status||'—');
  const out=item.output?`<details><summary>출력 보기</summary><pre class="drill-attack-output">${esc(item.output)}</pre></details>`:(item.detail?`<small class="muted">${esc(item.detail)}</small>`:'');
  return `<tr><td>${esc(item.label||item.sec||'—')}</td><td>${state}</td><td>${out}</td></tr>`;
 }).join('');
 const skipped=run.skipped.length?`<p class="muted">건너뜀: ${run.skipped.map(esc).join(', ')}</p>`:'';
 return `<section class="panel full-panel">${header('실행 진행','RUN ALL')}
  ${run.runId?`<p class="muted">실행 ID: ${esc(run.runId)}${run.done?' · 모든 항목 종료':' · 진행 중(자동 갱신)'}</p>`:''}${skipped}
  <div class="table-scroll"><table><caption class="sr-only">실행 진행</caption>
  <thead><tr><th>항목</th><th>상태</th><th>결과</th></tr></thead>
  <tbody>${rows||'<tr><td colspan="3" class="muted">실행 항목을 기다리는 중입니다.</td></tr>'}</tbody></table></div></section>`;
}

function runsSection(){
 if(!runs||!runs.items.length){
  return `<section class="panel full-panel">${header('실행 이력','RUN HISTORY')}
   <p class="muted">기록된 실행이 없습니다. [전부 실행]을 누르면 이곳에 이력이 남습니다.</p></section>`;
 }
 const rows=runs.items.map(r=>{
  const secs=(r.secs&&r.secs.length)?r.secs.join(' · '):(r.type||'—');
  return `<tr><td>${esc(r.runId||'—')}</td><td>${esc(r.title||r.type||'—')}</td><td>${esc(secs)}</td><td>${esc(r.state||'—')}</td><td>${format(milliseconds(r.createdAt))}</td></tr>`;
 }).join('');
 return `<section class="panel full-panel">${header('실행 이력','RUN HISTORY')}
  <div class="table-scroll"><table><caption class="sr-only">실행 이력</caption>
  <thead><tr><th>실행 ID</th><th>유형</th><th>SEC 항목</th><th>상태</th><th>접수 시각 (KST)</th></tr></thead>
  <tbody>${rows}</tbody></table></div></section>`;
}

function paint(){
 return `<section class="panel full-panel drill-workspace">${header('보안 시나리오','SCENARIOS')}
  ${environmentStrip(catalog.environment)}${runPanel()}${scenarioTable()}</section>${progressSection()}${runsSection()}`;
}
function rerender(){const box=$('#drills');if(box)box.innerHTML=paint();}

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
 run.busy=true;run.error=null;run.done=false;run.items=[];run.skipped=[];run.runId=null;rerender();
 try{
  const result=await api.startRunAll({});
  run.runId=result.runId;saveRunAllId(result.runId);
  run.skipped=result.skipped||[];
  run.items=(result.launched||[]).map(item=>({sec:item.sec,label:null,status:'Pending'}));
  await refreshHistory();rerender();
  run.timer=setTimeout(poll,3000);
 }catch(error){run.busy=false;run.error=error.message;rerender();}
}
function onClick(e){
 if(e.target.closest('[data-run-all-start]')){start();return;}
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
 resumeRunAll();
 return loadPanel(box,
  async()=>{const [c,r]=await Promise.all([api.drillsCatalog(),api.drills()]);catalog=c;runs=r;return {catalog:c,runs:r};},
  ()=>{
   if(run.runId&&!run.done&&!run.timer)run.timer=setTimeout(poll,0);   // 진행 중이던 실행을 이어서 갱신
   return paint();
  },'보안 시나리오');
}
