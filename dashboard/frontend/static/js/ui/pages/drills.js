// 공격·대응 실습(1차): 실행 유형을 고르면 그 유형 전용 설정·정보·연결 시나리오를 보여준다.
// 조회 전용이다. 선택은 클라이언트 상태이며 실제 공격·부하 실행 경로는 없다('시작' 비활성).
import {$,api} from '../context.js?v=ui-1';
import {esc,format,milliseconds} from '../components/format.js?v=ui-1';
import {loadPanel,header} from '../components/panel.js?v=ui-1';

const SUPPORT_COLOR={runnable:'#32d4be','prep-needed':'#d8ca78','observe-only':'#85b1d5','design-needed':'#8fa295'};
const KIND_KO={attack:'웹 공격 검증',scenario:'목적별 검증(단계 포함)',load:'부하 시험 · 운영 경보 검증'};
const TYPE_NAME={'web-scan':'웹 보안 검사','sec-scenario':'보안 시나리오','load':'부하 시험'};
const typeNames=ids=>ids.length?ids.map(i=>TYPE_NAME[i]||i).join(', '):'조회 전용';
const FLOW=['실행 주체','시험 대상','관측 원천','탐지','조치','재검증'];
const START_BLOCK={'web-scan':'ZAP 실행 경로 준비 중 (3차)','load':'부하 실행 경로 준비 중 (2차)','sec-scenario':'선택한 시나리오의 실행 경로 미연결'};
// 유형별 정보(관측 원천은 카탈로그의 type.sources 를 쓰고, 대응·주의만 여기서 보강).
const TYPE_INFO={
 'web-scan':{response:'수동 · WAF 규칙 검토, Nginx 강화(SEC-02)',
  cautions:['검사 실행 성공은 공격 성공·침해 확정이 아니다.','HTTP 403만으로 WAF 차단을 단정하지 않는다.','DVWA와 서비스 웹(Nginx–Flask–MySQL)은 별개 대상이다.','ZAP 송신 기록과 대상 측 수신·처리 증거를 구분한다.']},
 'load':{response:'CPU·메모리 초과 자동조치는 없음(재부팅·프로세스 종료·증설을 가정하지 않음).',
  cautions:['부하로 인한 사용률 상승 자체는 침해가 아니다.','목표 부하와 실측값을 구분한다.','알람은 5분 평균 × 2회 — 최소 10분 지속해야 전이한다.','메모리 지표 결측을 0%로 표기하지 않는다.','중단 요청 접수와 실제 부하 종료 확인은 다르다.']},
 'sec-scenario':{response:'시나리오별 상이(자동/수동).',
  cautions:['전체 시나리오가 즉시 실행 가능하다고 가정하지 않는다.','실행 경로가 없는 항목은 준비 필요·조회 전용·설계 필요로 구분한다.']},
};

let catalog=null,runs=null;
const sel={typeId:null,target:null,scenario:null};
// 웹보안검사 실행 상태(클라이언트). runId 로 상태를 폴링한다.
const webRun={runId:null,items:[],skipped:[],busy:false,error:null,timer:null,done:false};

function supportPill(support,label){
 const c=SUPPORT_COLOR[support]||SUPPORT_COLOR['design-needed'];
 return `<span class="service-pill" style="color:${c}"><i style="background:${c}"></i>${esc(label)} <small>${esc(support)}</small></span>`;
}
const currentType=()=>catalog?.types.find(t=>t.id===sel.typeId)||catalog?.types[0]||null;
const currentScenario=()=>catalog?.scenarios.find(s=>s.id===sel.scenario)||null;

function environmentRow(env){
 const conn=env.dataSourceConnected?'연결됨':'미연결';
 const iso=env.isolationVerified==='unknown'?'확인 불가':esc(env.isolationVerified);
 return `<dl class="drill-env">
  <div><dt>실행 모드</dt><dd>${env.executionMode==='live'?'실제 실행':'데모 재생'}</dd></div>
  <div><dt>리전</dt><dd>${esc(env.region||'—')}</dd></div>
  <div><dt>데이터 소스</dt><dd>${conn} <small>${esc(env.providerState||'')}</small></dd></div>
  <div><dt>격리 환경</dt><dd>${iso}</dd></div>
 </dl>`;
}
function flowStrip(type){
 const strip=`<ol class="drill-flow">${FLOW.map((step,i)=>
  `<li><span class="drill-flow-dot" aria-hidden="true">○</span>${esc(step)}${i<FLOW.length-1?'<span class="drill-flow-arrow" aria-hidden="true">→</span>':''}</li>`).join('')}</ol>`;
 return strip+(type?`<p class="muted">선택한 유형의 관측 원천: ${type.sources.map(esc).join(' · ')}</p>`:'');
}
function typeCard(t){
 const active=t.id===sel.typeId?' active':'';
 const variants=(t.variants||[]).length
  ?`<ul class="drill-variants">${t.variants.map(v=>`<li><span>${esc(v.name)}</span>${v.note?`<small>${esc(v.note)}</small>`:''}</li>`).join('')}</ul>`:'';
 return `<div class="drill-type${active}" role="button" tabindex="0" aria-pressed="${t.id===sel.typeId}" data-drill-type="${esc(t.id)}">
  <h4>${esc(t.name)} <small>${esc(t.tool)}</small></h4>
  <p class="muted">${esc(KIND_KO[t.kind]||t.kind)}</p>
  ${variants}</div>`;
}

// 왼쪽: 선택한 유형의 실행 설정과 실행 가능 여부.
function configPanel(){
 const type=currentType();if(!type)return '';
 let picker='',reason=START_BLOCK[type.id]||'실행 경로 미연결';
 if(type.id==='sec-scenario'){
  const options=catalog.scenarios.map(s=>`<option value="${esc(s.id)}"${s.id===sel.scenario?' selected':''}>${esc(s.id)} · ${esc(s.purpose)}</option>`).join('');
  picker=`<label class="drill-field"><span>시나리오</span><select data-drill-scenario><option value="">시나리오 선택…</option>${options}</select></label>`;
  const sc=currentScenario();
  if(sc){
   reason=sc.support==='observe-only'?'조회 전용 · 실행 없이 관측만':'준비 필요 · 실행 경로 미연결';
   picker+=`<div class="drill-derived"><p><b>대응</b> ${esc(sc.response)}</p><p><b>관측 원천</b> ${sc.sources.map(esc).join(' · ')}</p><p><b>지원 상태</b> ${supportPill(sc.support,sc.supportLabel)}</p>${sc.note?`<p class="muted">${esc(sc.note)}</p>`:''}</div>`;
  }
 }else{
  const variants=type.variants||[];
  const targetLabel=type.id==='load'?'부하 종류':'대상';
  picker=`<div class="drill-field"><span>${targetLabel}</span><div class="drill-target-group">${
   variants.map(v=>`<button type="button" class="drill-target${v.id===sel.target?' active':''}" data-drill-target="${esc(v.id)}">${esc(v.name)}</button>`).join('')}</div></div>`;
  if(type.id==='load'){
   picker+=`<label class="drill-field"><span>대상 인스턴스</span><select disabled><option>미연결 — 대상 목록 없음</option></select></label>`;
   picker+=`<label class="drill-field"><span>강도·지속</span><select data-drill-profile><option>목표 85% · 15분</option><option>목표 90% · 20분</option></select></label>`;
   picker+=`<p class="muted">기본 수치는 예시이며 운영 정책이 아닙니다.</p>`;
  }else{
   picker+=`<label class="drill-field"><span>검사 프로필</span><select data-drill-profile><option>기본 스캔</option><option>전체 스캔</option></select></label>`;
   picker+=`<p class="muted">등록·승인된 웹 대상에서만 선택합니다.</p>`;
  }
 }
 // 웹보안검사만 실제 실행 경로가 연결돼 있다(지리별 공격자 → SSM). 준비되면 [시작] 활성화.
 if(type.id==='web-scan'){
  const geoReady=catalog?.environment?.webScanReady===true;
  const ready=catalog?.environment?.dataSourceConnected===true;  // 서울 SEC-02/07/10 은 geo 없이도 실행
  picker+=`<label class="drill-field"><span>SSH 계정</span><input type="text" data-web-ssh-user value="victim" ${webRun.busy?'disabled':''}></label>`;
  const startAttr=ready&&!webRun.busy?'data-run-all-start':'disabled';
  const label=webRun.busy?'실행 중…':'전부 실행';
  const geoLine=geoReady?'지리별 웹 공격(SEC-08/06B) 포함 · 미국·싱가포르·시드니·뭄바이·도쿄'
                        :'지리별 공격자 미배포 — SEC-08/06B 는 건너뜁니다(terraform enable_geo_attackers)';
  const elig=ready?`<div class="drill-eligibility"><span class="drill-elig-dot" style="background:#32d4be"></span>실행 가능 · ${esc(geoLine)}</div>`
                  :`<div class="drill-eligibility"><span class="drill-elig-dot"></span>실행 불가 · 데이터 소스 미연결</div>`;
  return `<div class="drill-config"><h3>실행 설정 — 전부 실행</h3>${picker}${elig}
   <div class="drill-actions">
    <button type="button" class="primary-button" ${startAttr}>${esc(label)}</button></div>
   ${webRun.error?`<p class="panel-error" role="alert">${esc(webRun.error)}</p>`:''}
   <p class="muted">한 번에 실행: SEC-02(서비스 포트·헤더), SEC-04(Trivy 이미지 CVE), SEC-07(비밀값 스캔), SEC-08/06B(DVWA·SSH 지리 공격: nmap·hydra·ZAP·sqlmap), SEC-10(서울 EC2 부하·대시보드 제외). 아래 진행에 항목별 상태가 표시됩니다.</p></div>`;
 }
 return `<div class="drill-config"><h3>실행 설정 — ${esc(type.name)}</h3>${picker}
  <div class="drill-eligibility"><span class="drill-elig-dot"></span>실행 불가 · ${esc(reason)}</div>
  <div class="drill-actions">
   <button type="button" class="primary-button" disabled title="1차 범위: 실행 경로가 연결되지 않았습니다">시작 (준비 중)</button>
   <button type="button" class="cancel-button" disabled hidden>중단</button></div>
  <p class="muted">선택·확인은 지금 동작합니다. 실제 실행·중단은 실행 공급자 연결(2·3차) 후 활성화됩니다.</p></div>`;
}

const WEB_STATUS_KO={Pending:'대기',InProgress:'실행 중',Delayed:'지연',Success:'완료',Cancelled:'취소',
 TimedOut:'시간초과',Failed:'실패',Cancelling:'취소 중',Unknown:'알 수 없음'};
// 실행 진행 패널: 리전이 아니라 SEC 항목(예: 'SEC-10 · docker-host')으로 표기한다.
function webRunSection(){
 if(!webRun.runId&&!webRun.items.length)return '';
 const rows=webRun.items.map(r=>{
  const st=WEB_STATUS_KO[r.status]||esc(r.status||'—');
  const out=r.output?`<details><summary>출력 보기</summary><pre class="drill-attack-output">${esc(r.output)}</pre></details>`:(r.detail?`<small class="muted">${esc(r.detail)}</small>`:'');
  return `<tr><td>${esc(r.label||r.sec||'—')}</td><td>${st}</td><td>${out}</td></tr>`;
 }).join('');
 const skip=webRun.skipped&&webRun.skipped.length?`<p class="muted">건너뜀: ${webRun.skipped.map(esc).join(', ')}</p>`:'';
 return `<section class="panel full-panel">${header('실행 진행','DRILL RUN')}
  ${webRun.runId?`<p class="muted">실행 ID: ${esc(webRun.runId)}${webRun.done?' · 모든 항목 종료':' · 진행 중(자동 갱신)'}</p>`:''}${skip}
  <div class="table-scroll"><table><caption class="sr-only">실행 진행</caption>
  <thead><tr><th>항목</th><th>상태</th><th>결과</th></tr></thead>
  <tbody>${rows||'<tr><td colspan="3" class="muted">전부 실행을 누르면 항목별 진행이 표시됩니다.</td></tr>'}</tbody></table></div></section>`;
}

// 오른쪽: 유형 전용 정보를 라벨/값 2열로 정리(가독성).
function metaRow(label,valueHtml){return `<div class="drill-meta-row"><span class="drill-meta-label">${esc(label)}</span><div class="drill-meta-val">${valueHtml}</div></div>`;}
function typeInfo(type){
 const info=TYPE_INFO[type.id]||{response:'',cautions:[]};
 const chips=type.sources.map(s=>`<span class="drill-chip">${esc(s)}</span>`).join('');
 const cautions=`<ul class="drill-caution">${info.cautions.map(c=>`<li>${esc(c)}</li>`).join('')}</ul>`;
 return `<div class="drill-info">
  ${metaRow('관측 원천',chips+'<span class="drill-hint">서로 다른 자료로 취급</span>')}
  ${metaRow('연결된 대응',`<span>${esc(info.response)}</span>`)}
  ${metaRow('주의',cautions)}</div>`;
}
function legendInfo(){
 const rows=Object.entries(catalog.supportLegend).map(([k,v])=>`<div class="drill-legend-row"><span class="drill-legend-dot" style="background:${SUPPORT_COLOR[k]||'#8fa295'}"></span><b>${esc(v)}</b><small class="muted">${esc(k)}</small></div>`).join('');
 return `<div class="drill-info">
  ${metaRow('지원 상태',`<div class="drill-legend">${rows}</div>`)}
  ${metaRow('안내',`<span class="muted">분류는 설계 기준이며 즉시 실행 가능 여부의 승인이 아닙니다.</span>`)}</div>`;
}

function scenarioRow(s,showType){
 const obs=s.observation==='connected'?'연결됨':'미연결';
 const typeCell=showType?`<td>${esc(typeNames(s.types))}</td>`:'';
 return `<tr><td>${esc(s.id)}</td><td>${esc(s.purpose)}</td>${typeCell}
  <td>${s.sources.map(esc).join(' · ')}</td><td>${esc(s.response)}</td>
  <td>${supportPill(s.support,s.supportLabel)}</td><td>${obs}</td></tr>`;
}
function scenarioTable(list,caption,showType){
 if(!list.length)return '<p class="muted">이 유형에 연결된 시나리오가 없습니다.</p>';
 return `<div class="table-scroll"><table><caption class="sr-only">${esc(caption)}</caption>
  <thead><tr><th>ID</th><th>목적</th>${showType?'<th>실행 유형</th>':''}<th>관측 원천</th><th>대응</th><th>지원 상태</th><th>관측</th></tr></thead>
  <tbody>${list.map(s=>scenarioRow(s,showType)).join('')}</tbody></table></div>`;
}
function detailSection(){
 const type=currentType();if(!type)return '';
 const isScenario=type.id==='sec-scenario';
 const right=isScenario?legendInfo():typeInfo(type);
 // 전체 시나리오 카탈로그는 '보안 시나리오' 유형에서만 보여준다(웹·부하는 제외).
 const related=isScenario
  ?`<div class="drill-related"><div class="panel-subhead">보안 시나리오 카탈로그 (전체)</div>${scenarioTable(catalog.scenarios,'보안 시나리오 카탈로그',true)}</div>`
  :'';
 const attackRun=type.id==='web-scan'?webRunSection():'';
 return `<section class="panel full-panel">${header('선택한 유형 · '+esc(type.name),esc(type.tool))}
  <div class="drill-detail">${configPanel()}${right}</div>${related}</section>${attackRun}`;
}
function runsSection(){
 if(!runs||!runs.items.length){
  return `<section class="panel full-panel">${header('실행 이력','RUN HISTORY')}
   <p class="muted">기록된 실습 실행이 없습니다. 실제 실행·부하·웹 검사 경로는 후속 단계에서 연결됩니다(1차 범위: 관측·구조).</p></section>`;
 }
 const rows=runs.items.map(r=>{
   const secs=(r.secs&&r.secs.length)?r.secs.join(' · '):(r.type||'—');  // 리전 대신 SEC 항목으로 표기
   return `<tr><td>${esc(r.runId||'—')}</td><td>${esc(r.title||r.type||'—')}</td><td>${esc(secs)}</td><td>${esc(r.state||'—')}</td><td>${format(milliseconds(r.createdAt))}</td></tr>`;
  }).join('');
 return `<section class="panel full-panel">${header('실행 이력','RUN HISTORY')}
  <div class="table-scroll"><table><caption class="sr-only">실습 실행 이력</caption>
  <thead><tr><th>실행 ID</th><th>유형</th><th>SEC 항목</th><th>상태</th><th>접수 시각 (KST)</th></tr></thead>
  <tbody>${rows}</tbody></table></div></section>`;
}

function paint(){
 const c=catalog,warn=[];
 if(!c.environment.dataSourceConnected)warn.push('데이터 소스 미연결 — 관측 원천 조회는 준비되면 표시됩니다. 미연결을 0건이나 정상으로 표기하지 않습니다.');
 const notice=warn.map(w=>`<p class="panel-error" role="status">${esc(w)}</p>`).join('');
 return notice+
  `<div class="view-intro"><span>모의 공격과 부하 시험을 실행하고, 탐지부터 대응·재검증까지 확인합니다. 현재 화면은 1차(관측·구조)로 선택·확인은 동작하지만 실제 실행 경로는 연결하지 않았습니다.</span></div>`+
  `<section class="panel full-panel">${header('실행 환경','ENVIRONMENT')}${environmentRow(c.environment)}${flowStrip(currentType())}</section>`+
  `<section class="panel full-panel">${header('실행 유형 선택','DRILL TYPES')}
   <p class="muted">카드를 클릭하면 아래에 그 유형 전용 설정·정보·연결 시나리오가 표시됩니다. CPU·메모리 사용률 상승 자체는 침해가 아니라 부하 시험으로 표기합니다.</p>
   <div class="drill-types">${c.types.map(typeCard).join('')}</div></section>`+
  detailSection()+
  runsSection();
}

function rerender(){const box=$('#drills');if(box)box.innerHTML=paint();}
function pickType(id){if(!catalog?.types.some(t=>t.id===id))return;sel.typeId=id;sel.target=null;sel.scenario=null;rerender();}

const TERMINAL=new Set(['Success','Cancelled','TimedOut','Failed']);
async function pollRunAll(){
 if(!webRun.runId)return;
 try{
  const status=await api.runAllStatus(webRun.runId);
  webRun.items=status.items||[];
  webRun.skipped=status.skipped||webRun.skipped;
  webRun.done=webRun.items.length>0&&webRun.items.every(r=>TERMINAL.has(r.status));
 }catch(error){webRun.error=error.message;}
 rerender();
 if(webRun.done){webRun.busy=false;webRun.timer=null;rerender();return;}
 webRun.timer=setTimeout(pollRunAll,5000);
}
async function startRunAll(){
 if(webRun.busy)return;
 const user=($('[data-web-ssh-user]')?.value||'victim').trim();
 webRun.busy=true;webRun.error=null;webRun.done=false;webRun.items=[];webRun.skipped=[];webRun.runId=null;rerender();
 try{
  const result=await api.startRunAll({sshUser:user});
  webRun.runId=result.runId;
  webRun.skipped=result.skipped||[];
  webRun.items=(result.launched||[]).map(l=>({sec:l.sec,label:null,status:'Pending'}));
  rerender();
  webRun.timer=setTimeout(pollRunAll,3000);
 }catch(error){webRun.busy=false;webRun.error=error.message;rerender();}
}
function onClick(e){
 const type=e.target.closest('[data-drill-type]');if(type){pickType(type.dataset.drillType);return;}
 const target=e.target.closest('[data-drill-target]');if(target){sel.target=target.dataset.drillTarget;rerender();return;}
 if(e.target.closest('[data-run-all-start]')){startRunAll();return;}
}
function onKeydown(e){
 const type=e.target.closest('[data-drill-type]');
 if(type&&(e.key==='Enter'||e.key===' ')){e.preventDefault();pickType(type.dataset.drillType);}
}
function onChange(e){
 const scenario=e.target.closest('[data-drill-scenario]');if(scenario){sel.scenario=scenario.value||null;rerender();}
}

export function renderDrills(){
 const box=$('#drills');
 if(box&&!box._drillsBound){box.addEventListener('click',onClick);box.addEventListener('keydown',onKeydown);box.addEventListener('change',onChange);box._drillsBound=true;}
 return loadPanel(box,
  async()=>{const [c,r]=await Promise.all([api.drillsCatalog(),api.drills()]);catalog=c;runs=r;if(!sel.typeId)sel.typeId=c.types[0]?.id||null;return {catalog:c,runs:r};},
  ()=>paint(),'공격·대응 실습');
}
