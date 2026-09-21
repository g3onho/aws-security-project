from pathlib import Path
p=Path('../frontend/static/js/app.js')
s=p.read_text(encoding='utf-8-sig')
s=s.replace("regions,sources,statuses,severityColors,threatActors,DEMO_NOW,metricsFor", "regions,sources,statuses,severityColors")
s=s.replace("state,selectEvents,api,toCSV", "state,selectEvents,api,config,summary,DEMO_NOW,metricsFor,request")
s=s.replace("?v=2.2.2", "?v=local-1")
s=s.replace("const format=(time,short=false)=>new Intl", "const format=(time,short=false)=>time==null?'데이터 없음':new Intl")
s=s.replace("else animateTo(DEFAULT_ROTATION,DEFAULT_ZOOM);}render();}", "else animateTo(DEFAULT_ROTATION,DEFAULT_ZOOM);}state.page=1;refresh();}")
s=s.replace("function table(rows,full=false){return", "function table(rows,full=false){const total=rows.length,pages=Math.max(1,Math.ceil(total/15));state.page=Math.min(state.page,pages);rows=rows.slice((state.page-1)*15,state.page*15);return")
s=s.replace("총 ${rows.length}건 · 현재 필터 적용", "총 ${total}건 · 현재 필터 적용")
s=s.replace("</div></section>`;}\nfunction responseCard", "</div><div class=\"table-pager\"><button data-page=\"prev\" ${state.page<=1?'disabled':''}>← 이전</button><span>${state.page} / ${pages}</span><button data-page=\"next\" ${state.page>=pages?'disabled':''}>다음 →</button></div></section>`;}\nfunction responseCard")
# All server strings rendered into HTML must be escaped.
for field in ['source','scenario','mode','execution','verification']:
 s=s.replace('${e.'+field+'}', '${esc(e.'+field+')}')
s=s.replace('${status}</span>','${esc(status)}</span>')
s=s.replace("<span>● 정상</span>","<span>○ 미연동</span>")
s=s.replace("HTTP /health: 데모 200", "각 서비스의 실제 상태 점검: 미연동")
s=s.replace("function visibleRows(){const rows=selectEvents();return state.view==='vulnerabilities'?rows.filter(e=>['Trivy','Inspector'].includes(e.source)):state.view==='responses'?rows.filter(e=>e.history.length>1||e.status==='승인 대기'):rows;}","function visibleRows(){return selectEvents();}")
start=s.index('function eventDialog(');end=s.index('async function refresh()',start)
s=s[:start]+r'''
let detailSerial=0,operationBusy=false,pollTimer;
async function eventDialog(id,ask=false){
 const serial=++detailSerial;activeId=id;approval=ask;
 if(!$('#event-dialog').open){lastTrigger=document.activeElement;$('#event-dialog').showModal();}
 $('#dialog-content').textContent='상세 정보를 불러오는 중…';
 try{const e=await api.detail(id);if(serial!==detailSerial||activeId!==id)return;drawDetail(e,ask);if(e.activeExecutionId)pollJob(id,e.activeExecutionId);}
 catch(error){if(serial===detailSerial){$('#dialog-content').innerHTML=`<div class="dialog-body"><p>${esc(error.message)}</p><button data-action="retry-detail">재시도</button><button data-action="close">닫기</button></div>`;}}
}
function drawDetail(e,ask=false){
 const canWrite=config.writeEnabled&&config.role==='operator'&&e.actionable;
 const running=['EXECUTING','VERIFYING'].includes(e.rawStatus);
 const value=v=>v==null?'검사 대기':esc(v)+esc(e.unit);
 let buttons='<button class="cancel-button" data-action="close">닫기</button>';
 if(canWrite&&!running&&!operationBusy){
  if(ask)buttons='<button data-action="cancel-review">돌아가기</button><button class="primary-button" data-action="confirm-approve">변경 내용 승인</button>';
  else if(e.rawStatus==='APPROVED')buttons+='<button data-action="cancel">승인 취소</button><button class="primary-button" data-action="execute">데모 조치 실행</button>';
  else if(['PENDING_VERIFICATION','VERIFICATION_FAILED'].includes(e.rawStatus))buttons+='<button class="primary-button" data-action="verify">동일 기준 재검증</button>';
  else if(['NEW','PENDING_APPROVAL','EXECUTION_FAILED'].includes(e.rawStatus))buttons+='<button class="primary-button" data-action="approve">조치 검토 및 승인</button>';
 }
 $('#dialog-content').innerHTML=`<div class="dialog-header"><div><div class="eyebrow">${esc(e.id)} / ${esc(e.scenario)}</div><h2 id="dialog-title">${esc(e.title)}</h2></div><button class="dialog-close" data-action="close" aria-label="상세 닫기">×</button></div><div class="dialog-body"><dl class="detail-meta"><div><dt>위험도</dt><dd>${badge(e)}</dd></div><div><dt>탐지 소스</dt><dd>${esc(e.source)}</dd></div><div><dt>대상 자원</dt><dd>${esc(e.resource)}</dd></div><div><dt>상태</dt><dd>${esc(e.status)}</dd></div><div><dt>승인자</dt><dd>${esc(e.approver||'미승인')}</dd></div><div><dt>발생 시각</dt><dd>${format(e.at)} KST</dd></div></dl><div class="execution-flow"><span>실행 ${esc(e.execution)}</span><span>→ 재검증 ${esc(e.verification)}</span></div>${e.sourceIp?`<section class="detail-section"><h3>공격 출발지 → 대상</h3><p>${esc(e.sourceIp)} → ${esc(e.region)}</p><p>${esc(e.geoStatus)} · ${esc(e.sourceLocation?.provenance||'좌표 없음')}</p><p>모의 IP/좌표입니다. 실제 공격자 귀속 정보가 아닙니다.</p></section>`:''}<section class="detail-section"><h3>탐지 근거</h3><p>${esc(e.evidence)}</p></section><section class="detail-section"><h3>권장 조치</h3><p>${esc(e.recommendation)}</p></section>${e.plan?`<section class="${ask?'approval-box':'detail-section'}"><h3>${ask?'승인할 변경 내용':'로컬 모의 조치 계획'}</h3><p>대상: ${esc(e.plan.target)}</p><p>변경: ${esc(e.plan.change)}</p><p>절차: ${esc(e.plan.document)} · 버전 ${esc(e.plan.version)}</p>${e.plan.imageBefore?`<p>이미지 ${esc(e.plan.imageBefore)} → ${esc(e.plan.imageAfter)}</p>`:''}<p>실제 AWS 자원은 변경되지 않습니다.</p></section>`:'<p class="muted">이 이벤트의 수동 실행은 미지원입니다. 자동 대응 이력은 조회만 가능합니다.</p>'}<section class="detail-section"><h3>Before / After · 동일 기준 재검증</h3><p>${esc(e.criterion)} · 검사 버전 ${esc(e.criterionVersion)}</p><p>같은 대상: ${esc(e.resource)}</p><div class="comparison"><div><label>BEFORE</label><strong>${value(e.before)}</strong><small>${format(e.beforeAt)} KST</small></div><div><label>AFTER · ${esc(e.verification)}</label><strong>${value(e.afterValue)}</strong><small>${format(e.afterAt)}${e.afterAt?' KST':''}</small></div></div></section><section class="detail-section"><h3>처리 이력</h3><ol class="history-list">${e.history.map(h=>`<li><time>${format(h.at)} KST</time>${esc(h.text)}</li>`).join('')}</ol></section><section class="detail-section"><button data-action="evidence">증적 12항목 보기</button><div id="evidence-content"></div></section></div><div class="dialog-actions"><span>${running?'작업 처리 중 · 창을 닫아도 계속됩니다.':'로컬 데모 · 실제 AWS 조치 없음'}</span>${buttons}</div>`;
}
function closeDialog(){clearTimeout(pollTimer);detailSerial++;$('#event-dialog').close();}
function pollJob(id,jobId){
 clearTimeout(pollTimer);
 pollTimer=setTimeout(async()=>{try{const result=await api.job(id,jobId);if(activeId!==id||!$('#event-dialog').open)return;
 const e=await api.detail(id);drawDetail(e);if(result.execution.status==='RUNNING')pollJob(id,jobId);else{await refresh();toast('작업 완료 · '+e.status);}}
 catch(error){toast(error.message);}},800);
}
async function dialogAction(action){
 if(action==='close'){closeDialog();return;}
 if(action==='approve'){approval=true;drawDetail(api.get(activeId),true);return;}
 if(action==='cancel-review'){approval=false;drawDetail(api.get(activeId));return;}
 if(action==='retry-detail'){eventDialog(activeId);return;}
 if(action==='evidence'){try{const result=await request('/api/events/'+encodeURIComponent(activeId)+'/evidence');$('#evidence-content').innerHTML=result.items.map(i=>`<p><strong>${i.no}. ${esc(i.label)}</strong><br>${esc(i.value||'데이터 없음')} <small>(${esc(i.source)})</small></p>`).join('');}catch(error){toast(error.message);}return;}
 if(operationBusy)return;
 if(['confirm-approve','cancel','execute','verify'].includes(action)){
  const id=activeId;operationBusy=true;drawDetail(api.get(id));
  try{const result=await api.change(id,action==='confirm-approve'?'approve':action);await refresh();if(activeId===id&&$('#event-dialog').open){drawDetail(await api.detail(id));if(result.execution)pollJob(id,result.execution.executionId);}toast(result.execution?'작업이 접수됐습니다.':'승인 상태를 저장했습니다.');}
  catch(error){toast(error.message);if(activeId===id)await api.detail(id);}
  finally{operationBusy=false;if(activeId===id&&$('#event-dialog').open)drawDetail(api.get(id));}
 }
}
''' +s[end:]
s=s.replace("try{await Promise.all([api.load(),mapReady?Promise.resolve():loadMap()]);render();box.hidden=true;$('#updated').textContent=`갱신 ${format(Date.now(),true)} KST`;}","try{const [loaded]=await Promise.all([api.load(),mapReady?Promise.resolve():loadMap()]);if(loaded===false)return;render();box.hidden=true;$('#updated').textContent=`갱신 ${format(summary.collectedAt,true)} KST`;$('#session-user').textContent=config.user.name+' · '+(config.role==='operator'?'조치 담당':'조회 전용');$('#worker-state').textContent=summary.health.checks.worker==='ok'?'로컬 작업 처리기 정상':'작업 처리기 중지 · 실행 대기 작업은 재시작 후 처리';}")
s=s.replace("catch(e){box.classList.add('error');", "catch(e){if(e.name==='AbortError')return;box.classList.add('error');")
s=s.replace("state[key]=e.target.value;render();", "state[key]=e.target.value;state.page=1;refresh();")
s=s.replace("state.search=e.target.value;render();", "state.search=e.target.value;state.page=1;clearTimeout(searchTimer);searchTimer=setTimeout(refresh,220);")
s=s.replace("state.endOffset=+e.target.value;render();", "state.endOffset=+e.target.value;state.page=1;clearTimeout(searchTimer);searchTimer=setTimeout(refresh,120);")
s=s.replace("state.view=view.dataset.view;render();", "state.view=view.dataset.view;state.page=1;refresh();")
s=s.replace("state.hours=+hours.dataset.hours;render();", "state.hours=+hours.dataset.hours;state.page=1;refresh();")
s=s.replace("$('#time-range').value=0;render();", "$('#time-range').value=0;state.page=1;refresh();")
s=s.replace("$('#status').value=state.status;render();", "$('#status').value=state.status;state.page=1;refresh();")
start=s.index(" if(id==='export')");end=s.index('\n});',start)
s=s[:start]+" if(id==='export')api.export().catch(e=>toast(e.message));\n if(id==='logout')api.logout().catch(e=>toast(e.message));\n const pager=e.target.closest('[data-page]');if(pager){state.page+=pager.dataset.page==='next'?1:-1;render();}\n"+s[end:]
s=s.replace("$('#status').insertAdjacentHTML('beforeend',statuses.map", "let searchTimer;\n$('#status').insertAdjacentHTML('beforeend',[...statuses,'승인됨','실행 실패'].map")
p.write_text(s,encoding='utf-8')
p=Path('../frontend/templates/index.html');s=p.read_text(encoding='utf-8-sig').replace('?v=2.2.2','?v=local-1')
s=s.replace('</head>',' <link rel="stylesheet" href="/static/css/local.css?v=local-1">\n</head>')
s=s.replace('<span class="avatar" aria-label="관제 담당자">OP</span>','<span id="session-user" class="session-user"></span><button id="logout" class="subtle-button">로그아웃</button>')
s=s.replace('<div id="content"></div>','<div id="worker-state" class="local-context" role="status"></div><div id="content"></div>')
s=s.replace('데모 환경 정상','로컬 데모 환경').replace('SECURITY CONSOLE / v2.2','LOCAL BACKEND / v0.1')
p.write_text(s,encoding='utf-8')
