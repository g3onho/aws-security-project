// 인프라 모니터링: 호스트 카드·CPU/메모리 차트·임계치 초과 구간·CloudWatch 경보·서버 가동 상태·3계층(확인 불가).
import {state,metricsFor,servicesOf} from '../context.js?v=ui-1';
import {esc,format,formatAt,milliseconds} from '../components/format.js?v=ui-1';
import {header,empty,canvas} from '../components/panel.js?v=ui-1';
import {drawChart} from '../charts/charts.js?v=ui-2';
import {periodStops} from '../constants.js?v=ui-1';
// ── 인프라 모니터링 ────────────────────────────────────────
// 7934104(v17) 화면 — 호스트 카드 · CPU/메모리 차트 · 임계치 초과 구간 · 3계층 상태 — 을
// 표준 API(/api/metrics 시계열, /api/infra/status 구성요소)에 맞춰 되살린 것.
// 호스트 선택은 화면 안에서만 바꾼다. state.resource 를 쓰면 이벤트·지표 조회 범위까지 좁아진다.
const SERVICE_TEXT={healthy:'정상',degraded:'저하',unhealthy:'장애',unknown:'확인 불가'};
const SERVICE_COLOR={healthy:'#087a68',degraded:'#9d5b22',unhealthy:'#b42332',unknown:'#526e84'};
const periodLabel=s=>s==null?'—':s>=3600?`${s/3600}시간`:`${s/60}분`;
const pct=v=>v==null?'—':Math.round(v*10)/10+'%';
const metricKo=m=>m==='cpu'?'CPU':'메모리';
// 기간 버튼과 같은 이름(15분·1시간·1일·1주일). 목록에 없는 값만 시간·분으로 적는다.
const periodName=hours=>periodStops.find(s=>s.hours===hours)?.label||(hours<1?Math.round(hours*60)+'분':hours+'시간');
let infraHost='';
function servicePill(status){const c=SERVICE_COLOR[status]||SERVICE_COLOR.unknown;return `<span class="service-pill" style="color:${c}"><i style="background:${c}"></i>${SERVICE_TEXT[status]||esc(status)} <small>${esc(status)}</small></span>`;}
// 임계치를 넘은 연속 표본을 한 구간으로 묶는다.
function breachesOf(points,metric,limit){
 const out=[];let cur=null;
 for(const p of points){
  if(p.value!=null&&p.value>limit){cur=cur||{metric,from:p.at,to:p.at,peak:p.value,samples:0};cur.to=p.at;cur.peak=Math.max(cur.peak,p.value);cur.samples++;}
  else if(cur){out.push(cur);cur=null;}
 }
 if(cur)out.push(cur);
 return out;
}
export function hostViews(m){
 const threshold=m?.thresholds||{cpu:80,memory:80},byId=new Map();
 for(const s of m?.series||[]){
  const h=byId.get(s.resource)||{resource:s.resource,name:s.name||s.resource,cpu:[],memory:[]};
  if(s.metric==='cpu'||s.metric==='memory')h[s.metric]=s.points.map(p=>({at:milliseconds(p.timestamp),value:p.value,instanceId:p.value==null?null:(p.instanceId||s.resource)}));
  byId.set(s.resource,h);
 }
 return [...byId.values()].map(h=>{
  const stat=key=>{const v=h[key].map(p=>p.value).filter(x=>x!=null);return {now:v.length?v[v.length-1]:null,max:v.length?Math.max(...v):null,avg:v.length?v.reduce((a,b)=>a+b,0)/v.length:null,samples:v.length};};
  const firstByInstance=new Map();
  for(const point of [...h.cpu,...h.memory])if(point.instanceId)firstByInstance.set(point.instanceId,Math.min(firstByInstance.get(point.instanceId)??Infinity,point.at));
  const instanceIds=[...firstByInstance.keys()].sort((a,b)=>firstByInstance.get(a)-firstByInstance.get(b));
  const switches=instanceIds.slice(1).map(id=>({at:firstByInstance.get(id)}));
  return {...h,threshold,instanceIds,switches,stats:{cpu:stat('cpu'),memory:stat('memory')},
   breaches:[...breachesOf(h.cpu,'cpu',threshold.cpu),...breachesOf(h.memory,'memory',threshold.memory)].sort((a,b)=>a.from-b.from)};
 });
}
function selectedHost(hosts){return hosts.find(h=>h.resource===infraHost)||hosts[0];}
function hostPicker(hosts,sel){
 return `<label class="host-picker"><span>대상 호스트</span><select id="host">${hosts.map(h=>`<option value="${esc(h.resource)}"${h===sel?' selected':''}>${esc(h.name)} · ${esc(h.resource)}</option>`).join('')}</select></label>`;
}
function breachPanel(h,span){
 if(!h.breaches.length)return `<div class="context-note">선택 구간에 ${h.threshold.cpu}% 임계치를 넘은 표본이 없습니다. CPU 최대 ${pct(h.stats.cpu.max)} · 메모리 최대 ${pct(h.stats.memory.max)}.</div>`;
 return `<ul class="breach-list">${h.breaches.map(b=>`<li><span class="breach-metric" style="color:${b.metric==='cpu'?'#e7a064':'#ef777f'}">${metricKo(b.metric)}</span><span>${formatAt(b.from,span)} — ${formatAt(b.to,span)} KST</span><b>최고 ${pct(b.peak)}</b><small>표본 ${b.samples}개 · 임계치 ${h.threshold[b.metric]}%</small></li>`).join('')}</ul>`;
}
// 카드 수치는 선택 기간의 평균·최대다(마지막 표본이 아니다) — 기간 버튼을 바꾸면 함께 바뀐다.
function hostGrid(hosts,sel,label){
 const bar=(v,limit)=>`<div class="host-bar"><div class="host-bar-fill" style="width:${Math.min(100,v||0)}%;background:${v>limit?'#e7a064':'#32d4be'}"></div><i style="left:${limit}%"></i></div>`;
 const row=(name,s)=>`<div class="host-metric"><span>${name} <small>${esc(label)} 평균</small></span><b>${pct(s.avg)}</b></div><div class="host-metric host-metric-sub"><span>최대</span><span>${pct(s.max)}</span></div>`;
 return `<div class="host-grid">${hosts.map(h=>{
  const over=h.breaches.length,on=h===sel;
  return `<button data-key="host-${esc(h.resource)}" class="host-card ${on?'selected':''} ${over?'over':''}" data-host="${esc(h.resource)}" aria-pressed="${on}">
   <div class="host-card-head"><strong>${esc(h.name)}</strong><small>EC2</small></div>
   ${row('CPU',h.stats.cpu)}${bar(h.stats.cpu.avg,h.threshold.cpu)}
   ${row('메모리',h.stats.memory)}${bar(h.stats.memory.avg,h.threshold.memory)}
   <div class="host-card-foot">${over?`<span class="over-flag">임계 초과 ${over}구간</span>`:'<span>임계 초과 없음</span>'}<small>${esc(h.resource)}</small></div>
  </button>`;}).join('')}</div>`;
}
// v23: EC2 가동 상태와 3계층(Nginx·Flask·MySQL)을 나눈다. EC2 목록을 화살표로 이어 계층처럼 보이게 하지 않는다.
function serverStatus(svc,hosts){
 if(!svc)return `<div class="context-note">서버 상태를 불러오지 못했습니다. 새로고침 후에도 같으면 백엔드 /api/infra/status 응답을 확인하세요.</div>`;
 const items=svc.components||[];
 if(!items.length)return empty('조회 범위에 EC2 서버가 없습니다.');
 const nameOf=c=>hosts.find(h=>h.resource===c.resource)?.name||c.name||c.resource;
 return `<div class="table-scroll"><table class="service-table"><caption class="sr-only">서버 가동 상태</caption><thead><tr><th>서버</th><th>역할</th><th>가동 상태</th><th>근거</th><th>관측 시각</th></tr></thead><tbody>${items.map(c=>`<tr><td>${esc(nameOf(c))}<br><small class="muted">${esc(c.resource)}</small></td><td>${esc(c.role||'—')}</td><td>${servicePill(c.status)}</td><td>${esc(c.detail||'—')}<br><small class="muted">${esc(c.source||'')}</small></td><td>${format(milliseconds(c.observedAt))}</td></tr>`).join('')}</tbody></table></div>
 <div class="context-note">EC2 인스턴스 상태(running 등)입니다. 서버 안의 서비스가 응답하는지는 뜻하지 않습니다.</div>`;
}
const ALARM_TEXT={ALARM:'경보',OK:'정상',INSUFFICIENT_DATA:'데이터 부족'};
export function alarmOverviewChart(alarms){
 if(!Array.isArray(alarms)||!alarms.length)return '';
 const known=new Set(['ALARM','INSUFFICIENT_DATA','OK']);
 const isAlarm=a=>a.state==='ALARM';
 const needsCheck=a=>!isAlarm(a)&&(a.needsCheck??(a.state==='INSUFFICIENT_DATA'||!known.has(a.state)));
 // 정상은 화면에 올리지 않는다(DEC-035). 조건·상태 전체는 접힌 상세 표에서 확인한다.
 const groups=[
  ['경보','alarm',isAlarm,'지표가 기준을 넘었습니다.'],
  ['확인 필요','check',needsCheck,'CPU·메모리처럼 계속 들어와야 하는 지표가 없거나 판정할 데이터가 부족합니다.'],
 ];
 const card=([label,key,matches,hint])=>{
  const items=alarms.filter(matches);
  return `<div class="alarm-status-group ${key}"><div class="alarm-status-head"><span>${label}</span><b>${items.length}개</b></div>
   ${items.length?`<ul>${items.map(a=>`<li><strong>${esc(a.label||a.name)}</strong><small>${a.noData?'데이터 없음 · ':''}${esc(a.autoResponse?.label||(a.notifies?'SNS 알림':'대응 설정 없음'))}</small></li>`).join('')}</ul>
   <p class="alarm-status-hint">${hint}</p>`:'<p class="alarm-status-empty">해당 경보 없음</p>'}</div>`;
 };
 return `<div class="alarm-status-board" role="group" aria-label="CloudWatch 경보별 현재 상태"><div class="alarm-status-intro"><strong>확인이 필요한 경보</strong><span>전체 ${alarms.length}개 중 정상이 아닌 것만 표시 · 마지막 조회 기준</span></div>
  <div class="alarm-status-grid">${groups.map(card).join('')}</div><p>대응 표시는 설정이며 실제 실행 결과는 조치 이력에서 확인합니다.</p></div>`;
}
function alarmState(a){
 if(a.state==='OK'&&a.noData&&a.needsCheck)return '<span class="alarm-state warn" title="treat_missing_data=notBreaching — 계속 들어와야 하는 지표인데 데이터가 없어 정상으로 처리됨">확인 필요 · 데이터 없음</span>';
 if(a.state==='OK'&&a.noData)return '<span class="alarm-state ok" title="사건이 있어야 지표가 생기는 경보 — 사건이 없어 데이터가 없는 것이 평소 상태">정상 · 사건 없음</span>';
 return `<span class="alarm-state ${a.state==='ALARM'?'bad':a.state==='OK'?'ok':'warn'}">${ALARM_TEXT[a.state]||esc(a.state)}</span>`;
}
const compareKo={GreaterThanThreshold:'>',GreaterThanOrEqualToThreshold:'≥',LessThanThreshold:'<',LessThanOrEqualToThreshold:'≤'};
function alarmTable(svc){
 const alarms=svc?.alarms;
 if(alarms==null)return `<div class="context-note">CloudWatch 경보 정보를 불러오지 못했거나 대시보드에 알람 이름 접두어(NAME_PREFIX)가 설정되지 않았습니다.</div>`;
 if(!alarms.length)return empty('조회 범위에 CloudWatch 경보가 없습니다.');
 return `<details class="alarm-details"><summary>경보 조건·대응 설정 자세히 보기</summary><div class="table-scroll"><table class="alarm-table"><caption class="sr-only">CloudWatch 경보</caption><thead><tr><th>상태</th><th>경보</th><th>조건</th><th>자동 대응</th><th>마지막 변경 (KST)</th></tr></thead><tbody>${alarms.map(a=>`<tr><td>${alarmState(a)}</td><td>${esc(a.label||a.name)}${a.scenario?` <span class="scenario-tag">${esc(a.scenario)}</span>`:''}<br><small class="muted">${esc(a.name)}</small></td><td>${esc(a.metric||'')} ${esc(compareKo[a.comparison]||a.comparison||'')} ${esc(a.threshold??'')}<br><small class="muted">${a.periodSeconds?`${Math.round(a.periodSeconds/60)}분`:''}${a.evaluationPeriods?` × ${a.evaluationPeriods}회`:''}${a.notifies?' · SNS 알림':''}</small></td><td>${a.autoResponse?`<span class="auto-chip ${a.autoResponse.mode==='auto'?'ok':a.autoResponse.mode==='dry-run'?'muted':'warn'}" title="${esc(a.autoResponse.detail||'')}">${esc(a.autoResponse.label)}</span>`:`<span class="muted">${a.notifies?'SNS 알림':'대응 설정 없음'}</span>`}</td><td>${format(milliseconds(a.updatedAt))}</td></tr>`).join('')}</tbody></table></div></details>`;
}
function infraSections(svc,hosts){
 const alarms=svc?.alarms,firing=(alarms||[]).filter(a=>a.state==='ALARM').length;
 return `<section class="panel full-panel">${header('CloudWatch 경보',alarms==null?'정보 없음':`${alarms.length}개 · 경보 ${firing}개`)}${alarmOverviewChart(alarms)}${alarmTable(svc)}</section>
 <section class="panel full-panel">${header('서버 가동 상태',svc?`EC2 ${(svc.components||[]).length}대`:'조회 실패')}${serverStatus(svc,hosts)}</section>`;
}
export function infrastructure(){
 const m=metricsFor(),svc=servicesOf(),span=state.hours*3600000,hosts=hostViews(m);
 if(!hosts.length)return `<div class="view-intro"><span>CloudWatch · CPU / 메모리</span></div><section class="panel">${header('EC2 자원 사용률','대상 없음')}${empty('조회 기간에 수집된 EC2 지표가 없습니다.')}</section>
  ${infraSections(svc,hosts)}`;
 const label=periodName(state.hours),h=selectedHost(hosts),overCpu=h.breaches.filter(b=>b.metric==='cpu').length,overMem=h.breaches.length-overCpu;
 const samples=hosts.reduce((a,x)=>a+x.stats.cpu.samples,0);
 return `<div class="view-intro"><span>운영 중인 서버 ${hosts.length}대 · ${periodLabel(m.periodSeconds)} 평균 · 표본 ${samples}개</span><span>최근 ${esc(label)} · 경보 임계치 <strong class="mint">${h.threshold.cpu}%</strong></span></div>
 <section class="panel">${header('운영 중인 서버',`${hosts.length}대 · 카드를 누르면 아래 상세 차트가 바뀝니다`)}${hostGrid(hosts,h,label)}
  <div class="context-note">리전에서 조회된 EC2 전체입니다. 카드 수치는 선택 기간(최근 ${esc(label)})의 5분 평균 표본을 다시 평균·최대로 낸 값이며, 기간 버튼을 바꾸면 함께 바뀝니다. 표본은 5분 평균입니다(CPU 는 EC2 기본 모니터링 5분 간격). 메모리는 CloudWatch Agent 가 설치된 호스트만 수집됩니다.</div></section>
 <div class="infrastructure-grid">
  <section class="panel">${header(`상세 · ${esc(h.name)}`,hostPicker(hosts,h))}<div class="metric-large">${canvas('metrics-chart',`CPU ${pct(h.stats.cpu.now)}, 메모리 ${pct(h.stats.memory.now)}, 임계치 ${h.threshold.cpu}%`)}</div>
   <div class="metric-stats"><div><span>CPU 최근 표본</span><b>${pct(h.stats.cpu.now)}</b></div><div><span>CPU 최대 / 평균</span><b>${pct(h.stats.cpu.max)} / ${pct(h.stats.cpu.avg)}</b></div><div><span>메모리 최근 표본</span><b>${pct(h.stats.memory.now)}</b></div><div><span>메모리 최대 / 평균</span><b>${pct(h.stats.memory.max)} / ${pct(h.stats.memory.avg)}</b></div></div>
   <div class="context-note">${esc(h.resource)} — x축은 선택 기간 전체를 표시합니다. 최근 수치는 그 기간의 마지막 수집 표본입니다. 빈 구간에는 수집된 지표가 없습니다.${h.instanceIds.length>1?` 이전 인스턴스 ${h.instanceIds.length-1}개의 CloudWatch 기록을 연결했습니다.`:''}</div></section>
  <section class="panel">${header('임계치 초과 구간',`CPU ${overCpu}회 / 메모리 ${overMem}회`)}${breachPanel(h,span)}
   <div class="context-note">CloudWatch 알람 조건은 5분 평균 2회 연속 초과입니다. 위 구간은 화면 표본 기준이라 알람 건수와 1:1이 아닙니다.</div></section>
 </div>${infraSections(svc,hosts)}`;
}
// x축 눈금(DEC-036). 표본은 5분 평균이라 모든 기간에서 전부 그리고, 눈금만 KST 정시에 맞춰 둔다.
// 15분=5분 · 1시간=10분 · 1일=2시간 · 1주일=6시간 간격. 1시간 이상 간격은 자정에 날짜(M/D)를 쓴다.
const KST_MS=9*3600000,MIN_MS=60000;
export function tickStepMs(span){
 if(span<=15*MIN_MS)return 5*MIN_MS;
 if(span<=60*MIN_MS)return 10*MIN_MS;
 if(span<=24*60*MIN_MS)return 2*60*MIN_MS;
 return 6*60*MIN_MS;
}
export function alignedTicks(from,to,stepMs){
 const out=[];
 for(let t=Math.ceil((from+KST_MS)/stepMs)*stepMs-KST_MS;t<=to;t+=stepMs)out.push({value:t});
 return out;
}
const kst=value=>new Date(value+KST_MS);
const isKstMidnight=value=>kst(value).getUTCHours()===0&&kst(value).getUTCMinutes()===0;
const two=n=>String(n).padStart(2,'0');
const tickLabel=stepMs=>value=>{
 const d=kst(value);
 if(stepMs<60*MIN_MS)return `${two(d.getUTCHours())}:${two(d.getUTCMinutes())}`;
 return isKstMidnight(value)?`${d.getUTCMonth()+1}/${d.getUTCDate()}`:`${two(d.getUTCHours())}시`;
};
export function xAxisOptions(from,to,span){
 const step=tickStepMs(span);
 return {type:'linear',min:from,max:to,afterBuildTicks:axis=>{axis.ticks=alignedTicks(axis.min,axis.max,step);},
  grid:{color:ctx=>step>=60*MIN_MS&&isKstMidnight(ctx.tick?.value)?'rgba(120,140,160,.45)':'rgba(120,140,160,.14)'},
  ticks:{color:'#62798c',autoSkip:false,maxRotation:0,font:{size:10},callback:tickLabel(step)}};
}
// 5분 표본(v20.5)은 1주일에 2,016개라 그대로 그린다. 그보다 많아지면(집계 간격을 줄일 때) 구간 최댓값으로
// 묶어 그린다(임계치 초과가 평균에 묻히지 않게). 통계·초과 구간 계산은 원본 표본 그대로다.
const CHART_POINTS=2100;
const bucketMax=values=>{const seen=values.filter(v=>v!=null);return seen.length?Math.max(...seen):null;};
export function thinSeries(points,cpu,mem,limit=CHART_POINTS){
 if(points.length<=limit)return {points,cpu,mem};
 const step=Math.ceil(points.length/limit),out={points:[],cpu:[],mem:[]};
 for(let i=0;i<points.length;i+=step){out.points.push(points[i]);out.cpu.push(bucketMax(cpu.slice(i,i+step)));out.mem.push(bucketMax(mem.slice(i,i+step)));}
 return out;
}
export function drawInfrastructureChart(){
 const metric=metricsFor(),hosts=hostViews(metric);if(!hosts.length)return;
 const h=selectedHost(hosts),span=state.hours*3600000;
 const times=[...new Set([...h.cpu,...h.memory].map(p=>p.at))].sort((a,b)=>a-b);
 const periodMs=(metric.periodSeconds||300)*1000,all=[];
 for(let i=0;i<times.length;i++){
  if(i&&times[i]-times[i-1]>periodMs*1.5)all.push({at:times[i-1]+periodMs});
  all.push({at:times[i]});
 }
 const memAt=new Map(h.memory.map(p=>[p.at,p.value])),cpuAt=new Map(h.cpu.map(p=>[p.at,p.value])),t=h.threshold;
 const {points,cpu,mem}=thinSeries(all,all.map(p=>cpuAt.get(p.at)??null),all.map(p=>memAt.get(p.at)??null));
 const xy=values=>points.map((p,i)=>({x:p.at,y:values[i]}));
 const from=metric.rangeFrom??Date.now()-span,to=metric.rangeTo??from+span;
 drawChart('metrics-chart','line',{datasets:[
  {label:'CPU %',data:xy(cpu),borderColor:'#00579e',tension:.3,borderWidth:2,spanGaps:false,
   pointRadius:cpu.map(v=>v>t.cpu?3.5:0),pointBackgroundColor:cpu.map(v=>v>t.cpu?'#a76629':'#00579e')},
  {label:'메모리 %',data:xy(mem),borderColor:'#258474',tension:.3,borderWidth:2,spanGaps:false,
   pointRadius:mem.map(v=>v>t.memory?3.5:0),pointBackgroundColor:mem.map(v=>v>t.memory?'#b42332':'#258474')},
  {label:`${t.cpu}% 임계치`,data:[{x:from,y:t.cpu},{x:to,y:t.cpu}],borderColor:'#a76629',borderDash:[5,5],pointRadius:0,borderWidth:1},
  ]},
  {plugins:{legend:{display:true,labels:{color:'#526e84',boxWidth:12}}},scales:{y:{min:0,max:100,ticks:{color:'#62798c'}},x:xAxisOptions(from,to,span)}});
}
// 호스트 선택은 화면 안에서만(조회 범위를 바꾸지 않는다). 바뀌었으면 true.
export function selectHost(id){if(infraHost===id)return false;infraHost=id;return true;}
