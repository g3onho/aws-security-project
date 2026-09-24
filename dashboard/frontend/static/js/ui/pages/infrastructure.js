// 인프라 모니터링: 호스트 카드·CPU/메모리 차트·임계치 초과 구간·3계층 상태. PR-6 이 고칠 곳.
import {state,metricsFor,servicesOf} from '../context.js?v=ui-1';
import {esc,format,formatAt,milliseconds} from '../components/format.js?v=ui-1';
import {header,empty,canvas} from '../components/panel.js?v=ui-1';
import {drawChart} from '../charts/charts.js?v=ui-1';
// ── 인프라 모니터링 ────────────────────────────────────────
// 7934104(v17) 화면 — 호스트 카드 · CPU/메모리 차트 · 임계치 초과 구간 · 3계층 상태 — 을
// 표준 API(/api/metrics 시계열, /api/infra/status 구성요소)에 맞춰 되살린 것.
// 호스트 선택은 화면 안에서만 바꾼다. state.resource 를 쓰면 이벤트·지표 조회 범위까지 좁아진다.
const SERVICE_TEXT={healthy:'정상',degraded:'저하',unhealthy:'장애',unknown:'확인 불가'};
const SERVICE_COLOR={healthy:'#32d4be',degraded:'#d8ca78',unhealthy:'#ef777f',unknown:'#8fa295'};
const periodLabel=s=>s==null?'—':s>=3600?`${s/3600}시간`:`${s/60}분`;
const pct=v=>v==null?'—':Math.round(v*10)/10+'%';
const metricKo=m=>m==='cpu'?'CPU':'메모리';
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
  if(s.metric==='cpu'||s.metric==='memory')h[s.metric]=s.points.map(p=>({at:milliseconds(p.timestamp),value:p.value}));
  byId.set(s.resource,h);
 }
 return [...byId.values()].map(h=>{
  const stat=key=>{const v=h[key].map(p=>p.value).filter(x=>x!=null);return {now:v.length?v[v.length-1]:null,max:v.length?Math.max(...v):null,avg:v.length?v.reduce((a,b)=>a+b,0)/v.length:null,samples:v.length};};
  return {...h,threshold,stats:{cpu:stat('cpu'),memory:stat('memory')},
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
function hostGrid(hosts,sel){
 const bar=(v,limit)=>`<div class="host-bar"><div class="host-bar-fill" style="width:${Math.min(100,v||0)}%;background:${v>limit?'#e7a064':'#32d4be'}"></div><i style="left:${limit}%"></i></div>`;
 return `<div class="host-grid">${hosts.map(h=>{
  const over=h.breaches.length,on=h===sel;
  return `<button data-key="host-${esc(h.resource)}" class="host-card ${on?'selected':''} ${over?'over':''}" data-host="${esc(h.resource)}" aria-pressed="${on}">
   <div class="host-card-head"><strong>${esc(h.name)}</strong><small>EC2</small></div>
   <div class="host-metric"><span>CPU</span><b>${pct(h.stats.cpu.now)}</b></div>${bar(h.stats.cpu.now,h.threshold.cpu)}
   <div class="host-metric"><span>메모리</span><b>${pct(h.stats.memory.now)}</b></div>${bar(h.stats.memory.now,h.threshold.memory)}
   <div class="host-card-foot">${over?`<span class="over-flag">임계 초과 ${over}구간</span>`:'<span>임계 초과 없음</span>'}<small>${esc(h.resource)}</small></div>
  </button>`;}).join('')}</div>`;
}
function serviceFlow(svc,hosts){
 if(!svc)return `<div class="context-note">3계층 상태를 불러오지 못했습니다. 새로고침 후에도 같으면 백엔드 /api/infra/status 응답을 확인하세요.</div>`;
 const items=svc.components||[];
 if(!items.length)return empty('저장된 인프라 상태 증거가 없습니다.');
 const nameOf=id=>hosts.find(h=>h.resource===id)?.name||id;
 return `<div class="service-flow">${items.map((c,i)=>`${i?`<span class="service-arrow" style="color:${SERVICE_COLOR[c.status]||SERVICE_COLOR.unknown}">→</span>`:''}<div class="service-node ${c.status==='unhealthy'?'down':esc(c.status)}"><strong>${esc(c.name)}</strong>${servicePill(c.status)}<small>${esc(nameOf(c.resource))}</small></div>`).join('')}</div>
 <div class="table-scroll"><table class="service-table"><caption class="sr-only">계층별 점검 결과</caption><thead><tr><th>계층</th><th>자원</th><th>상태</th><th>판정 근거</th><th>관측 시각</th></tr></thead><tbody>${items.map(c=>`<tr><td>${esc(c.name)}</td><td>${esc(nameOf(c.resource))}<br><small class="muted">${esc(c.resource)}</small></td><td>${servicePill(c.status)}</td><td>${esc(c.detail||'—')}<br><small class="muted">${esc(c.source||'')}</small></td><td>${format(milliseconds(c.observedAt))}</td></tr>`).join('')}</tbody></table></div>`;
}
export function infrastructure(){
 const m=metricsFor(),svc=servicesOf(),span=state.hours*3600000,hosts=hostViews(m);
 if(!hosts.length)return `<div class="view-intro"><span>CloudWatch · CPU / 메모리</span></div><section class="panel">${header('EC2 자원 사용률','대상 없음')}${empty('조회 기간에 수집된 EC2 지표가 없습니다.')}</section>
  <section class="panel full-panel">${header('3계층 서비스',svc?`${(svc.components||[]).length}개 구성요소`:'조회 실패')}${serviceFlow(svc,hosts)}</section>`;
 const h=selectedHost(hosts),overCpu=h.breaches.filter(b=>b.metric==='cpu').length,overMem=h.breaches.length-overCpu;
 const samples=hosts.reduce((a,x)=>a+x.stats.cpu.samples,0);
 return `<div class="view-intro"><span>운영 중인 서버 ${hosts.length}대 · ${periodLabel(m.periodSeconds)} 평균 · 표본 ${samples}개</span><span>최근 ${state.hours<1?Math.round(state.hours*60)+'분':state.hours>=24?state.hours/24+'일':state.hours+'시간'} · 경보 임계치 <strong class="mint">${h.threshold.cpu}%</strong></span></div>
 <section class="panel">${header('운영 중인 서버',`${hosts.length}대 · 카드를 누르면 아래 상세 차트가 바뀝니다`)}${hostGrid(hosts,h)}
  <div class="context-note">리전에서 조회된 EC2 전체입니다. CPU·메모리 모두 5분 평균입니다(CPU 는 EC2 기본 모니터링 5분 간격). 메모리는 CloudWatch Agent 가 설치된 호스트만 수집됩니다.</div></section>
 <div class="infrastructure-grid">
  <section class="panel">${header(`상세 · ${esc(h.name)}`,hostPicker(hosts,h))}<div class="metric-large">${canvas('metrics-chart',`CPU ${pct(h.stats.cpu.now)}, 메모리 ${pct(h.stats.memory.now)}, 임계치 ${h.threshold.cpu}%`)}</div>
   <div class="metric-stats"><div><span>CPU 현재</span><b>${pct(h.stats.cpu.now)}</b></div><div><span>CPU 최대 / 평균</span><b>${pct(h.stats.cpu.max)} / ${pct(h.stats.cpu.avg)}</b></div><div><span>메모리 현재</span><b>${pct(h.stats.memory.now)}</b></div><div><span>메모리 최대 / 평균</span><b>${pct(h.stats.memory.max)} / ${pct(h.stats.memory.avg)}</b></div></div>
   <div class="context-note">${esc(h.resource)} — 선택 구간의 마지막 표본 기준입니다.</div></section>
  <section class="panel">${header('임계치 초과 구간',`CPU ${overCpu}회 / 메모리 ${overMem}회`)}${breachPanel(h,span)}
   <div class="context-note">CloudWatch 알람 조건은 5분 평균 2회 연속 초과입니다. 위 구간은 화면 표본 기준이라 알람 건수와 1:1이 아닙니다.</div></section>
  <section class="panel full-panel">${header('3계층 서비스',svc?`${(svc.components||[]).length}개 구성요소 · 수집된 상태`:'조회 실패')}${serviceFlow(svc,hosts)}</section>
 </div>`;
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
 const hosts=hostViews(metricsFor());if(!hosts.length)return;
 const h=selectedHost(hosts),span=state.hours*3600000,all=h.cpu.length>=h.memory.length?h.cpu:h.memory;
 const memAt=new Map(h.memory.map(p=>[p.at,p.value])),cpuAt=new Map(h.cpu.map(p=>[p.at,p.value])),t=h.threshold;
 const {points,cpu,mem}=thinSeries(all,all.map(p=>cpuAt.get(p.at)??null),all.map(p=>memAt.get(p.at)??null));
 drawChart('metrics-chart','line',{labels:points.map(p=>formatAt(p.at,span)),datasets:[
  {label:'CPU %',data:cpu,borderColor:'#32d4be',tension:.3,borderWidth:2,spanGaps:true,
   pointRadius:cpu.map(v=>v>t.cpu?3.5:0),pointBackgroundColor:cpu.map(v=>v>t.cpu?'#e7a064':'#32d4be')},
  {label:'메모리 %',data:mem,borderColor:'#a3c7b7',tension:.3,borderWidth:2,spanGaps:true,
   pointRadius:mem.map(v=>v>t.memory?3.5:0),pointBackgroundColor:mem.map(v=>v>t.memory?'#ef777f':'#a3c7b7')},
  {label:`${t.cpu}% 임계치`,data:points.map(()=>t.cpu),borderColor:'#e7a064',borderDash:[5,5],pointRadius:0,borderWidth:1}]},
  {plugins:{legend:{display:true,labels:{color:'#c4d7cb',boxWidth:12}}},scales:{y:{min:0,max:100,ticks:{color:'#8fa295'}},x:{ticks:{color:'#8fa295',maxTicksLimit:8}}}});
}
// 호스트 선택은 화면 안에서만(조회 범위를 바꾸지 않는다). 바뀌었으면 true.
export function selectHost(id){if(infraHost===id)return false;infraHost=id;return true;}
