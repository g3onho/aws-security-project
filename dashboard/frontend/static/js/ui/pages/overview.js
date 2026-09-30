// 통합 관제: 인프라 상태·자원 표본·자동 대응·최근 보안 이벤트.
import {summary,metricsFor,servicesOf} from '../context.js?v=v43';
import {header} from '../components/panel.js?v=v43';
import {esc} from '../components/format.js?v=v43';
import {responseStats} from '../components/event-response.js?v=v43';

function highestLatest(metric,key){
 const values=(metric?.series||[]).filter(s=>s.metric===key).map(s=>{
  const point=[...(s.points||[])].reverse().find(p=>p.value!=null);
  return point?Number(point.value):null;
 }).filter(v=>v!=null&&Number.isFinite(v));
 return values.length?Math.max(...values):null;
}
const count=value=>Math.max(0,Number(value)||0);
const pct=value=>value==null?'정보 없음':`${Math.round(value*10)/10}%`;

function sampleCard(metric,key,label,threshold){
 const series=(metric?.series||[]).filter(s=>s.metric===key);
 const samples=series.flatMap(s=>s.points||[]).filter(p=>p.value!=null&&Number.isFinite(Number(p.value)));
 const latest=highestLatest(metric,key);
 const thresholdValue=Number.isFinite(Number(threshold))?Number(threshold):null;
 if(!samples.length)return `<div class="overview-spark-card" data-metric="${key}"><div class="overview-spark-heading"><span>${label} 표본</span><b>정보 없음</b></div><div class="overview-spark-empty">선택 기간에 수집된 표본이 없습니다.</div></div>`;

 const byTime=new Map();
 for(const item of series.flatMap(s=>s.points||[])){
  const at=Date.parse(item.timestamp);if(!Number.isFinite(at))continue;
  const values=byTime.get(at)||[];
  if(item.value!=null&&Number.isFinite(Number(item.value)))values.push(Number(item.value));
  byTime.set(at,values);
 }
 const points=[...byTime].sort((a,b)=>a[0]-b[0]).map(([at,values])=>({at,value:values.length?Math.max(...values):null}));
 const start=Number.isFinite(metric?.rangeFrom)?metric.rangeFrom:points[0].at;
 const end=Number.isFinite(metric?.rangeTo)?metric.rangeTo:points.at(-1).at;
 const width=240,height=54,pad=4,plotWidth=width-pad*2,plotHeight=height-pad*2;
 const coord=(point,index)=>({
  x:points.length<2?width/2:pad+plotWidth*(end>start?(point.at-start)/(end-start):index/(points.length-1)),
  y:pad+plotHeight*(1-Math.max(0,Math.min(100,point.value))/100),
 });
 const runs=[];let run=[];
 for(let i=0;i<points.length;i++){
  if(points[i].value==null){if(run.length)runs.push(run);run=[];continue;}
  run.push(coord(points[i],i));
 }
 if(run.length)runs.push(run);
 const lines=runs.map(group=>group.length>1?`<polyline class="overview-sample-line" points="${group.map(p=>`${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')}"/>`:`<circle class="overview-sample-point" cx="${group[0].x.toFixed(1)}" cy="${group[0].y.toFixed(1)}" r="2.5"/>`).join('');
 const thresholdY=thresholdValue==null?'':(pad+plotHeight*(1-Math.max(0,Math.min(100,thresholdValue))/100)).toFixed(1);
 const chart=`<svg class="overview-sparkline" data-metric="${key}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" role="img" aria-label="${label} 표본 ${samples.length}개, 서버별 최고 최근 표본 ${pct(latest)}${thresholdValue==null?'':`, 임계치 ${thresholdValue}%`}">
  ${thresholdY?`<line class="overview-sample-threshold" x1="0" x2="${width}" y1="${thresholdY}" y2="${thresholdY}"/>`:''}<line class="overview-sample-base" x1="0" x2="${width}" y1="${height-pad}" y2="${height-pad}"/>${lines}</svg>`;
 return `<div class="overview-spark-card${latest!=null&&thresholdValue!=null&&latest>thresholdValue?' is-alert':''}" data-metric="${key}">
  <div class="overview-spark-heading"><span>${label} 표본</span><b>${pct(latest)}</b></div>${chart}
  <small>EC2별 최고 · ${samples.length}개 표본${thresholdValue==null?'':` · 기준 ${thresholdValue}%`}</small></div>`;
}

function infrastructureCard(){
 const svc=servicesOf(),metric=metricsFor(),alarms=summary.alarms;
 const components=svc?.components||[],running=components.filter(c=>c.status==='healthy').length;
 const other=Math.max(0,components.length-running),alarmTotal=count(alarms?.total),firing=count(alarms?.alarm),check=count(alarms?.needsCheck??alarms?.insufficientData),ok=Math.max(0,alarmTotal-firing-check);
 const segment=(value,total,key)=>value?`<i class="${key}" style="width:${(value/total*100).toFixed(1)}%"></i>`:'';
 const st=key=>components.filter(c=>c.status===key).length,degraded=st('degraded'),unhealthy=st('unhealthy'),unknownN=Math.max(0,other-degraded-unhealthy);
 const legend=items=>`<div class="overview-mini-legend">${items.filter(([,n])=>n).map(([cls,n,label])=>`<span><i class="${cls}"></i>${label} <b>${n}</b></span>`).join('')}</div>`;
 const ec2Tile=`<div class="overview-infra-stat overview-infra-viz"><span>서버 상태</span><b>${svc?`${running}/${components.length} 대`:'정보 없음'}</b>${svc&&components.length?`<div class="overview-mini-bar" role="img" aria-label="서버 가동 ${running}대, 저하 ${degraded}대, 장애 ${unhealthy}대, 미확인 ${unknownN}대">${segment(running,components.length,'running')}${segment(degraded,components.length,'degraded')}${segment(unhealthy,components.length,'unhealthy')}${segment(unknownN,components.length,'other')}</div>${legend([['running',running,'정상'],['degraded',degraded,'저하'],['unhealthy',unhealthy,'장애'],['other',unknownN,'미확인']])}`:''}${svc?'':'<small>조회 불가</small>'}</div>`;
 const alarmTile=`<div class="overview-infra-stat overview-infra-viz${firing?' is-alert':''}"><span>CloudWatch 경보</span><b>${alarms?`${alarmTotal}건`:'정보 없음'}</b>${alarms&&alarmTotal?`<div class="overview-mini-bar" role="img" aria-label="경보 ${firing}건, 확인 필요 ${check}건, 정상 ${ok}건">${segment(firing,alarmTotal,'alarm')}${segment(check,alarmTotal,'insufficient')}${segment(ok,alarmTotal,'ok')}</div>${legend([['alarm',firing,'경보'],['insufficient',check,'확인 필요'],['ok',ok,'정상']])}`:''}${alarms?'':'<small>조회 불가</small>'}</div>`;
 return `<section class="panel">${header('인프라 상태 요약','EC2 · CloudWatch')}<div class="overview-infra-body">
  <div class="overview-infra-stats">${ec2Tile}${alarmTile}
  ${sampleCard(metric,'cpu','CPU',metric?.thresholds?.cpu)}${sampleCard(metric,'memory','메모리',metric?.thresholds?.memory)}</div>
  ${tierSummary(svc)}
  <div class="overview-infra-footer"><button class="text-button" data-view="infrastructure">인프라 자세히 보기 →</button></div></div></section>`;
}
const TIER_STATE={healthy:['정상','ok'],degraded:['저하','warn'],unhealthy:['비정상','bad'],unknown:['확인 불가','muted']};
function tierSummary(svc){
 const tiers=svc?.tiers||[];
 if(!svc)return `<div class="overview-tier-summary"><div class="overview-tier-heading"><strong>3계층 서비스</strong><span>조회 실패</span></div></div>`;
 if(!tiers.length)return `<div class="overview-tier-summary"><div class="overview-tier-heading"><strong>3계층 서비스</strong><span>점검 자료 없음</span></div></div>`;
 const unknown=tiers.some(t=>!t.status||t.status==='unknown');
 const bad=tiers.some(t=>['degraded','unhealthy'].includes(t.status));
 const note=bad?'확인 필요한 계층이 있습니다':unknown?(tiers.every(t=>!t.observedAt)?'점검 결과 자료 없음':'일부 점검 결과가 없거나 오래됨'):'점검 결과 정상';
 return `<div class="overview-tier-summary"><div class="overview-tier-heading"><strong>3계층 서비스</strong><span>${note}</span></div>
  <div class="overview-tier-flow">${tiers.map((tier,index)=>`${index?'<span class="overview-tier-arrow" aria-hidden="true">→</span>':''}<div class="overview-tier-node" title="${esc(tier.detail||'')}"><b>${esc(tier.name)}</b><span class="${TIER_STATE[tier.status]?.[1]||'muted'}">${TIER_STATE[tier.status]?.[0]||'확인 불가'}</span></div>`).join('')}</div></div>`;
}

// 자동 대응 현황: 자동 조치 / 수동 대응 / 직접 조치 세 갈래. 링 그래프 = 각 갈래 대상 중 조치 완료 비율.
// 자동은 SSM 실행 완료(재검증 전)까지만 뜻한다. 해결 여부는 보안 이벤트가 목록에서 사라지는지로 확인한다.
const ratio=(done,total)=>total>0?Math.min(100,done/total*100):0;
export function responseCard(){
 const st=responseStats(),a=st.auto,m=st.manual,d=st.direct;
 const waiting=st.error?'조치 이력을 읽지 못해 집계하지 못했습니다.':'조치 이력을 불러오는 중…';
 const autoNote=summaryNote();
 const groups=[
  {key:'automatic',label:'자동 대응',ok:!!a,total:a?.total,done:a?.done,
   desc:a?`정책에 따라 자동 실행한 조치 · 실행 완료 ${a.done} · 실패 ${a.failed} · 진행 ${a.running}`:autoNote,unit:'실행 완료(재검증 전)'},
  {key:'manual',label:'수동 대응',ok:!!m,total:m?m.done+m.open:0,done:m?.done,
   desc:m?`대시보드에서 조치할 수 있는 건 · 조치 완료(재검증 통과) ${m.done} · 미조치 ${m.open}${m.failed?` (자동 실패 ${m.failed} 포함)`:''}`:waiting,unit:'조치 완료'},
  {key:'direct',label:'직접 조치',ok:!!d,total:d?d.done+d.open:0,done:d?.done,
   desc:d?`AWS에서 직접 조치해야 하는 건 · 목록에서 사라짐(외부 해결 추정) ${d.done} · 미조치 ${d.open}`:waiting,unit:'해결 추정'},
 ];
 const cards=groups.map(g=>{
  const share=g.ok?ratio(g.done,g.total):0,pctText=g.ok&&g.total>0?`${Math.round(share)}%`:'—';
  return `<div class="response-summary-card ${g.key}" title="${esc(g.desc)}"><span>${g.label}</span><b>${g.ok?`${g.total}건`:'—'}</b>
   <div class="response-share-ring" role="img" aria-label="${g.label} ${g.ok?`${g.total}건 중 ${g.unit} ${Math.round(share)}%`:'집계 불가'}" style="--share:${share.toFixed(1)}%">
    <svg viewBox="0 0 120 120" aria-hidden="true" focusable="false"><defs><linearGradient id="rr-${g.key}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="var(--ring-from)"/><stop offset="1" stop-color="var(--ring-to)"/></linearGradient></defs>
    <circle class="rr-track" cx="60" cy="60" r="50" pathLength="100"/><circle class="rr-arc" cx="60" cy="60" r="50" pathLength="100" stroke="url(#rr-${g.key})" stroke-dasharray="${share>0?Math.max(share,1.5).toFixed(1):0} 100"/></svg><b>${pctText}</b></div></div>`;
 }).join('');
 return `<section class="panel response-overview-panel">${header('자동 대응 현황','선택 기간')}<div class="response-body">
  <div class="response-summary">${cards}</div>
  <div class="response-overview-footer"><button class="text-button" data-view="responses">조치 이력 보기 →</button></div></div></section>`;
}
function summaryNote(){const a=summary.automation;return a==null?'자동 대응 기록을 불러오지 못했습니다.':'조치 이력 테이블이 설정되지 않았습니다.';}
export function overviewCharts(){
 return `<div class="overview-summary-grid">${infrastructureCard()}<div id="overview-response-box" class="overview-response-slot" data-key="overview-response-box">${responseCard()}</div></div>`;
}
