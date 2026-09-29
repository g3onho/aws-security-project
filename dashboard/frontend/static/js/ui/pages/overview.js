// 통합 관제: 인프라 상태·자원 표본·자동 대응·최근 보안 이벤트.
import {summary,metricsFor,servicesOf} from '../context.js?v=ui-1';
import {header} from '../components/panel.js?v=ui-1';
import {esc} from '../components/format.js?v=ui-1';

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
 const other=Math.max(0,components.length-running),alarmTotal=count(alarms?.total),firing=count(alarms?.alarm),insufficient=count(alarms?.insufficientData),noData=count(alarms?.noData),ok=Math.max(0,alarmTotal-firing-insufficient-noData);
 const segment=(value,total,key)=>value?`<i class="${key}" style="width:${(value/total*100).toFixed(1)}%"></i>`:'';
 const ec2Tile=`<div class="overview-infra-stat overview-infra-viz"><span>EC2 가동</span><b>${svc?`${running}/${components.length} 대`:'정보 없음'}</b>${svc&&components.length?`<div class="overview-mini-bar" role="img" aria-label="EC2 가동 ${running}대, 그 외 ${other}대">${segment(running,components.length,'running')}${segment(other,components.length,'other')}</div>`:''}<small>${svc?components.some(c=>c.status==='unknown')?'상태 미확인 포함':'인스턴스 상태':'조회 불가'}</small></div>`;
 const alarmTile=`<div class="overview-infra-stat overview-infra-viz${firing?' is-alert':''}"><span>CloudWatch 경보</span><b>${alarms?`${firing}건`:'정보 없음'}</b>${alarms&&alarmTotal?`<div class="overview-mini-bar" role="img" aria-label="경보 ${firing}건, 정상 ${ok}건, 데이터 부족 ${insufficient}건, 데이터 없음 ${noData}건">${segment(firing,alarmTotal,'alarm')}${segment(insufficient,alarmTotal,'insufficient')}${segment(noData,alarmTotal,'nodata')}${segment(ok,alarmTotal,'ok')}</div>`:''}<small>${alarms?`전체 ${alarmTotal} · 데이터 부족 ${insufficient} · 데이터 없음 ${noData}`:'조회 불가'}</small></div>`;
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
 const note=unknown?'점검 결과 자료 없음':tiers.some(t=>['degraded','unhealthy'].includes(t.status))?'확인 필요한 계층이 있습니다':'점검 결과 정상';
 return `<div class="overview-tier-summary"><div class="overview-tier-heading"><strong>3계층 서비스</strong><span>${note}</span></div>
  <div class="overview-tier-flow">${tiers.map((tier,index)=>`${index?'<span class="overview-tier-arrow" aria-hidden="true">→</span>':''}<div class="overview-tier-node"><b>${esc(tier.name)}</b><span class="${TIER_STATE[tier.status]?.[1]||'muted'}">${TIER_STATE[tier.status]?.[0]||'확인 불가'}</span></div>`).join('')}</div></div>`;
}

// 자동 대응은 판정 유형 세 가지로 나눈다. 실행 상태는 해당 카드 설명으로 분리한다.
export function responseCard(){
 const a=summary.automation;
 const note=a==null?'자동 대응 기록을 불러오지 못했습니다.':a.configured===false?'조치 이력 테이블이 설정되지 않았습니다.':null;
 if(note)return `<section class="panel">${header('자동 대응 현황','SOAR')}<div class="response-body"><p class="muted">${note}</p></div></section>`;
 const total=count(a.total),groups=[
  ['자동 실행',a.autoExecuted,'automatic',`완료 ${count(a.succeeded)} · 실패 ${count(a.failed)} · 진행 ${count(a.inProgress)}`],
  ['수동 대응 필요',a.manual,'manual','담당자 알림'],
  ['판단만',a.dryRun,'dry-run','dry-run 기록'],
 ].map(([label,value,key,detail])=>({label,count:count(value),key,detail}));
 const classified=groups.reduce((sum,item)=>sum+item.count,0),unclassified=Math.max(0,total-classified),noChange=count(a.noChange);
 const cards=groups.map(item=>{
  const share=classified?item.count/classified*100:0;
  return `<div class="response-summary-card ${item.key}"><span>${item.label}</span><b>${item.count}건</b>
   <div class="response-share-ring" role="img" aria-label="${item.label} ${item.count}건, 판정 분류 중 ${Math.round(share)}%" style="--share:${share.toFixed(1)}%"><b>${Math.round(share)}%</b></div>
   <small>${item.detail}</small></div>`;
 }).join('');
 const noteParts=[`판정 분류 ${classified}건 기준`,noChange?`변경 없음 ${noChange}건`:null,unclassified>noChange?`그 외 ${unclassified-noChange}건`:null].filter(Boolean);
 return `<section class="panel response-overview-panel">${header('자동 대응 현황',`${total}건 · 선택 기간`)}<div class="response-body">
  <div class="response-summary">${cards}</div><p class="response-summary-footnote">${noteParts.join(' · ')}</p>
  <div class="response-overview-footer"><small>실행 결과와 재검증 결과는 조치 이력에서 확인합니다.</small><button class="text-button" data-view="responses">조치 이력 보기 →</button></div></div></section>`;
}
export function overviewCharts(){
 return `<div class="overview-summary-grid">${infrastructureCard()}${responseCard()}</div>`;
}
