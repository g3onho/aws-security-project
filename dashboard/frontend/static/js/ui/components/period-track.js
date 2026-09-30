// 기간 트랙(v20.5): 왼쪽 '지금'부터 오른쪽으로 15분·1시간·1일·1주일 지점이 같은 간격으로 놓인다.
// 곡선 = 지금부터 그 시점까지 쌓인 수(누적). 그래서 각 지점의 높이·숫자가 곧 그 기간 버튼을 눌렀을 때의 수다.
// 무엇을 세는지는 화면이 정한다: 탐지(통합 관제·보안 이벤트) · 임계 초과 구간(인프라) · 조치 이력(조치 이력).
// 선택한 기간까지는 밝게, 그 너머는 흐리게. 지점을 누르면 기간 버튼과 같은 동작(data-hours)을 한다.
import {esc} from './format.js?v=v44';

const HOUR=3600000;
export const PERIOD_STOPS=Object.freeze([{hours:0,label:'지금'},{hours:.25,label:'15분'},{hours:1,label:'1시간'},{hours:24,label:'1일'},{hours:168,label:'1주일'}]);
// 지점 위치(0~1). 실제 시간 비율(15분:1주일 = 1:672)이 아니라, 뒤로 갈수록 간격이 조금씩 넓어져
// '기간 차이가 있다'는 느낌만 준다. 구간 폭 비 = 1 : 1.5 : 2.3 : 3.2.
export const STOP_X=Object.freeze([0,.125,.3125,.6,1]);
const W=1000,H=56,TOP=22,BASE=H-4,SAMPLES=40;

// ago(ms 전) → x. 지점 사이는 시간 선형(구간마다 길이가 다른 조각 선형 축).
export function xOf(ago){
 const stops=PERIOD_STOPS.map(s=>s.hours*HOUR);
 if(ago<=0)return 0;if(ago>=stops.at(-1))return W;
 const i=stops.findIndex((t,k)=>ago<=stops[k+1]);
 return W*(STOP_X[i]+(STOP_X[i+1]-STOP_X[i])*(ago-stops[i])/(stops[i+1]-stops[i]));
}
// 지금부터 ago 전까지 탐지 수
export const cumulative=(ages,ago)=>{let n=0;for(const a of ages)if(a>0&&a<=ago)n++;return n;};

// times: 세는 대상의 시각(ms) 목록. null 이면 아직 불러오는 중이며 숫자는 미정으로 둔다.
export function periodTrackMarkup(times,hours,now,{noun='탐지',unit='건'}={}){
 const ages=(times||[]).filter(t=>t!=null).map(t=>now-t).filter(a=>a>0).sort((a,b)=>a-b);
 // 높이 = √(누적/1주일 누적). 1주일 대비 몇 건 안 되는 최근 구간도 곡선이 보이게 하는 제곱근 축(순서·단조성은 그대로).
 const total=Math.max(1,cumulative(ages,168*HOUR)),y=n=>BASE-(BASE-TOP)*Math.sqrt(n/total);
 // 곡선: 구간마다 SAMPLES 개 표본(가까운 과거일수록 촘촘한 시간 간격)
 const points=[[0,BASE]];
 for(let k=0;k<PERIOD_STOPS.length-1;k++){
  const a=PERIOD_STOPS[k].hours*HOUR,b=PERIOD_STOPS[k+1].hours*HOUR;
  for(let s=1;s<=SAMPLES;s++){const t=a+(b-a)*s/SAMPLES;points.push([xOf(t),y(cumulative(ages,t))]);}
 }
 const line=points.map(([x,v],i)=>`${i?'L':'M'}${x.toFixed(1)},${v.toFixed(1)}`).join(''),area=`${line}L${W},${BASE}L0,${BASE}Z`;
 const selX=xOf(hours*HOUR),sel=PERIOD_STOPS.findIndex(s=>s.hours===hours);
 const SVG_PX=42;   // .pt-svg 높이(px) — 숫자 사각형 중심을 곡선 위에 둔다
 const stops=PERIOD_STOPS.map((s,i)=>{
  const x=STOP_X[i]*100,count=s.hours?(times==null?null:cumulative(ages,s.hours*HOUR)):null,active=i===sel,inside=i<=sel;
  const py=(y(count||0)/H*SVG_PX).toFixed(1),style=`left:${x}%;--y:${py}px`;
  const edge=i===0?' first':i===PERIOD_STOPS.length-1?' last':'';
  const marker=count??'…';
  return s.hours
   ?`<button class="pt-stop${active?' active':''}${inside?' inside':''}${edge}" style="${style}" data-hours="${s.hours}" aria-label="최근 ${esc(s.label)} · ${esc(noun)} ${marker}${esc(unit)}" aria-pressed="${active}" title="최근 ${esc(s.label)} · ${esc(noun)} ${marker}${esc(unit)}"><span class="pt-stem"></span><span class="pt-marker" data-period-count="${s.hours}" aria-hidden="true">${marker}</span><span class="pt-label">${esc(s.label)}</span></button>`
   :`<div class="pt-stop now${edge}" style="${style}" aria-label="지금 · ${esc(noun)} 0${esc(unit)}"><span class="pt-marker" data-period-count="0" aria-hidden="true">0</span><span class="pt-label">지금</span></div>`;
 }).join('');
 return `<div class="pt" role="group" aria-label="조회 기간: 지금부터 과거로. 곡선은 지금부터 쌓인 ${esc(noun)} 수">
 <svg class="pt-svg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">
  <defs><clipPath id="pt-sel"><rect x="0" y="0" width="${selX.toFixed(1)}" height="${H}"/></clipPath>
  <linearGradient id="pt-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0e8f80" stop-opacity=".42"/><stop offset="1" stop-color="#0e8f80" stop-opacity=".04"/></linearGradient></defs>
  <line class="pt-base" x1="0" x2="${W}" y1="${BASE}" y2="${BASE}"/>
  <path class="pt-area-dim" d="${area}"/><path class="pt-line-dim" d="${line}"/>
  <g clip-path="url(#pt-sel)"><path class="pt-area" d="${area}" fill="url(#pt-fill)"/><path class="pt-line" d="${line}"/></g>
 </svg>${stops}</div>`;
}
