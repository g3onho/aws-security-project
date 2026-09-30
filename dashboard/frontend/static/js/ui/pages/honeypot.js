// 허니팟 화면(v25): ① 동작 상태 ② 파이프라인 타임라인 ③ 통계 차트 ④ 관계 그래프 ⑤ 세션 목록·재생 ⑥ 차단 IP 관리.
// 세션의 명령·사용자명·비밀번호·미끼 응답·AI 요약은 모두 공격자가 조종할 수 있는 값이다 — 이 파일은 그 값을
// 항상 esc() 를 거쳐 텍스트로만 그린다(innerHTML 에 원문을 넣지 않는다). 그래프도 SVG 문자열을 esc() 로 만든다.
// 원천을 읽지 못한 구역은 그 구역에만 "읽지 못함"을 표시하고, 빈 표나 0 으로 바꾸지 않는다.
import {$,$$,api,config,state,ui} from '../context.js?v=v44';
import {esc,format,formatAt} from '../components/format.js?v=v44';
import {header,canvas,toast} from '../components/panel.js?v=v44';
import {drawChart} from '../charts/charts.js?v=v44';
import {severityColors} from '../constants.js?v=v44';
import {blocklistCsv,downloadCsv,downloadFile} from '../components/downloads.js?v=v44';
import {mapSvg,stageList,replayMap} from './honeypot-map.js?v=v44';

const MINT='#0e8f80',SOFT='#4186be',AMBER='#a88a0d',RED='#d63a44',GRAY='#57665c';
const VERDICT={ok:['정상 동작',MINT],waiting:['동작 확인 중',AMBER],partial:['일부 동작',AMBER],unknown:['확인 불가',GRAY],not_deployed:['허니팟 미배포',GRAY]};
const CARD_LABEL={instance:'미끼 인스턴스',logs:'로그 수신',ai:'AI 응답',alarm:'탐지 알람',block:'자동 차단'};
const CARD_COLOR={ok:MINT,info:SOFT,warn:AMBER,bad:RED,unknown:GRAY};
const CARD_MARK={ok:'✓',info:'i',warn:'!',bad:'✕',unknown:'?'};
const INTENT_KO={recon:'정찰','credential-access':'자격증명 접근','lateral-movement':'내부 이동',exfiltration:'유출',impact:'영향·파괴',unknown:'미상'};
// 통계 차트·관계 그래프 전용 파스텔 팔레트: 다른 화면(위험도 색·자동 대응 카드)과 같은 톤으로 맞춘다.
const CH={mint:'#5cbfae',blue:'#8aa6c8',amber:'#f2c766',orange:'#eba363',red:'#f28f96',violet:'#b8a1e3',gray:'#aab6b1',ink:'#8a9891'};
const INTENT_COLOR={recon:CH.blue,'credential-access':CH.amber,'lateral-movement':CH.violet,exfiltration:CH.orange,impact:CH.red,unknown:CH.gray};
const SEVERITY_KO={low:'낮음',medium:'보통',high:'높음',critical:'치명'};
const SEVERITY_COLOR={low:severityColors.Low,medium:severityColors.Medium,high:severityColors.High,critical:severityColors.Critical};
const STEP_STATE={done:['완료','✓',MINT],missing:['기록 없음','–',GRAY],failed:['실패','✕',RED],pending:['진행 중','…',AMBER],unknown:['읽지 못함','?',AMBER]};
const BLOCK_STATE={applying:['적용 중',AMBER],blocked:['차단 중',RED],expiring:['만료 예정(해제 대기)',AMBER],releasing:['해제 중',AMBER],
 released:['해제됨',MINT],expired:['만료 해제됨',MINT],failed:['차단 실패',RED],mismatch:['불일치',AMBER],unrecorded:['기록 없음',AMBER]};
const MISMATCH_KO={'nacl-missing':'표에는 차단인데 NACL 에 Deny 가 없다','record-missing':'NACL 에 Deny 가 있는데 표에 기록이 없다(수동 차단·이전 배포)',
 'nacl-still-blocked':'해제로 기록됐지만 NACL 에 Deny 가 남아 있다','rule-changed':'표의 규칙 번호와 NACL 의 번호가 다르다'};
const SOURCE_KO={HONEYPOT:'미끼서버','SEC-06A':'MySQL 무차별 대입','SEC-06B':'SSH 접속 거부 급증',MANUAL:'수동'};

// 화면 상태. 각 구역은 {ok,data,error,warnings} 로 성공·실패를 따로 가진다(한 구역 실패가 나머지를 막지 않는다).
const S={status:null,stats:null,sessions:null,blocklist:null,timeline:null,detail:null,ip:'',filter:{ip:'',intent:''},
 reveal:false,action:null,busy:false,message:null,layout:null,layoutKey:''};
const section=(promise)=>promise.then(r=>({ok:true,...r}),error=>({ok:false,error:error.message,warnings:[],data:null}));
const iso=ms=>ms?new Date(ms).toISOString():'';
const role=()=>config().role;
const canWrite=()=>S.blocklist?.ok&&S.blocklist.data.canWrite===true;

export const honeypotTimes=()=>S.stats?.ok?S.stats.data.timeline.flatMap(b=>Array(b.sessions).fill(b.at)):null;

// ── 공통 조각 ───────────────────────────────────────────────────────────────
const failed=(what,part)=>`<p class="panel-error" role="status">${esc(what)}을(를) 읽지 못했습니다: ${esc(part.error)} — 빈 값이나 정상이 아니라 확인 불가입니다.</p>`;
const warnLines=part=>(part.warnings||[]).map(w=>`<p class="hp-warn" role="status">⚠ ${esc(w)}</p>`).join('');
const pill=(text,color)=>`<span class="service-pill" style="color:${color}"><i style="background:${color}"></i>${esc(text)}</span>`;
const ipCell=ip=>ip?`<button type="button" class="hp-link" data-hp-ip="${esc(ip)}">${esc(ip)}</button>`:'—';
const block=ip=>S.blocklist?.ok?S.blocklist.data.items.find(i=>i.ip===ip)||null:null;

// ── ① 동작 상태 ────────────────────────────────────────────────────────────
function statusSection(){
 const part=S.status;
 if(!part.ok)return `<section class="panel full-panel">${header('동작 상태','STATUS')}${failed('허니팟 상태',part)}</section>`;
 const d=part.data;
 if(!d.deployed)return `<section class="panel full-panel">${header('동작 상태','STATUS')}<div class="empty"><strong>허니팟 미배포</strong>enable_honeypot 이 꺼져 있어 미끼 서버가 없습니다. 배포 후 이 화면에서 접속·분석·차단을 확인합니다.</div></section>`;
 const [label,color]=VERDICT[d.verdict.state]||VERDICT.unknown;
 const cards=Object.keys(CARD_LABEL).filter(k=>d.cards[k]).map((k,i)=>{
  const c=d.cards[k],col=CARD_COLOR[c.state]||GRAY;
  return `<div class="hp-card" data-card="${esc(k)}" data-state="${esc(c.state)}" style="--c:${col}">
   <div class="hp-card-top"><span class="hp-mark" aria-hidden="true">${CARD_MARK[c.state]||'?'}</span><span class="hp-card-label">${esc(CARD_LABEL[k])}</span></div>
   <strong class="hp-card-text">${esc(c.text)}</strong>
   <div class="hp-card-foot"><small>${c.at?esc(format(c.at))+' KST':'시각 없음'}</small>${c.detail?`<small class="muted">${esc(c.detail)}</small>`:''}</div></div>`;
 }).join('');
 const reasons=d.verdict.reasons.length?`<ul class="hp-reasons">${d.verdict.reasons.map(r=>`<li>${esc(r)}</li>`).join('')}</ul>`:'';
 return `<section class="panel full-panel">${header('동작 상태','STATUS')}
  <div class="hp-verdict" data-verdict="${esc(d.verdict.state)}" style="--c:${color}"><span class="hp-verdict-dot" aria-hidden="true"></span><div><strong>${esc(label)}</strong>${reasons}</div></div>
  ${warnLines(part)}<div class="hp-cards">${cards}</div>
  <p class="muted hp-note">미끼 인스턴스·로그·AI 응답·알람·자동 차단이 모두 관측되면 "정상 동작"으로 표시합니다. 접속이 없으면 "동작 확인 중"입니다.</p></section>`;
}

// ── ② 파이프라인 타임라인 ─────────────────────────────────────────────────────
function ipChoices(){
 const set=new Set();
 if(S.stats?.ok)S.stats.data.topIps.forEach(r=>set.add(r.ip));
 if(S.blocklist?.ok)S.blocklist.data.items.forEach(i=>set.add(i.ip));
 return [...set];
}
function pickerHtml(){
 const ips=ipChoices();
 return ips.length?`<label class="hp-pick"><span>공격 IP</span><select data-hp-select>${ips.map(ip=>`<option value="${esc(ip)}"${ip===S.ip?' selected':''}>${esc(ip)}</option>`).join('')}</select></label>`:'';
}
// 공격 경로 지도: 타임라인 API 의 steps 를 아키텍처 위에 그린다(새 데이터 원천 없음).
function mapSection(){
 const ips=ipChoices(),tl=S.timeline;
 let body,steps=null;
 if(!ips.length)body=`${mapSvg(null)}<p class="muted hp-note">선택한 기간에 미끼 접속·차단 IP 가 없어 구조만 보여 줍니다. 공격자 EC2 에서 미끼(10.x)에 SSH 접속하면 경로가 켜집니다.</p>`;
 else if(!tl)body=`${mapSvg(null)}<p class="panel-loading">불러오는 중…</p>`;
 else if(!tl.ok)body=`${mapSvg(null)}${failed('공격 경로',tl)}`;
 else{steps=tl.data.steps;body=`${warnLines(tl)}${mapSvg(steps)}${stageList(steps)}<p class="muted hp-note">선·번호는 실제 기록으로만 켜집니다. ✓ 완료 · – 기록 없음 · ✕ 실패 · … 진행 중 · ? 읽지 못함. 기록이 없는 단계를 성공으로 그리지 않습니다.</p>`;}
 // v42: 공격 IP 선택과 [다시 재생]을 지도 위 별도 줄이 아니라 카드 머리글 오른쪽(제목과 같은 줄)에 둔다. 지도는 머리글 바로 아래부터 시작한다.
 const tools=ips.length?`<span class="hp-map-tools">${pickerHtml()}<button type="button" class="subtle-button" data-hp-replay>▶ 다시 재생</button></span>`:'';
 return `<section class="panel full-panel" id="hp-map">${header('공격 경로 지도 · 아키텍처 위에서 본 한 공격',tools)}<div class="hp-map">${body}</div></section>`;
}
function timelineSection(){
 const ips=ipChoices();
 const picker='';
 let body;
 if(!ips.length)body='<p class="muted hp-pad">선택한 기간에 미끼 접속·차단 IP 가 없어 보여줄 공격이 없습니다.</p>';
 else if(!S.timeline)body='<p class="panel-loading">불러오는 중…</p>';
 else if(!S.timeline.ok)body=failed('파이프라인 타임라인',S.timeline);
 else{
  const steps=S.timeline.data.steps;
  const first=steps.find(s=>s.at)?.at;
  body=`${warnLines(S.timeline)}<ol class="hp-steps">${steps.map(s=>{
   const [text,mark,color]=STEP_STATE[s.state]||STEP_STATE.unknown;
   const after=s.at&&first?`+${Math.max(0,Math.round((s.at-first)/1000))}초`:'';
   return `<li data-step="${esc(s.key)}" data-state="${esc(s.state)}"><span class="hp-step-mark" style="color:${color};border-color:${color}" aria-hidden="true">${mark}</span>
    <b>${esc(s.label)}</b><span style="color:${color}">${esc(text)}</span>
    <small>${s.at?esc(format(s.at))+' KST '+esc(after):''}</small><small class="muted">${esc(s.detail||'')}</small><small class="muted">${esc(s.source||'')}</small></li>`;}).join('')}</ol>
   <p class="muted hp-note">"기록 없음"은 그 단계가 일어났다는 기록이 없다는 뜻이고, "읽지 못함"은 원천을 읽지 못해 알 수 없다는 뜻입니다.</p>`;
 }
 return `<section class="panel full-panel">${header('파이프라인 타임라인 · 한 공격이 어디까지 갔나','TIMELINE')}<div class="hp-pad">${picker}</div>${body}</section>`;
}

// ── ③ 통계 차트 ────────────────────────────────────────────────────────────
function statsSection(){
 const part=S.stats;
 if(!part.ok)return `<section class="panel full-panel">${header('통계','STATISTICS')}${failed('허니팟 통계',part)}</section>`;
 const d=part.data,t=d.totals;
 if(!t.sessions)return `<section class="panel full-panel">${header('통계','STATISTICS')}${warnLines(part)}<div class="empty"><strong>선택한 기간에 미끼 접속이 없습니다</strong>로그를 읽었고 세션이 0개입니다. 시험 접속(ssh)을 해 보세요.</div></section>`;
 const label=(id,text)=>canvas(id,text);
 return `<section class="panel full-panel">${header('통계 · 접속과 명령','STATISTICS')}${warnLines(part)}
  <div class="hp-totals"><div><b>${t.sessions}</b>세션</div><div><b>${t.uniqueIps}</b>출발지 IP</div><div><b>${t.commands}</b>명령</div><div><b>${t.unanalyzed}</b>분석 대기·없음</div></div>
  <div class="hp-charts">
   <div class="hp-chart wide"><h3>시간대별 접속·명령</h3><div class="hp-canvas">${label('hp-chart-timeline','시간대별 접속 세션과 명령 수')}</div></div>
   <div class="hp-chart"><h3>출발지 IP 상위</h3><div class="hp-canvas">${label('hp-chart-ips','출발지 IP 상위 세션 수')}</div></div>
   <div class="hp-chart"><h3>명령 상위</h3><div class="hp-canvas">${label('hp-chart-commands','실행 시도 명령 상위')}</div></div>
   <div class="hp-chart"><h3>공격 의도(AI 분석)</h3><div class="hp-canvas">${label('hp-chart-intents','AI 분석 공격 의도 분포')}</div></div>
   <div class="hp-chart"><h3>위험도(AI 분석)</h3><div class="hp-canvas">${label('hp-chart-severity','AI 분석 위험도 분포')}</div></div>
   <div class="hp-chart"><h3>로그인 시도 사용자명 상위</h3><div class="hp-canvas">${label('hp-chart-users','로그인 시도 사용자명 상위')}</div></div>
  </div><p class="muted hp-note">의도·위험도는 AI 분석의 참고 값이며 차단·해제 판단에 쓰지 않습니다. 비밀번호는 집계하지 않습니다.</p></section>`;
}
const TICK='#4f5b58',GRID='#dfe6e3';
const TOOLTIP={backgroundColor:'#d8e6f3',titleColor:'#0f0f0f',bodyColor:'#0e1e2a',padding:10};  // charts.js 기본값과 같다(plugins 를 넘기면 통째로 바뀌므로 다시 지정)
const opts=(extra={})=>({...extra,plugins:{legend:{display:false},tooltip:TOOLTIP,...(extra.plugins||{})}});
const axis=(extra={})=>({beginAtZero:true,ticks:{precision:0,color:TICK},grid:{color:GRID},border:{color:GRID},...extra});
const catAxis=(extra={})=>({ticks:{color:TICK},grid:{display:false},border:{color:GRID},...extra});
const horizontal=(id,rows,color,label)=>drawChart(id,'bar',{labels:rows.map(r=>String(r.key??r.ip).slice(0,40)),datasets:[{label,data:rows.map(r=>r.count??r.sessions),backgroundColor:color,borderRadius:4,maxBarThickness:22}]},
 opts({indexAxis:'y',scales:{x:axis(),y:catAxis()}}));
function drawCharts(){
 if(!S.stats?.ok||!S.stats.data.totals.sessions)return;
 const d=S.stats.data,span=(Date.parse(d.to)-Date.parse(d.from))/3600000;
 drawChart('hp-chart-timeline','bar',{labels:d.timeline.map(b=>formatAt(b.at,span)),datasets:[
  {label:'세션',data:d.timeline.map(b=>b.sessions),backgroundColor:CH.mint,borderRadius:4},{label:'명령',data:d.timeline.map(b=>b.commands),backgroundColor:CH.blue,borderRadius:4}]},
  opts({plugins:{legend:{display:true,labels:{color:TICK,boxWidth:12}}},scales:{y:axis(),x:catAxis()}}));
 horizontal('hp-chart-ips',d.topIps.map(r=>({key:r.ip,count:r.sessions})),CH.mint,'세션');
 horizontal('hp-chart-commands',d.topCommands,CH.blue,'횟수');
 horizontal('hp-chart-users',d.topUsers,CH.amber,'시도');
 const donut=(id,rows,names,colors)=>drawChart(id,'doughnut',{labels:rows.map(r=>names[r.key]),datasets:[{data:rows.map(r=>r.count),backgroundColor:rows.map(r=>colors[r.key]),borderWidth:2,borderColor:'#ebefed'}]},
  opts({cutout:'62%',plugins:{legend:{display:true,position:'right',labels:{color:TICK,boxWidth:10}}}}));
 donut('hp-chart-intents',d.intents,INTENT_KO,INTENT_COLOR);
 donut('hp-chart-severity',d.severities,SEVERITY_KO,SEVERITY_COLOR);
}

// ── ④ 관계 그래프 ──────────────────────────────────────────────────────────
// d3-force 로 처음 배치를 계산한 뒤(애니메이션 없음) SVG 문자열을 esc() 로 만든다. v42: ① 글자가 겹치지 않게 자리를 고른다(네 방향 후보,
// 자리가 없으면 글자를 숨기고 마우스를 올리면 툴팁) ② 노드를 끌어 옮길 수 있다 ③ 노드에 마우스를 올리면 이어진 노드만 강조한다.
// 노드를 누르면(끌지 않고) 세션 상세·IP 타임라인으로 간다.
const W=1040,H=540,LABEL_FS=12.5,NODE_R={ip:13,session:8,command:5};
function layout(graph){
 const key=JSON.stringify([graph.nodes.map(n=>n.id),graph.links.length]);
 if(S.layoutKey===key&&S.layout)return S.layout;
 const d3=window.d3force;
 const nodes=graph.nodes.map(n=>({...n})),links=graph.links.map(l=>({...l}));
 if(!d3)return {nodes:nodes.map((n,i)=>({...n,x:60+(i%14)*70,y:50+Math.floor(i/14)*60})),links,plain:true};
 const room=n=>n.type==='ip'?34:n.type==='session'?15:26;   // 글자가 들어갈 여유까지 충돌 반경에 포함
 const sim=d3.forceSimulation(nodes).force('link',d3.forceLink(links).id(n=>n.id).distance(l=>l.target.type==='command'?95:66).strength(.7))
  .force('charge',d3.forceManyBody().strength(-300)).force('center',d3.forceCenter(W/2,H/2)).force('collide',d3.forceCollide(room).iterations(2))
  .force('x',d3.forceX(W/2).strength(.03)).force('y',d3.forceY(H/2).strength(.05)).stop();
 for(let i=0;i<320;i++)sim.tick();
 const clamp=(v,max)=>Math.max(22,Math.min(max-22,v));
 nodes.forEach(n=>{n.x=clamp(n.x,W);n.y=clamp(n.y,H);});
 S.layout={nodes,links:links.map(l=>({source:l.source.id||l.source,target:l.target.id||l.target}))};S.layoutKey=key;
 return S.layout;
}
const labelOf=n=>n.type==='ip'?String(n.label).slice(0,20):n.type==='command'?String(n.label).slice(0,22):'';
const textW=t=>{let w=0;for(const ch of t)w+=ch.codePointAt(0)>0x2e7f?LABEL_FS:/[A-Z0-9mwMW@%]/.test(ch)?LABEL_FS*.68:/[ilj.,:;'|! ]/.test(ch)?LABEL_FS*.36:LABEL_FS*.6;return w;};
// 글자 자리 정하기: IP → 세션 수가 많은 명령 순으로, 노드 오른쪽·왼쪽·위·아래 중 다른 글자·노드와 겹치지 않는 첫 자리. 없으면 글자를 그리지 않는다.
export function placeLabels(nodes,width=W,height=H){
 const boxes=[],out=new Map(),circles=nodes.map(n=>({x:n.x,y:n.y,r:(NODE_R[n.type]||6)+2}));
 const hit=b=>boxes.some(o=>b.x<o.x+o.w&&b.x+b.w>o.x&&b.y<o.y+o.h&&b.y+b.h>o.y)||circles.some(c=>b.x<c.x+c.r&&b.x+b.w>c.x-c.r&&b.y<c.y+c.r&&b.y+b.h>c.y-c.r);
 const order=nodes.filter(n=>labelOf(n)).sort((a,b)=>(a.type==='ip'?0:1)-(b.type==='ip'?0:1)||(b.count||b.sessions||0)-(a.count||a.sessions||0));
 for(const n of order){
  const t=labelOf(n),w=textW(t)+4,h=LABEL_FS+3,rr=(NODE_R[n.type]||6)+4;
  const spots=[{x:n.x+rr,y:n.y-h/2,a:'start'},{x:n.x-rr-w,y:n.y-h/2,a:'end'},{x:n.x-w/2,y:n.y-rr-h,a:'middle'},{x:n.x-w/2,y:n.y+rr,a:'middle'}];
  for(const c of spots){
   const b={x:c.x,y:c.y,w,h};
   if(b.x<2||b.x+b.w>width-2||b.y<2||b.y+b.h>height-2||hit(b))continue;
   boxes.push(b);out.set(n.id,{x:c.a==='start'?c.x:c.a==='end'?c.x+w:c.x+w/2,y:c.y+h-3,anchor:c.a});break;
  }
 }
 return out;
}
function graphSection(){
 const part=S.stats;
 if(!part?.ok||!part.data.totals.sessions)return '';
 const g=part.data.graph,hidden=g.hidden;
 const lay=layout(g),at=Object.fromEntries(lay.nodes.map(n=>[n.id,n])),labels=placeLabels(lay.nodes);
 const lines=lay.links.map(l=>at[l.source]&&at[l.target]?`<line data-s="${esc(l.source)}" data-t="${esc(l.target)}" x1="${at[l.source].x.toFixed(1)}" y1="${at[l.source].y.toFixed(1)}" x2="${at[l.target].x.toFixed(1)}" y2="${at[l.target].y.toFixed(1)}"/>`:'').join('');
 const dots=lay.nodes.map(n=>{
  const r=NODE_R[n.type]||6,fill=n.type==='ip'?CH.mint:n.type==='session'?(INTENT_COLOR[n.intent]||CH.gray):CH.ink;
  const name=n.type==='ip'?n.label:n.type==='session'?`세션 ${n.label} · ${INTENT_KO[n.intent]||'미상'}`:n.label;
  const tip=`<title>${esc(name)}</title>`,spot=labels.get(n.id);
  const text=labelOf(n)?`<text class="hp-lbl" ${spot?`x="${spot.x.toFixed(1)}" y="${spot.y.toFixed(1)}" text-anchor="${spot.anchor}"`:'hidden'}>${esc(labelOf(n))}</text>`:'';
  return `<g class="hp-node hp-node-${esc(n.type)}" tabindex="0" role="button" data-hp-node="${esc(n.id)}" aria-label="${esc(name)}"><circle cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="${r}" fill="${fill}"/>${text}${tip}</g>`;
 }).join('');
 const more=hidden.ips||hidden.sessions||hidden.commands?`<p class="muted hp-note">화면이 복잡해지지 않도록 일부만 그렸습니다: 외 IP ${hidden.ips}개 · 세션 ${hidden.sessions}개 · 명령 ${hidden.commands}종.</p>`:'';
 const hiddenLabels=lay.nodes.filter(n=>labelOf(n)&&!labels.has(n.id)).length;
 return `<section class="panel full-panel">${header('공격 관계 그래프 · IP → 세션 → 명령',`<button type="button" class="subtle-button" data-hp-relayout>배치 다시 계산</button>`)}${warnLines(part)}
  <svg class="hp-graph" viewBox="0 0 ${W} ${H}" role="group" aria-label="출발지 IP, 세션, 명령의 관계 그래프"><g class="hp-links">${lines}</g>${dots}</svg>
  <div class="hp-legend"><span><i style="background:${CH.mint}"></i>출발지 IP</span>${Object.entries(INTENT_KO).map(([k,v])=>`<span><i style="background:${INTENT_COLOR[k]}"></i>세션 · ${esc(v)}</span>`).join('')}<span><i style="background:${CH.ink}"></i>명령</span></div>
  ${lay.plain?'<p class="muted hp-note">그래프 배치 라이브러리를 불러오지 못해 격자로 표시합니다.</p>':''}${more}
  <p class="muted hp-note">노드를 끌어 옮기거나 마우스를 올려 이어진 노드를 볼 수 있습니다. 노드를 누르면 아래 타임라인·세션 상세로 이동합니다.${hiddenLabels?` 글자가 겹치는 ${hiddenLabels}개는 숨겼습니다(마우스를 올리면 이름이 보입니다).`:''}</p></section>`;
}
// 끌기: 노드 위치를 S.layout 에 저장하므로 자동 새로고침으로 다시 그려도 옮긴 자리가 유지된다. 끌지 않고 누르기만 하면 기존 클릭(상세 열기)이다.
let drag=null;
function svgPoint(svg,e){
 const m=svg.getScreenCTM?.();if(!m)return null;
 const p=new DOMPoint(e.clientX,e.clientY).matrixTransform(m.inverse());
 return {x:Math.max(14,Math.min(W-14,p.x)),y:Math.max(14,Math.min(H-14,p.y))};
}
function moveNode(svg,id,x,y){
 const node=S.layout.nodes.find(n=>n.id===id);if(!node)return;
 node.x=x;node.y=y;
 const g=[...svg.querySelectorAll('[data-hp-node]')].find(el=>el.dataset.hpNode===id);
 const circle=g?.querySelector('circle');if(circle){circle.setAttribute('cx',x.toFixed(1));circle.setAttribute('cy',y.toFixed(1));}
 for(const line of svg.querySelectorAll('line')){
  if(line.dataset.s===id){line.setAttribute('x1',x.toFixed(1));line.setAttribute('y1',y.toFixed(1));}
  if(line.dataset.t===id){line.setAttribute('x2',x.toFixed(1));line.setAttribute('y2',y.toFixed(1));}
 }
 const labels=placeLabels(S.layout.nodes);
 for(const el of svg.querySelectorAll('[data-hp-node]')){
  const text=el.querySelector('text');if(!text)continue;
  const spot=labels.get(el.dataset.hpNode);
  if(!spot){text.setAttribute('hidden','');continue;}
  text.removeAttribute('hidden');text.setAttribute('x',spot.x.toFixed(1));text.setAttribute('y',spot.y.toFixed(1));text.setAttribute('text-anchor',spot.anchor);
 }
}
function onPointerDown(e){
 const el=e.target.closest?.('[data-hp-node]'),svg=el?.closest('svg.hp-graph');
 if(!el||!svg||!S.layout||e.button>0)return;
 drag={id:el.dataset.hpNode,svg,sx:e.clientX,sy:e.clientY,moved:false};
 const move=ev=>{
  if(!drag)return;
  if(!drag.moved&&Math.hypot(ev.clientX-drag.sx,ev.clientY-drag.sy)<4)return;
  drag.moved=true;
  const p=svgPoint(drag.svg,ev);if(p)moveNode(drag.svg,drag.id,p.x,p.y);
 };
 const up=()=>{
  window.removeEventListener('pointermove',move);window.removeEventListener('pointerup',up);window.removeEventListener('pointercancel',up);
  if(drag?.moved){S.justDragged=true;setTimeout(()=>{S.justDragged=false;},0);}
  drag=null;
 };
 window.addEventListener('pointermove',move);window.addEventListener('pointerup',up);window.addEventListener('pointercancel',up);
}
function highlight(e,on){
 const el=e.target.closest?.('[data-hp-node]'),svg=el?.closest('svg.hp-graph');
 if(!svg||!S.layout)return;
 svg.classList.toggle('hp-focus',on);
 const id=el.dataset.hpNode,near=new Set([id]);
 for(const l of S.layout.links){if(l.source===id)near.add(l.target);if(l.target===id)near.add(l.source);}
 for(const g of svg.querySelectorAll('[data-hp-node]'))g.classList.toggle('hp-hl',on&&near.has(g.dataset.hpNode));
 for(const line of svg.querySelectorAll('line'))line.classList.toggle('hp-hl',on&&(line.dataset.s===id||line.dataset.t===id));
}

// ── ⑤ 세션 목록·재생 ──────────────────────────────────────────────────────
function sessionsSection(){
 const part=S.sessions;
 if(!part.ok)return `<section class="panel full-panel">${header('세션','SESSIONS')}${failed('세션 목록',part)}</section>`;
 const d=part.data;
 const rows=d.items.map(s=>{
  const b=block(s.srcIp),bs=b?BLOCK_STATE[b.state]:null;
  return `<tr data-session="${esc(s.sessionId)}"><td>${esc(format(s.startedAt))}</td><td>${ipCell(s.srcIp)}</td><td><code>${esc(s.sessionId)}</code></td>
   <td>${s.authCount}</td><td>${s.commandCount}</td><td>${s.intent?esc(INTENT_KO[s.intent]||s.intent):'<span class="muted">분석 없음</span>'}</td>
   <td>${s.severity?esc(SEVERITY_KO[s.severity]||s.severity):'—'}</td><td>${s.analyzed?(s.aiApplied?'AI':'규칙'):'—'}</td>
   <td>${bs?pill(bs[0],bs[1]):'<span class="muted">—</span>'}</td>
   <td><button type="button" class="subtle-button" data-hp-session="${esc(s.sessionId)}">재생</button></td></tr>`;
 }).join('');
 const intents=Object.entries(INTENT_KO).map(([k,v])=>`<option value="${k}"${S.filter.intent===k?' selected':''}>${esc(v)}</option>`).join('');
 const filter=`<div class="hp-pad hp-filter"><label class="drill-field"><span>출발지 IP</span><input type="text" data-hp-filter-ip value="${esc(S.filter.ip)}" maxlength="15" placeholder="10.0.2.55"></label>
  <label class="drill-field"><span>의도</span><select data-hp-filter-intent><option value="">전체</option>${intents}</select></label>
  <button type="button" class="subtle-button" data-hp-filter-apply>조회</button></div>`;
 return `<section class="panel full-panel">${header('세션 · 미끼에서 한 작업',`${d.total}개`)}${filter}${warnLines(part)}
  ${d.items.length?`<div class="table-scroll"><table><caption class="sr-only">미끼서버 세션 목록</caption>
  <thead><tr><th>시각(KST)</th><th>출발지 IP</th><th>세션</th><th>로그인 시도</th><th>명령</th><th>의도</th><th>위험도</th><th>분석</th><th>차단 상태</th><th></th></tr></thead><tbody>${rows}</tbody></table></div>`
   :'<p class="muted hp-pad">조건에 맞는 세션이 없습니다(로그는 정상적으로 읽었습니다).</p>'}
  ${d.nextCursor?`<div class="hp-pad"><button type="button" class="subtle-button" data-hp-more="${esc(d.nextCursor)}">더 보기</button></div>`:''}</section>`;
}
// ── 세션 재생(v42 재구성) ──────────────────────────────────────────────────────
// 전에는 명령과 응답 원문을 한 덩어리로 붙였다(제어 문자·ANSI 색 코드·\r\n 이 그대로 섞이고, 로그인 시도는 아래 표에 따로 있었다).
// 지금은 ① 별도 창에서 열고 ② 접속 → 로그인 시도 → 명령·응답 → 종료를 시각 순서 한 흐름으로 보이고 ③ 응답의 제어 문자를 정리하며
// ④ 줄이 시각 간격대로 차례로 나타난다(다시 재생·바로 보기). 텍스트는 처음부터 DOM 에 모두 있다 — 재생은 CSS 애니메이션일 뿐이다.
export function cleanOutput(value,limit=2000){
 if(value==null)return null;
 let text=String(value)
  .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g,'')          // OSC(창 제목 등)
  .replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g,'')                    // CSI(색·커서 이동)
  .replace(/\x1b[@-Z\\-_]/g,'')
  .replace(/\r\n?/g,'\n')
  .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,'')
  .replace(/[ \t]+$/gm,'').replace(/\n{3,}/g,'\n\n').replace(/^\n+|\s+$/g,'');
 if(text.length>limit)text=`${text.slice(0,limit)}\n… (이하 ${text.length-limit}자 생략)`;
 return text;
}
const fmtSec=ms=>`+${(Math.max(0,ms)/1000).toFixed(1)}초`;
function replayLines(s){
 const t0=s.startedAt||s.commands[0]?.at||s.authAttempts[0]?.at||0;
 const events=[];
 if(s.hasConnect!==false)events.push({at:s.startedAt,kind:'connect'});
 for(const x of s.authAttempts)events.push({at:x.at,kind:'auth',x});
 for(const c of s.commands)events.push({at:c.at,kind:'cmd',c});
 if(s.endedAt)events.push({at:s.endedAt,kind:'end'});
 events.sort((a,b)=>(a.at||0)-(b.at||0));
 let delay=0.15,prev=null;const out=[];
 for(const e of events){
  if(prev!=null&&e.at!=null)delay+=Math.min(1.6,Math.max(0.45,(e.at-prev)/1000*0.25));
  if(e.at!=null)prev=e.at;
  const tag=`<span class="hp-ts">${e.at!=null&&t0?esc(fmtSec(e.at-t0)):'&nbsp;'}</span>`;
  const row=(cls,inner,extra='')=>out.push(`<span class="hp-line ${cls}" style="--d:${delay.toFixed(2)}s">${tag}${inner}</span>${extra}`);
  if(e.kind==='connect')row('hp-sys',`<span class="hp-msg">접속 ${esc(s.srcIp||'출발지 미상')}${s.srcPort?':'+esc(s.srcPort):''}</span>`);
  else if(e.kind==='auth'){
   const pw=e.x.password==null?`<span class="hp-mask">${'•'.repeat(Math.min(12,e.x.passwordLength||0))}</span> <span class="muted">(${esc(e.x.passwordLength??'?')}자, 가림)</span>`:`<code>${esc(e.x.password)}</code>`;
   row('hp-sys hp-auth',`<span class="hp-msg">로그인 시도 · 사용자명 <code>${esc(e.x.user||'—')}</code> · 비밀번호 ${pw}</span>`);
  }else if(e.kind==='cmd'){
   row('hp-cmd',`<span class="hp-cmdline"><span class="hp-ps">$ </span><span class="hp-in">${esc(e.c.command)}</span></span>`);
   delay+=0.3;
   const res=cleanOutput(e.c.response);
   out.push(res==null?`<span class="hp-line hp-res" style="--d:${delay.toFixed(2)}s"><span class="hp-ts">&nbsp;</span><span class="hp-none">(응답 기록 없음)</span></span>`
    :res===''?`<span class="hp-line hp-res" style="--d:${delay.toFixed(2)}s"><span class="hp-ts">&nbsp;</span><span class="hp-none">(출력 없음)</span></span>`
    :`<span class="hp-line hp-res" style="--d:${delay.toFixed(2)}s"><span class="hp-ts">&nbsp;</span><span class="hp-out">${esc(res)}</span></span>`);
  }else row('hp-sys',`<span class="hp-msg">세션 종료</span>`);
 }
 return out.join('');
}
function detailPanel(){
 const part=S.detail;
 if(!part)return '';
 if(part.loading)return '<div class="hp-detail"><h2 id="replay-title" class="hp-replay-title">세션 재생</h2><p class="panel-loading">세션을 불러오는 중…</p></div>';
 if(!part.ok)return `<div class="hp-detail"><h2 id="replay-title" class="hp-replay-title">세션 재생</h2>${failed('세션 상세',part)}<div class="hp-pad"><button type="button" class="text-button" data-hp-close-detail>닫기</button></div></div>`;
 const s=part.data,a=s.analysis;
 const length=s.startedAt&&s.endedAt?fmtSec(s.endedAt-s.startedAt).replace('+',''):'';
 const reveal=canWrite()?`<button type="button" class="subtle-button" data-hp-reveal>${S.reveal?'비밀번호 가리기':'비밀번호 원문 보기'}</button>`:'<span class="muted">비밀번호 원문은 조치 담당 계정만 볼 수 있습니다.</span>';
 const facts=[`로그인 시도 ${s.authCount}회`,`명령 ${s.commandCount}개`,length?`길이 ${length}`:'',
  s.intent?`의도 ${INTENT_KO[s.intent]||s.intent}`:'의도 분석 없음',s.severity?`위험도 ${SEVERITY_KO[s.severity]||s.severity}`:'',s.analyzed?(s.aiApplied?'AI 분석':'규칙 분석'):''].filter(Boolean);
 const ai=a?`<div class="hp-ai"><b>AI 분석</b> <span class="hp-badge">참고용 · 차단 판단에 쓰지 않음</span>
   <p>${a.summary?esc(a.summary):'요약 없음'}</p><p class="muted">${a.aiApplied?'AI 가 만든 분석':'AI 미적용(규칙 기반 대체 판정)'} · 의도 ${esc(INTENT_KO[a.intent]||a.intent)} · 위험도 ${a.severity?esc(SEVERITY_KO[a.severity]):'미상'}</p>
   ${a.iocs.length?`<p><b>IOC</b> ${a.iocs.map(i=>`<code>${esc(i)}</code>`).join(' ')}</p>`:''}</div>`:'<p class="muted hp-pad">세션 종료·분석 기록이 아직 없습니다.</p>';
 const empty=!s.commands.length&&!s.authAttempts.length;
 return `<div class="hp-detail" data-detail="${esc(s.sessionId)}">
  <div class="hp-replay-head"><div><h2 id="replay-title" class="hp-replay-title">세션 재생</h2>
    <p class="hp-replay-sub"><code>${esc(s.sessionId)}</code> · ${esc(s.srcIp||'출발지 미상')} · ${esc(format(s.startedAt))} KST</p></div>
   <div class="hp-replay-ctl"><button type="button" class="subtle-button" data-hp-play>▶ 다시 재생</button><button type="button" class="subtle-button" data-hp-skip>⏭ 바로 보기</button><button type="button" class="dialog-close" data-hp-close-detail aria-label="세션 재생 닫기">×</button></div></div>
  <ul class="hp-facts">${facts.map(f=>`<li>${esc(f)}</li>`).join('')}</ul>
  ${warnLines(part)}
  <pre class="hp-terminal${S.animate?' play':''}" aria-label="세션 재생(접속·로그인 시도·입력한 명령과 미끼가 보낸 응답)">${empty?'<span class="hp-none">기록된 로그인 시도나 명령이 없습니다(접속만 했습니다).</span>':replayLines(s)}</pre>
  <div class="hp-pad">${reveal}</div>
  ${ai}<div class="hp-pad hp-close-row"><button type="button" class="text-button" data-hp-close-detail>닫기</button></div></div>`;
}
function paintDetail(){
 const dialog=$('#replay-dialog'),box=$('#replay-content');
 if(!dialog||!box)return;
 if(!S.detail){box.innerHTML='';if(dialog.open)dialog.close();return;}
 box.innerHTML=detailPanel();
 if(!dialog.open)dialog.showModal();
}

// ── ⑥ 차단 IP 관리 ────────────────────────────────────────────────────────
function expiryText(i){
 if(i.state==='blocked'||i.state==='expiring'||i.state==='applying')return i.expiresAt?esc(format(i.expiresAt)):'영구';
 return i.expiresAt?`<span class="muted">${esc(format(i.expiresAt))}</span>`:'—';
}
function blockActions(i){
 if(!canWrite())return '<span class="muted">권한 없음</span>';
 const can=['blocked','expiring','failed','mismatch','unrecorded'].includes(i.state)&&i.state!=='releasing';
 const parts=[];
 if(can)parts.push(`<button type="button" class="subtle-button" data-hp-release="${esc(i.ip)}">해제</button>`);
 if(i.status==='ACTIVE')parts.push(`<button type="button" class="subtle-button" data-hp-period="${esc(i.ip)}">기간</button>`);
 if(i.status!=='UNRECORDED')parts.push(`<button type="button" class="subtle-button" data-hp-allow="${esc(i.ip)}">${i.allowlisted?'예외 해제':'예외 등록'}</button>`);
 return parts.join(' ')||'—';
}
function blockRow(i){
 const [text,color]=BLOCK_STATE[i.state]||['알 수 없음',GRAY],s=i.sessions;
 const why=i.mismatch?`<small class="hp-mismatch">⚠ ${esc(MISMATCH_KO[i.mismatch]||i.mismatch)}</small>`:'';
 const rel=i.releasedAt?`<small>${esc(format(i.releasedAt))} · ${esc(i.releasedBy||'')} · ${esc(i.releaseReason||'')}</small>`:'';
 const err=i.lastError?`<small class="hp-mismatch">${esc(i.lastError)}</small>`:'';
 const evidence=s===null||s===undefined?'<span class="muted">근거를 읽지 못함</span>'
  :s.sessionCount?`세션 ${s.sessionCount} · 명령 ${s.commandCount}<small>${esc((s.topCommands||[]).map(c=>c.key).join(' | '))}</small>`
  :`<span class="muted">이 기간 미끼 세션 없음${i.evidence?.hits?` · 차단 당시 접속 ${i.evidence.hits}회`:''}</span>`;
 return `<tr data-block="${esc(i.ip)}" data-state="${esc(i.state)}"><td>${ipCell(i.ip)}${i.allowlisted?' <span class="hp-badge">예외 등록</span>':''}</td>
  <td>${pill(text,color)}${why}${err}</td><td>${esc(SOURCE_KO[i.source]||i.source||'—')}</td><td>${i.naclRule??i.ruleNumber??'—'}</td>
  <td>${i.blockedAt?esc(format(i.blockedAt)):'—'}</td><td>${expiryText(i)}</td><td>${evidence}${rel}</td><td class="hp-actions">${blockActions(i)}</td></tr>`;
}
function actionForm(){
 const a=S.action;if(!a)return '';
 const item=S.blocklist.data.items.find(i=>i.ip===a.ip);if(!item)return '';
 const durations=S.blocklist.data.durations;
 let title,extra,submit;
 if(a.kind==='release'){
  title=`${esc(a.ip)} 오탐 해제 — NACL 의 Deny 규칙 ${item.naclRule??item.ruleNumber??''}번을 지웁니다`;
  extra=`<label class="hp-check"><input type="checkbox" data-hp-allowlist> 예외 목록에도 추가 — 이후 이 IP 는 자동 차단하지 않고 '수동 대응 필요'로만 기록</label>`;
  submit='해제 실행';
 }else if(a.kind==='period'){
  title=`${esc(a.ip)} 차단 기간 변경 — 선택한 시점부터 다시 셉니다`;
  extra=`<label class="drill-field"><span>기간</span><select data-hp-duration>${durations.map(d=>`<option value="${d.hours}">${esc(d.label)}</option>`).join('')}</select></label>`;
  submit='기간 적용';
 }else{
  const on=!item.allowlisted;
  title=`${esc(a.ip)} ${on?'오탐 예외 등록 — 이후 자동 차단하지 않음':'오탐 예외 해제 — 다시 자동 차단 대상'}`;
  extra='';submit=on?'예외 등록':'예외 해제';
 }
 return `<div class="hp-form" data-hp-form="${esc(a.kind)}"><h3>${title}</h3>${extra}
  <label class="drill-field"><span>사유(필수, 500자 이하)</span><textarea data-hp-reason maxlength="500" rows="2" required></textarea></label>
  <div class="drill-actions"><button type="button" class="primary-button" data-hp-submit ${S.busy?'disabled':''}>${esc(submit)}</button><button type="button" class="cancel-button" data-hp-cancel>취소</button></div>
  <p class="muted hp-note">실행 접수는 해제 완료가 아닙니다. 완료는 다음 조회에서 NACL 을 다시 읽어 확인합니다. 모든 변경은 조치 이력과 감사 기록에 남습니다.</p></div>`;
}
function blocklistSection(){
 const part=S.blocklist;
 if(!part.ok)return `<section class="panel full-panel">${header('차단 IP 관리','BLOCKLIST')}${failed('차단 IP 목록',part)}</section>`;
 const d=part.data,c=d.counts;
 const summary=`<div class="hp-totals"><div><b>${c.blocked+c.expiring}</b>차단 중</div><div><b>${c.releasing+c.applying}</b>처리 중</div><div><b>${c.released+c.expired}</b>해제됨</div><div><b>${c.allowlisted}</b>예외 등록</div><div class="${c.mismatch?'hp-alert':''}"><b>${c.mismatch}</b>불일치</div></div>`;
 const tools=`<div class="hp-pad hp-tools"><button type="button" class="subtle-button" data-hp-export="csv">CSV 내려받기</button>
  <button type="button" class="subtle-button" data-hp-export="json">JSON 내려받기</button><button type="button" class="subtle-button" data-hp-print>보고서 인쇄</button>
  <span class="muted">기본 차단 기간: ${d.defaultTtlHours===0?'영구':d.defaultTtlHours==null?'확인 불가':esc(String(d.defaultTtlHours))+'시간'} · NACL ${esc(d.naclId)}</span></div>`;
 const rows=d.items.map(blockRow).join('');
 return `<section class="panel full-panel" id="hp-blocklist">${header('차단 IP 관리 · 블랙리스트',esc(String(d.items.length))+'개')}${summary}${warnLines(part)}${tools}
  ${d.items.length?`<div class="table-scroll"><table><caption class="sr-only">차단 IP 목록</caption>
  <thead><tr><th>IP</th><th>상태</th><th>차단 경로</th><th>NACL 규칙</th><th>차단 시각</th><th>만료</th><th>근거(미끼 세션)</th><th>조치</th></tr></thead><tbody>${rows}</tbody></table></div>`
   :'<p class="muted hp-pad">차단된 IP 가 없습니다(표와 NACL 을 모두 읽었고 둘 다 비어 있습니다).</p>'}
  ${actionForm()}
  <p class="muted hp-note">실제 차단의 기준은 NACL 1~99번 Deny 입니다. 표와 다르면 '불일치'로 표시하고 숨기지 않습니다. ${canWrite()?'':'조치 담당 계정만 해제·기간 변경·예외 등록을 할 수 있습니다.'}</p></section>${reportSection()}`;
}
// 인쇄용 보고서: 화면에는 숨기고, 인쇄할 때만 보인다(local.css @media print).
function reportSection(){
 if(!S.blocklist?.ok)return '';
 const d=S.blocklist.data;
 const rows=d.items.map(i=>`<tr><td>${esc(i.ip)}</td><td>${esc((BLOCK_STATE[i.state]||['알 수 없음'])[0])}${i.allowlisted?' · 예외':''}</td><td>${esc(SOURCE_KO[i.source]||i.source||'—')}</td>
  <td>${i.blockedAt?esc(format(i.blockedAt)):'—'}</td><td>${i.expiresAt?esc(format(i.expiresAt)):(i.status==='ACTIVE'?'영구':'—')}</td>
  <td>${i.sessions?`세션 ${i.sessions.sessionCount} · 명령 ${i.sessions.commandCount}<br>${esc((i.sessions.intents||[]).map(x=>INTENT_KO[x]||x).join(', '))}<br>${esc((i.sessions.topCommands||[]).map(c=>c.key).join(' | '))}`:'근거 미확인'}</td></tr>`).join('');
 const released=d.items.filter(i=>i.releasedAt).map(i=>`<tr><td>${esc(i.ip)}</td><td>${esc(format(i.releasedAt))}</td><td>${esc(i.releasedBy||'')}</td><td>${esc(i.releaseReason||'')}</td></tr>`).join('');
 return `<section id="hp-report" class="hp-report" hidden><h1>허니팟 차단 IP 보고서</h1>
  <p>조회 기간 ${esc(d.from)} ~ ${esc(d.to)} (UTC) · 출력 ${esc(new Date().toISOString())} · 출력자 ${esc(config().user?.name||'')}</p>
  <h2>차단 IP 목록</h2><table><thead><tr><th>IP</th><th>상태</th><th>차단 경로</th><th>차단 시각(KST)</th><th>만료</th><th>근거</th></tr></thead><tbody>${rows||'<tr><td colspan="6">없음</td></tr>'}</tbody></table>
  <h2>해제 이력</h2><table><thead><tr><th>IP</th><th>해제 시각(KST)</th><th>해제자</th><th>사유</th></tr></thead><tbody>${released||'<tr><td colspan="4">없음</td></tr>'}</tbody></table>
  <p>AI 분석은 참고용이며 차단·해제 판단에 쓰지 않았습니다. 실제 차단 상태의 기준은 NACL 입니다.</p></section>`;
}

// ── 화면 조립·불러오기 ───────────────────────────────────────────────────────
function paint(){
 const intro=`<div class="view-intro"><span>미끼서버(허니팟)가 잘 동작하는지 확인하고, 차단된 IP 를 보고·해제·기간 관리합니다. 기간은 위의 기간 버튼을 따릅니다.</span></div>`;
 const msg=S.message?`<p class="hp-message" role="status" data-kind="${esc(S.message.kind)}">${esc(S.message.text)}</p>`:'';
 if(!S.status.ok||!S.status.data.deployed)return intro+statusSection();
 return intro+msg+statusSection()+mapSection()+timelineSection()+statsSection()+graphSection()+sessionsSection()+blocklistSection();
}
function repaint(){
 const box=$('#honeypot');if(!box)return;
 ui.operationBusy=Boolean(S.action)||S.busy;     // 변경 양식을 열어 둔 동안은 자동 새로고침이 입력을 지우지 않게 한다
 box.innerHTML=paint();box.dataset.loaded='true';box.removeAttribute('aria-busy');
 drawCharts();
}
function pickIp(){
 if(S.ip&&ipChoices().includes(S.ip))return S.ip;
 const blocked=S.blocklist?.ok?S.blocklist.data.items.find(i=>i.state==='blocked'||i.state==='expiring'):null;
 return blocked?.ip||ipChoices()[0]||'';
}
async function loadTimeline(){
 S.timeline=null;
 if(!S.ip){repaint();return;}
 repaint();
 const ip=S.ip;
 const part=await section(api.honeypotTimeline(ip));
 if(ip!==S.ip)return;                       // 그 사이 다른 IP 를 골랐다
 S.timeline=part;repaint();
 if(part.ok)replayMap($('#hp-map'));   // 지도는 IP 를 고르거나 처음 그릴 때 한 번 재생한다(자동 새로고침마다 깜박이지 않게)
}
async function loadAll(){
 S.status=await section(api.honeypotStatus());
 if(!S.status.ok||!S.status.data.deployed){S.stats=S.sessions=S.blocklist=S.timeline=null;return;}
 [S.stats,S.sessions,S.blocklist]=await Promise.all([section(api.honeypotStats()),
  section(api.honeypotSessions({ip:S.filter.ip,intent:S.filter.intent})),section(api.blocklist())]);
 S.ip=pickIp();
 S.timeline=null;
}
export async function renderHoneypot(){
 const box=$('#honeypot');if(!box)return;
 if(!box._hpBound){box.addEventListener('click',onClick);box.addEventListener('change',onChange);box.addEventListener('keydown',onKeydown);box.addEventListener('pointerdown',onPointerDown);
  box.addEventListener('mouseover',e=>highlight(e,true));box.addEventListener('mouseout',e=>highlight(e,false));box._hpBound=true;}
 const replayDialog=$('#replay-dialog');
 if(replayDialog&&!replayDialog._hpBound){
  replayDialog.addEventListener('click',e=>{if(e.target===replayDialog){S.detail=null;S.reveal=false;paintDetail();return;}onClick(e);});
  replayDialog.addEventListener('close',()=>{S.detail=null;S.reveal=false;});
  replayDialog._hpBound=true;
 }
 const serial=ui.refreshSerial;
 box.setAttribute('aria-busy','true');
 try{
  await loadAll();
  if(serial!==ui.refreshSerial||!box.isConnected)return;
  repaint();
  if(S.status.ok&&S.status.data.deployed)await loadTimeline();
 }finally{box.removeAttribute('aria-busy');}
}

// ── 조작 ──────────────────────────────────────────────────────────────────
const say=(kind,text)=>{S.message={kind,text};};
async function reloadBlocklist(){
 S.blocklist=await section(api.blocklist());
 S.sessions=await section(api.honeypotSessions({ip:S.filter.ip,intent:S.filter.intent}));
 repaint();
}
async function submitAction(){
 const a=S.action,form=$('[data-hp-form]');if(!a||!form||S.busy)return;
 const reason=form.querySelector('[data-hp-reason]').value.trim();
 if(!reason){toast('사유를 입력하세요.');form.querySelector('[data-hp-reason]').focus();return;}
 const item=S.blocklist.data.items.find(i=>i.ip===a.ip);if(!item)return;
 S.busy=true;repaint();
 try{
  if(a.kind==='release'){
   const allowlist=Boolean(form.querySelector('[data-hp-allowlist]')?.checked);
   const result=await api.blocklistRelease(a.ip,{reason,expectedVersion:item.version,allowlist});
   say('ok',result.state==='released'?`${a.ip}: NACL 에 Deny 가 이미 없어 해제로 표시했습니다.`:`${a.ip}: 해제를 접수했습니다(SSM ${result.executionId}). 완료는 NACL 을 다시 읽어 확인합니다 — 잠시 뒤 새로고침하세요.`);
  }else if(a.kind==='period'){
   const hours=Number(form.querySelector('[data-hp-duration]').value);
   await api.blocklistPatch(a.ip,{reason,expectedVersion:item.version,durationHours:hours});
   say('ok',`${a.ip}: 차단 기간을 ${hours===0?'영구':hours+'시간'}으로 바꿨습니다(지금부터).`);
  }else{
   await api.blocklistPatch(a.ip,{reason,expectedVersion:item.version,allowlisted:!item.allowlisted});
   say('ok',`${a.ip}: 오탐 예외를 ${item.allowlisted?'해제':'등록'}했습니다.`);
  }
  S.action=null;S.busy=false;
  await reloadBlocklist();
 }catch(error){
  S.busy=false;say('error',`변경하지 못했습니다: ${error.message}`);
  repaint();
  if(/새로고침|바뀌었/.test(error.message))await reloadBlocklist();
 }
}
async function openSession(id,{reveal=false}={}){
 S.reveal=reveal;S.detail={loading:true};S.animate=false;paintDetail();
 const part=await section(api.honeypotSession(id,{reveal}));
 if(!S.detail)return;                          // 기다리는 동안 창을 닫았다
 S.detail=part.ok?part:{...part,ok:false};
 S.animate=!reveal;                            // 비밀번호 보기 전환 때는 처음부터 다시 재생하지 않는다
 paintDetail();S.animate=false;
}
function replay(skip){
 const term=$('.hp-terminal');if(!term)return;
 term.classList.remove('play','done');void term.offsetWidth;
 term.classList.add(skip?'done':'play');
}
async function selectIp(ip){
 if(!ip||ip===S.ip)return;
 S.ip=ip;await loadTimeline();
 $('.hp-steps')?.scrollIntoView?.({block:'nearest'});
}
async function applyFilter(){
 const ip=($('[data-hp-filter-ip]')?.value||'').trim(),intent=$('[data-hp-filter-intent]')?.value||'';
 if(ip&&!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)){toast('IP 는 10.0.2.55 형식으로 입력하세요.');return;}
 S.filter={ip,intent};
 S.sessions=await section(api.honeypotSessions({ip,intent}));repaint();
}
async function more(cursor){
 const next=await section(api.honeypotSessions({cursor,ip:S.filter.ip,intent:S.filter.intent}));
 if(next.ok&&S.sessions.ok)S.sessions={...next,data:{...next.data,items:[...S.sessions.data.items,...next.data.items]}};
 else say('error',`더 불러오지 못했습니다: ${next.error}`);
 repaint();
}
function exportBlocklist(kind){
 if(!S.blocklist?.ok)return;
 const d=S.blocklist.data,stamp=new Date().toISOString().slice(0,16).replace(/[-:T]/g,'');
 if(kind==='csv')downloadCsv(`blocklist-${stamp}.csv`,blocklistCsv(d.items,iso));
 else downloadFile(`blocklist-${stamp}.json`,JSON.stringify({exportedAt:new Date().toISOString(),from:d.from,to:d.to,naclId:d.naclId,items:d.items},null,1));
}
function printReport(){
 const report=$('#hp-report');if(!report){toast('인쇄할 보고서가 없습니다.');return;}
 report.hidden=false;document.body.classList.add('printing-report');
 const done=()=>{document.body.classList.remove('printing-report');report.hidden=true;window.removeEventListener('afterprint',done);};
 window.addEventListener('afterprint',done);
 try{window.print();}finally{if(!window.matchMedia?.('print').matches)setTimeout(done,500);}
}
function onClick(e){
 const t=e.target;
 if(S.justDragged){S.justDragged=false;return;}
 if(t.closest('[data-hp-relayout]')){S.layoutKey='';S.layout=null;repaint();return;}
 const ip=t.closest('[data-hp-ip]');if(ip){selectIp(ip.dataset.hpIp);return;}
 const node=t.closest('[data-hp-node]');if(node){const [kind,...rest]=node.dataset.hpNode.split(':'),id=rest.join(':');
  if(kind==='ip')selectIp(id);else if(kind==='s')openSession(id);return;}
 const view=t.closest('[data-hp-session]');if(view){openSession(view.dataset.hpSession);return;}
 if(t.closest('[data-hp-reveal]')){const id=S.detail?.data?.sessionId;if(id)openSession(id,{reveal:!S.reveal});return;}
 if(t.closest('[data-hp-close-detail]')){S.detail=null;S.reveal=false;paintDetail();return;}
 if(t.closest('[data-hp-play]')){replay(false);return;}
 if(t.closest('[data-hp-skip]')){replay(true);return;}
 if(t.closest('[data-hp-filter-apply]')){applyFilter();return;}
 const more_=t.closest('[data-hp-more]');if(more_){more(more_.dataset.hpMore);return;}
 const rel=t.closest('[data-hp-release]');if(rel){S.action={kind:'release',ip:rel.dataset.hpRelease};S.message=null;repaint();$('[data-hp-form]')?.scrollIntoView?.({block:'nearest'});return;}
 const per=t.closest('[data-hp-period]');if(per){S.action={kind:'period',ip:per.dataset.hpPeriod};S.message=null;repaint();return;}
 const alw=t.closest('[data-hp-allow]');if(alw){S.action={kind:'allow',ip:alw.dataset.hpAllow};S.message=null;repaint();return;}
 if(t.closest('[data-hp-cancel]')){S.action=null;repaint();return;}
 if(t.closest('[data-hp-submit]')){submitAction();return;}
 const exp=t.closest('[data-hp-export]');if(exp){exportBlocklist(exp.dataset.hpExport);return;}
 if(t.closest('[data-hp-print]')){printReport();return;}
 if(t.closest('[data-hp-replay]')){replayMap($('#hp-map'));return;}
}
function onChange(e){
 const pick=e.target.closest('[data-hp-select]');if(pick)selectIp(pick.value);
}
function onKeydown(e){
 const node=e.target.closest('[data-hp-node]');
 if(node&&(e.key==='Enter'||e.key===' ')){e.preventDefault();node.dispatchEvent(new MouseEvent('click',{bubbles:true}));}
 if(e.key==='Enter'&&e.target.matches('[data-hp-filter-ip]')){e.preventDefault();applyFilter();}
}
