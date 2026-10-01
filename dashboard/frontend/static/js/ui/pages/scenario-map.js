// 보안 시나리오 "경로 지도"(v44): 허니팟 공격 경로 지도와 같은 그림·재생 방식으로, 시나리오마다 다른 경로를 그린다.
// 새 API·AI 가 없다 — 시나리오 카탈로그(sources·response)와 [전부 실행] 항목 상태만 쓴다.
// 관측한 것은 ① 실행 단계뿐이다. 탐지→통합→저장→판정→조치→재검증은 '설계 경로'(점선·파랑)로만 그리고 성공으로 칠하지 않는다.
// 상태 문구·기록 없음 처리는 flow-map.js 의 scenarioStages 를 그대로 쓴다(이벤트 상세 지도와 같은 규칙).
import {esc} from '../components/format.js?v=v46';
import {icon,node,setFont} from './honeypot-map.js?v=v46';
import {FLOW_STATE,FLOW_STAGES,scenarioStages,eventStages,detectorOf} from './flow-map.js?v=v46';

const MINT='#0e8f80',SOFT='#4186be',AMBER='#a88a0d',RED='#d63a44',GRAY='#57665c';
const ROLE={attack:RED,observe:SOFT,respond:MINT};
const on=s=>['done','pending','failed','unknown','design'].includes(s);

// 그림 위 고정 노드(좌표는 flow-map 과 같은 1240×650 캔버스).
const POOL={
 ext:{x:95,y:168,w:120,h:58,t:'외부 공격자',s:'EC2 · 5개 리전',ic:'attacker',c:RED},
 waf:{x:95,y:300,w:88,h:52,t:'WAF',s:'웹 공격',ic:'shield',c:SOFT},
 alb:{x:262,y:300,w:88,h:52,t:'ALB',s:':8080',ic:'lb',c:SOFT},
 dvwa:{x:410,y:300,w:100,h:52,t:'DVWA',s:'웹 대상',ic:'host',c:SOFT},
 img:{x:500,y:160,w:116,h:52,t:'컨테이너',s:'이미지·코드',ic:'bug',c:SOFT},
 dash:{x:600,y:300,w:112,h:58,t:'보안 대시보드',s:'실행 주체',ic:'host',c:SOFT},
 inner:{x:760,y:170,w:124,h:62,t:'내부 공격자',s:'EC2 · 파리',ic:'attacker',c:RED},
 tgt:{x:760,y:240,w:110,h:52,t:'대상 EC2',s:'실습 서버',ic:'host',c:SOFT},
 mysql:{x:930,y:160,w:100,h:52,t:'MySQL',s:'테스트 DB',ic:'db',c:SOFT},
 sg:{x:1010,y:300,w:104,h:52,t:'보안 그룹',s:'SG 규칙',ic:'shield',c:SOFT},
 logs:{x:1140,y:300,w:110,h:52,t:'감사 로그',s:'Trail·Config·Flow',ic:'logs',c:SOFT},
 gd:{x:250,y:470,w:104,h:52,t:'GuardDuty',s:'행위 기반',ic:'shield',c:SOFT},
 insp:{x:360,y:470,w:104,h:52,t:'Inspector',s:'CVE 스캔',ic:'bug',c:SOFT},
 cfg:{x:470,y:470,w:104,h:52,t:'Config',s:'설정 평가',ic:'gear',c:SOFT},
 cw:{x:580,y:470,w:104,h:52,t:'CloudWatch',s:'WAF·Flow·알람',ic:'bell',c:SOFT},
 sh:{x:760,y:470,w:118,h:52,t:'Security Hub',s:'통합 finding',ic:'hub',c:SOFT},
 eb:{x:890,y:470,w:118,h:52,t:'EventBridge',s:'이벤트',ic:'bolt',c:MINT},
 asr:{x:1020,y:470,w:118,h:52,t:'asr_trigger',s:'규칙 판정',ic:'lambda',c:MINT},
 ssm:{x:1150,y:470,w:118,h:52,t:'SSM',s:'Automation',ic:'gear',c:MINT},
 corr:{x:890,y:590,w:118,h:52,t:'correlator',s:'상관분석',ic:'lambda',c:SOFT},
 ddb:{x:1020,y:590,w:118,h:52,t:'DynamoDB',s:'findings·이력',ic:'db',c:SOFT},
};
// 시나리오별 경로: a 실행 주체, t 대상, ts 대상 부제, web 이면 WAF→ALB 를 지난다.
const ROUTES={
 'SEC-01':{a:'dash',t:'sg',ts:'SSH 22 개방'},
 'SEC-02':{a:'ext',t:'tgt',ts:'포트·헤더'},
 'SEC-03':{a:'dash',t:'sg',ts:'DB 3306 개방'},
 'SEC-04':{a:'dash',t:'img',ts:'이미지 CVE'},
 'SEC-06A':{a:'inner',t:'mysql',ts:'로그인 반복'},
 'SEC-07':{a:'dash',t:'img',ts:'비밀값 스캔'},
 'SEC-08':{a:'ext',t:'dvwa',ts:'웹·SSH 공격',web:true},
 'SEC-06B':{a:'ext',t:'dvwa',ts:'웹 인증 공격',web:true},
 'SEC-09':{a:'dash',t:'logs',ts:'수집 상태'},
 'SEC-10':{a:'dash',t:'tgt',ts:'CPU·메모리 부하'},
};
const DEFAULT={a:'dash',t:'tgt',ts:'점검 대상'};
export const routeOf=id=>ROUTES[id]||DEFAULT;

const top=k=>POOL[k].y-POOL[k].h/2,bot=k=>POOL[k].y+POOL[k].h/2;
// 두 노드 사이 꺾은선(노드가 위에 그려져 끝이 가려진다). 배지는 꺾임의 가운데.
function elbow(a,b){
 const A=POOL[a],B=POOL[b];
 if(A.y===B.y)return {d:`M${A.x} ${A.y} H${B.x}`,bx:(A.x+B.x)/2,by:A.y};
 if(A.x===B.x)return {d:`M${A.x} ${A.y} V${B.y}`,bx:A.x,by:(A.y+B.y)/2};
 const mx=Math.round((A.x+B.x)/2);
 return {d:`M${A.x} ${A.y} H${mx} V${B.y} H${B.x}`,bx:mx,by:Math.round((A.y+B.y)/2)};
}

// 이번 실행 이후(since) 시나리오의 탐지 원천과 같은 출처로 들어온 보안 이벤트를 찾아 ②~⑦ 단계를 채운다.
// 시나리오 ID 를 이벤트가 들고 있지 않아 '시간 + 탐지 원천' 일치로 고르는 추정이다 — 그래서 모든 채운 단계에 '추정'을 붙인다.
// 일치하는 이벤트가 없으면 성공으로 두지 않고 '기록 없음'으로 바꾼다(선택 기간 밖일 수 있음을 밝힌다).
const DOWN=['detect','hub','store','judge','act','verify'];
function fillFromEvents(base,{events,since}){
 if(!Array.isArray(events)||!Number.isFinite(since)||!base.detectors.length)return base;
 const ok=new Set(base.detectors);
 const hits=events.filter(e=>{const t=Date.parse(e.observedAt);return Number.isFinite(t)&&t>=since-60000&&ok.has(detectorOf(e.source));})
  .sort((a,b)=>Date.parse(b.observedAt)-Date.parse(a.observedAt));
 const stages={...base.stages};
 if(!hits.length){
  for(const k of DOWN)if(base.stages[k].state!=='missing')stages[k]={state:'missing',detail:k==='detect'?'이번 실행 이후 같은 탐지 원천의 이벤트 기록 없음(선택 기간 기준)':'탐지 기록이 없어 이 단계도 기록 없음',at:null};
  return {...base,stages,evidence:{matched:0}};
 }
 const seen=eventStages(hits[0]).stages,tag=`추정(실행 이후·같은 탐지 원천 ${hits.length}건) · `;
 for(const k of DOWN){
  if(['judge','act','verify'].includes(k)&&base.stages[k].state==='missing')continue;   // 응답이 없는 시나리오는 그대로 둔다
  stages[k]={...seen[k],detail:tag+(seen[k].detail||'')};
 }
 return {...base,stages,evidence:{matched:hits.length,eventId:hits[0].id||null}};
}

// 모델: 7단계(origin~verify)마다 그릴 선들과 배지 위치. opts={events,since}
export function scenarioRoute(s,items=null,opts={}){
 const base=fillFromEvents(scenarioStages(s,items),opts),cfg=routeOf(s.id),T=cfg.t;
 const dets=base.detectors.length?base.detectors:[];
 const edges=[],badges={};
 const push=(stage,id,d,extra={})=>edges.push({stage,id,d,...extra});
 // ① 실행
 if(cfg.web){
  const d=`M${POOL.ext.x} ${POOL.ext.y} V${POOL.waf.y} H${POOL.dvwa.x}`;
  push('origin','origin',d,{role:'attack',label:'공격·실행',lx:112,ly:236});badges.origin=[95,234];
 }else{
  const e=elbow(cfg.a,T);push('origin','origin',e.d,{role:'attack'});badges.origin=[e.bx,e.by];
 }
 // ② 탐지: 대상 → 탐지 원천(없으면 흐린 선)
 const tx=POOL[T].x,tb=bot(T);
 const detKeys=dets.length?dets:[];
 for(const k of detKeys){
  const dx=POOL[k].x;
  push('detect','det-'+k,k==='sh'?`M${tx} ${tb} V404 H${POOL.sh.x} V444`:`M${tx} ${tb} V404 H${dx} V444`,{role:'observe',det:k});
 }
 const d0=detKeys.find(k=>k!=='sh')||detKeys[0];
 badges.detect=[d0?Math.round((tx+POOL[d0].x)/2):tx-40,404];
 // ③ 통합: 탐지 원천 → Security Hub
 for(const k of detKeys.filter(k=>k!=='sh'))push('hub','hub-'+k,`M${POOL[k].x} 496 V548 H${POOL.sh.x} V496`,{role:'observe',det:k});
 const h0=detKeys.find(k=>k!=='sh');
 badges.hub=[h0?Math.round((POOL[h0].x+POOL.sh.x)/2):POOL.sh.x,548];
 // ④ 상관분석·저장
 push('store','sh-eb',`M${POOL.sh.x} 470 H${POOL.eb.x}`,{role:'observe'});
 push('store','eb-corr','M890 496 V564',{role:'observe'});
 push('store','corr-ddb',`M${POOL.corr.x} 590 H${POOL.ddb.x}`,{role:'observe'});
 badges.store=[890,530];
 // ⑤ 자동 조치 판정 ⑥ 조치 실행
 push('judge','eb-asr',`M${POOL.eb.x} 470 H${POOL.asr.x}`,{role:'respond'});badges.judge=[955,470];
 push('act','asr-ssm',`M${POOL.asr.x} 470 H${POOL.ssm.x}`,{role:'respond'});badges.act=[1085,470];
 // ⑦ 재검증: SSM → 대상(대상 아래쪽 옆 줄로 들어간다)
 const vx=tx+18;
 push('verify','verify',`M${POOL.ssm.x} 444 V424 H${vx} V${tb}`,{role:'respond',label:'재검증',lx:Math.max(vx-70,700),ly:418});
 badges.verify=[vx,Math.round((tb+424)/2)];
 // 그림에 켜질 노드
 const use=new Set([cfg.a,T,'sh','eb','asr','ssm','corr','ddb',...detKeys]);
 if(cfg.web){use.add('waf');use.add('alb');}
 return {base,stages:base.stages,cfg,edges,badges,use,detectors:detKeys};
}

function edgeSvg(e,m,order){
 const info=m.stages[e.stage]||{state:'idle'};let s=info.state;
 if(e.det&&!m.detectors.includes(e.det))s='dim';
 if(s==='dim')return `<path class="hp-mp-edge dim" d="${e.d}" fill="none" stroke="#e2e9e7" stroke-width="1.4" stroke-dasharray="3 6"/>`;
 const lit=s==='done'||s==='pending',color=lit?ROLE[e.role]:s==='failed'?RED:s==='unknown'?AMBER:s==='design'?SOFT:'#d6dfdb';
 const cls=['done','pending','failed','unknown','design'].includes(s)?s:'off';
 const dash=s==='failed'||s==='unknown'?' stroke-dasharray="2 6"':s==='design'?' stroke-dasharray="5 6"':'';
 const label=e.label?`<text x="${e.lx}" y="${e.ly}" class="hp-mp-e" fill="${lit?color:GRAY}">${e.label}</text>`:'';
 return `<g class="hp-mp-eg ${cls}" style="--d:${(order*.45).toFixed(2)}s" data-edge="${e.id}" data-state="${s}">
  <path d="${e.d}" fill="none" stroke="#e6ecea" stroke-width="5" stroke-linecap="round"/>
  <path class="hp-mp-line" d="${e.d}" fill="none" stroke="${color}" stroke-width="${s==='done'?2.6:1.8}" stroke-linecap="round"${dash}/>${label}</g>`;
}
function badgeSvg(stage,m){
 const info=m.stages[stage.key]||{state:'idle'},[x,y]=m.badges[stage.key]||[stage.x,stage.y];
 const [text,mark,color]=FLOW_STATE[info.state]||FLOW_STATE.idle;
 const tip=`${stage.n}. ${stage.label} · ${text}${info.detail?' — '+info.detail:''}`;
 return `<g class="hp-mp-badge" style="--d:${(stage.n*.45-.2).toFixed(2)}s" data-stage="${stage.key}" data-state="${info.state}" tabindex="0" role="img" aria-label="${esc(tip)}">
  <title>${esc(tip)}</title><circle cx="${x}" cy="${y}" r="12.5" fill="#f3f6f5" stroke="${color}" stroke-width="1.8"/>
  <text x="${x}" y="${y+4}" text-anchor="middle" class="hp-mp-n" fill="${color}">${stage.n}</text>
  <text x="${x+15}" y="${y-10}" class="hp-mp-m" fill="${color}">${mark}</text></g>`;
}

export function routeSvg(m){
 setFont(13,12);
 const order={origin:0,detect:1,hub:2,store:3,judge:4,act:5,verify:6};
 const S=k=>m.stages[k]?.state;
 const cfg=m.cfg;
 const nodeOf=(k,over={})=>{
  const p=POOL[k],ov={...over};
  return node({id:k,x:p.x,y:p.y,w:p.w,h:p.h,title:esc(ov.t||p.t),sub:esc(ov.s||p.s),ic:p.ic,color:p.c,active:ov.active??m.use.has(k)});
 };
 // 켜지는 기준: 실행 노드·대상은 ① 이 기록됐거나 설계 경로일 때, 나머지는 해당 단계가 그려질 때.
 const stageOf={sh:'hub',eb:'store',corr:'store',ddb:'store',asr:'judge',ssm:'act'};
 const active=k=>{
  if(k===cfg.a||k===cfg.t||k==='waf'||k==='alb')return m.use.has(k);
  if(stageOf[k])return on(S(stageOf[k]));
  return m.detectors.includes(k)&&on(S('detect'));
 };
 const ctxKeys=['ext','waf','alb','dvwa','img','dash','inner','tgt','mysql','sg','logs'];
 const ctx=ctxKeys.map(k=>nodeOf(k,{active:false,...(k===cfg.t?{t:POOL[k].t,s:cfg.ts,active:true}:{}),...(k===cfg.a?{active:true}:{}),...((k==='waf'||k==='alb')&&m.use.has(k)?{active:true}:{})})).join('');
 const chain=['gd','insp','cfg','cw','sh','eb','asr','ssm','corr','ddb'].map(k=>nodeOf(k,{active:active(k)})).join('');
 return `<svg class="hp-map-svg flow-svg scenario-svg" viewBox="0 0 1240 650" role="group" aria-label="${esc(m.base.targetTitle)} 경로" xmlns="http://www.w3.org/2000/svg">
 <defs><filter id="hp-glow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="3.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <pattern id="hp-grid" width="28" height="28" patternUnits="userSpaceOnUse"><path d="M28 0H0V28" fill="none" stroke="#ebf2f0" stroke-width="1"/></pattern>
  <linearGradient id="hp-zone" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0e8f80" stop-opacity=".07"/><stop offset="1" stop-color="#0e8f80" stop-opacity=".01"/></linearGradient></defs>
 <rect width="1240" height="650" fill="#f3f6f5"/><rect width="1240" height="650" fill="url(#hp-grid)"/>
 <g class="hp-mp-zones">
  <rect x="14" y="60" width="166" height="330" rx="12" fill="none" stroke="#e1e8e5" stroke-dasharray="4 6"/><text x="28" y="82" class="hp-mp-z">INTERNET · EDGE</text>
  <rect x="200" y="50" width="1024" height="342" rx="14" fill="url(#hp-zone)" stroke="#d2ded9" stroke-width="1.4"/><text x="216" y="72" class="hp-mp-z">VPC 10.0.0.0/16</text>
  <rect x="216" y="92" width="290" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="230" y="112" class="hp-mp-z">PUBLIC · WEB</text>
  <rect x="520" y="92" width="340" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="534" y="112" class="hp-mp-z">PRIVATE · APP</text>
  <rect x="876" y="92" width="336" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="890" y="112" class="hp-mp-z">PRIVATE · DB</text>
  <rect x="200" y="416" width="1024" height="218" rx="14" fill="none" stroke="#dde6e2" stroke-dasharray="2 5"/><text x="216" y="438" class="hp-mp-z">탐지 · 수집(SIEM) → 자동 조치(SOAR)</text>
 </g>
 ${m.edges.map(e=>edgeSvg(e,m,order[e.stage]||0)).join('')}
 <g class="hp-mp-ctx">${ctx}</g>
 <g class="hp-mp-main">${chain}</g>
 ${FLOW_STAGES.map(st=>badgeSvg(st,m)).join('')}
</svg>`;
}

// 지도 아래 글자 목록 — 색·그림에 기대지 않는 같은 정보(스크린리더·인쇄). 마크업은 flowList 와 같은 .hp-map-list 를 쓴다.
export function routeList(m){
 return `<ol class="hp-map-list">${FLOW_STAGES.map(s=>{
  const i=m.stages[s.key]||{state:'idle'},[text,mark,color]=FLOW_STATE[i.state]||FLOW_STATE.idle;
  return `<li data-stage="${s.key}" data-state="${i.state}"><b style="border-color:${color};color:${color}">${s.n}</b><span>${esc(s.label)}</span><em style="color:${color}">${mark} ${esc(text)}</em><small>${esc(i.detail||'')}</small></li>`;
 }).join('')}</ol>`;
}
export const ROUTE_NOTE='① 실행은 이번 [전부 실행]의 실제 기록입니다. ②~⑦이 \'완료\'로 켜진 것은 실행 이후 같은 탐지 원천에서 들어온 이벤트로 채운 \'추정\'이고, 점선은 이벤트를 찾을 수 없어 카탈로그 설계만 보여 주는 경로입니다. 기록이 없는 단계를 성공으로 그리지 않습니다.';
