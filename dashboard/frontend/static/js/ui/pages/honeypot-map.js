// 허니팟 "공격 경로 지도": 아키텍처 위에 선택한 공격 IP 의 실제 진행 단계(타임라인 API 의 steps)를 그려 준다.
// 새 데이터 원천이 없다 — 기존 /api/honeypot/timeline 의 8단계(connect·auth·command·analysis·alarm·judge·ssm·nacl)를
// 그림의 선·번호 배지에 옮길 뿐이다. AI 가 그림을 만들지 않는다(없는 경로를 그럴듯하게 그리는 위험을 피한다).
// 단계의 상태(done/missing/failed/pending/unknown)를 색뿐 아니라 배지 글자(✓ – ✕ … ?)로도 표기한다.
// 공격자가 조종할 수 있는 문자열(단계 detail)은 esc() 를 거쳐 <title>·텍스트로만 넣는다. 고정 라벨만 원문 그대로 쓴다.
import {esc} from '../components/format.js?v=v46';

const MINT='#0e8f80',SOFT='#4186be',AMBER='#a88a0d',RED='#d63a44',GRAY='#57665c';
const STATE={done:['완료','✓',MINT],missing:['기록 없음','–',GRAY],failed:['실패','✕',RED],pending:['진행 중','…',AMBER],unknown:['읽지 못함','?',AMBER]};

// 단계 → 그림 위 위치(번호 배지). 번호는 실제 진행 순서다.
export const MAP_STAGES=[
 {key:'connect',n:1,label:'접속',x:800,y:238},
 {key:'auth',n:2,label:'로그인 시도',x:898,y:244},
 {key:'command',n:3,label:'명령 입력',x:952,y:248},
 {key:'analysis',n:4,label:'AI 세션 분석',x:1116,y:392},
 {key:'alarm',n:5,label:'탐지 알람',x:640,y:398},
 {key:'judge',n:6,label:'asr_trigger 판정',x:615,y:522},
 {key:'ssm',n:7,label:'SSM 실행',x:762,y:522},
 {key:'nacl',n:8,label:'NACL 차단',x:844,y:346},
];

// 선(edge): d 경로, stage(색·애니메이션 상태를 따르는 단계), role(공격 red · 관측 blue · 대응 mint), order(그려지는 순서)
const EDGES=[
 {id:'web1',d:'M95 200 V262',dim:true},
 {id:'web2',d:'M140 300 H228',dim:true},
 {id:'web3',d:'M292 300 H352',dim:true},
 {id:'attack',d:'M770 234 L994 252',stage:'connect',role:'attack',order:0,label:'SSH 22',lx:872,ly:214},
 {id:'ai',d:'M1086 288 C1120 340 1134 400 1134 470',stage:'analysis',role:'observe',order:3},
 {id:'log',d:'M1052 290 V404 H278 V470',stage:'alarm',role:'observe',order:4,label:'로그 전송',lx:860,ly:418},
 {id:'cw',d:'M304 500 H384',stage:'alarm',role:'observe',order:5},
 {id:'eb0',d:'M444 500 H524',stage:'alarm',role:'observe',order:5},
 {id:'eb',d:'M584 500 H664',stage:'judge',role:'respond',order:6},
 {id:'rec',d:'M690 530 V588 H1000 V530',stage:'judge',role:'respond',order:6,label:'기록',lx:850,ly:606},
 {id:'ssm',d:'M724 500 H802',stage:'ssm',role:'respond',order:7},
 {id:'gate',d:'M836 470 L842 262',stage:'nacl',role:'respond',order:8,label:'Deny 규칙',lx:872,ly:316},
];
const ROLE_COLOR={attack:RED,observe:SOFT,respond:MINT};

const ICON={ // 24×24 안에서 그린 단순 아이콘. 외부 글꼴·이미지에 의존하지 않는다.
 attacker:'<circle cx="12" cy="8" r="4"/><path d="M4 21c0-5 3.5-8 8-8s8 3 8 8z"/>',
 shield:'<path d="M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5z"/>',
 db:'<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/><path d="M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
 host:'<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/>',
 lb:'<circle cx="12" cy="5" r="2.6"/><circle cx="5" cy="19" r="2.6"/><circle cx="19" cy="19" r="2.6"/><path d="M12 8v4M12 12 5 16.4M12 12l7 4.4"/>',
 bell:'<path d="M6 17V11a6 6 0 0 1 12 0v6l2 2H4z"/><path d="M10 21h4"/>',
 bolt:'<path d="M13 2 4 14h6l-1 8 9-12h-6z"/>',
 lambda:'<path d="M5 20 11 5h2l6 15M9 13h7"/>',
 gear:'<circle cx="12" cy="12" r="3.4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
 logs:'<path d="M6 3h9l4 4v14H6z"/><path d="M9 11h7M9 15h7M9 7h3"/>',
 spark:'<path d="M12 2l2.2 6.3L21 10l-6.3 2.2L12 19l-2.2-6.8L3 10l6.8-1.7z"/>',
 bug:'<path d="M8 8h8v8a4 4 0 0 1-8 0z"/><path d="M9 5l1.5 3M15 5l-1.5 3M4 11h4M16 11h4M4 17h4M16 17h4"/>',
 hub:'<circle cx="12" cy="12" r="3"/><circle cx="5" cy="6" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="5" cy="18" r="2"/><circle cx="19" cy="18" r="2"/><path d="M7 7l3 3M17 7l-3 3M7 17l3-3M17 17l-3-3"/>',
 bucket:'<path d="M4 8h16l-2 12H6z"/><ellipse cx="12" cy="8" rx="8" ry="2.6"/>',
};
const icon=(name,x,y,size,color)=>`<g transform="translate(${x-size/2} ${y-size/2}) scale(${size/24})" fill="none" stroke="${color}" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">${ICON[name]}</g>`;

// 노드 하나. active 면 밝게, 아니면 흐리게. glow 는 관측된 노드만.
// 글씨가 상자(rect) 밖으로 나가지 않게: 폭을 어림해서 넘치면 textLength 로 상자 안에 맞춘다(글자 폭 압축).
export const FONT={t:14.5,s:12.5};
export function setFont(t,s){FONT.t=t;FONT.s=s;}
function textWidth(text,fs,bold){
 let em=0;
 for(const ch of String(text).replace(/&[a-z#0-9]+;/g,'x')){
  const c=ch.codePointAt(0);
  em+=c>0x2e7f?1:/[A-Z0-9]/.test(ch)?.66:/[ilj.,:;'|·! ]/.test(ch)?.36:/[mwMW]/.test(ch)?.9:.58;
 }
 return em*fs*(bold?1.06:1);
}
function fitText(x,y,cls,text,avail,fs,bold){
 const over=textWidth(text,fs,bold)>avail;
 return `<text x="${x}" y="${y}" class="${cls}"${over?` textLength="${avail.toFixed(0)}" lengthAdjust="spacingAndGlyphs"`:''}>${text}</text>`;
}
function node({id,x,y,w=104,h=58,title,sub,ic,color=SOFT,active=true,extra=''}){
 const stroke=active?color:'#d6dfdb',op=active?1:.55;
 return `<g class="hp-mp-node${active?' on':''}" data-node="${id}" opacity="${op}">
  <rect x="${x-w/2}" y="${y-h/2}" width="${w}" height="${h}" rx="9" fill="#eff4f3" stroke="${stroke}" stroke-width="${active?1.6:1}"${active?` filter="url(#hp-glow)"`:''}/>
  ${icon(ic,x-w/2+20,y-4,22,active?color:GRAY)}
  ${fitText(x-w/2+38,y-3,'hp-mp-t',title,w-38-12,FONT.t,true)}
  ${fitText(x-w/2+38,y+13,'hp-mp-s',sub,w-38-12,FONT.s,false)}${extra}</g>`;
}

const stepOf=(steps,key)=>steps?steps.find(s=>s.key===key)||null:null;
const stateOf=(steps,key)=>steps?(stepOf(steps,key)?.state||'missing'):'idle';

function edge(e,steps,first){
 if(e.dim)return `<path class="hp-mp-edge dim" d="${e.d}" fill="none" stroke="#d6dfdb" stroke-width="1.6" stroke-dasharray="3 6"/>`;
 const st=stateOf(steps,e.stage),color=ROLE_COLOR[e.role];
 const cls=st==='done'?'done':st==='pending'?'pending':st==='failed'?'failed':st==='unknown'?'unknown':'off';
 const col=st==='done'||st==='pending'?color:st==='failed'?RED:st==='unknown'?AMBER:'#d6dfdb';
 const delay=(e.order*0.45).toFixed(2);
 const label=e.label?`<text x="${e.lx}" y="${e.ly}" class="hp-mp-e" fill="${st==='done'?color:GRAY}">${e.label}</text>`:'';
 return `<g class="hp-mp-eg ${cls}" style="--d:${delay}s" data-edge="${e.id}" data-state="${st}">
  <path d="${e.d}" fill="none" stroke="#e6ecea" stroke-width="5" stroke-linecap="round"/>
  <path class="hp-mp-line" d="${e.d}" fill="none" stroke="${col}" stroke-width="${st==='done'?2.6:1.8}" stroke-linecap="round"${st==='failed'||st==='unknown'?' stroke-dasharray="2 6"':''}/>
  ${label}</g>`;
}

function badge(stage,steps,first){
 const s=stepOf(steps,stage.key),st=steps?(s?.state||'missing'):'idle';
 const [text,mark,color]=STATE[st]||['대기','·',GRAY];
 const after=s?.at&&first?`+${Math.max(0,Math.round((s.at-first)/1000))}초`:'';
 const tip=`${stage.n}. ${stage.label} · ${text}${after?' · '+after:''}${s?.detail?' — '+s.detail:''}`;
 const delay=(stage.n*0.45-.2).toFixed(2);
 return `<g class="hp-mp-badge" style="--d:${delay}s" data-stage="${stage.key}" data-state="${st}" tabindex="0" role="img" aria-label="${esc(tip)}">
  <title>${esc(tip)}</title>
  <circle cx="${stage.x}" cy="${stage.y}" r="12.5" fill="#f3f6f5" stroke="${color}" stroke-width="1.8"/>
  <text x="${stage.x}" y="${stage.y+4}" text-anchor="middle" class="hp-mp-n" fill="${color}">${stage.n}</text>
  <text x="${stage.x+15}" y="${stage.y-10}" class="hp-mp-m" fill="${color}">${mark}</text>
  ${after?`<text x="${stage.x}" y="${stage.y+27}" text-anchor="middle" class="hp-mp-time">${esc(after)}</text>`:''}</g>`;
}

// 지도 SVG. steps 가 null 이면 "대기"(IP 미선택·기간 내 공격 없음) 모드로 구조만 보여 준다.
export function mapSvg(steps){
 setFont(14.5,12.5);
 const first=steps?steps.find(s=>s.at)?.at:null;
 const done=k=>stateOf(steps,k)==='done';
 const connected=done('connect'),blocked=done('nacl');
 const S=k=>stepOf(steps,k);
 const hpDetail=connected?`${esc(S('connect').detail||'')}${done('command')?' · 명령 '+esc(S('command').detail||''):''}`:'접속 대기';
 const gateColor=blocked?RED:GRAY;
 const cut=blocked?`<g class="hp-mp-cut"><path d="M826 226 856 250M856 226 826 250" stroke="${RED}" stroke-width="3.4" stroke-linecap="round"/><text x="841" y="212" text-anchor="middle" class="hp-mp-e" fill="${RED}">차단</text></g>`:'';
 return `<svg class="hp-map-svg" viewBox="0 0 1240 650" role="group" aria-label="아키텍처 위 공격 경로" xmlns="http://www.w3.org/2000/svg">
 <defs>
  <filter id="hp-glow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="3.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <pattern id="hp-grid" width="28" height="28" patternUnits="userSpaceOnUse"><path d="M28 0H0V28" fill="none" stroke="#ebf2f0" stroke-width="1"/></pattern>
  <linearGradient id="hp-zone" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0e8f80" stop-opacity=".07"/><stop offset="1" stop-color="#0e8f80" stop-opacity=".01"/></linearGradient>
  <radialGradient id="hp-pulse"><stop offset="0" stop-color="${AMBER}" stop-opacity=".45"/><stop offset="1" stop-color="${AMBER}" stop-opacity="0"/></radialGradient>
 </defs>
 <rect width="1240" height="650" fill="#f3f6f5"/><rect width="1240" height="650" fill="url(#hp-grid)"/>

 <g class="hp-mp-zones">
  <rect x="14" y="60" width="166" height="330" rx="12" fill="none" stroke="#e1e8e5" stroke-dasharray="4 6"/><text x="28" y="82" class="hp-mp-z">INTERNET · EDGE</text>
  <rect x="200" y="50" width="1024" height="342" rx="14" fill="url(#hp-zone)" stroke="#d2ded9" stroke-width="1.4"/><text x="216" y="72" class="hp-mp-z">VPC 10.0.0.0/16</text>
  <rect x="216" y="92" width="256" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="230" y="112" class="hp-mp-z">PUBLIC · WEB</text>
  <rect x="490" y="92" width="316" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="504" y="112" class="hp-mp-z">PRIVATE · APP</text>
  <rect x="826" y="92" width="386" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="840" y="112" class="hp-mp-z">PRIVATE · DB</text>
  <rect x="481" y="82" width="740" height="302" rx="14" fill="none" stroke="${AMBER}" stroke-opacity=".55" stroke-dasharray="7 5"/><text x="1200" y="104" text-anchor="end" class="hp-mp-z" fill="${AMBER}">PRIVATE NACL · SOAR Deny 1~99</text>
  <rect x="200" y="416" width="1024" height="218" rx="14" fill="none" stroke="#dde6e2" stroke-dasharray="2 5"/><text x="216" y="438" class="hp-mp-z">탐지 · 자동 조치 (SIEM · SOAR)</text>
 </g>

 <g class="hp-mp-ctx">
  ${node({id:'ext',x:95,y:168,w:120,title:'외부 공격자',sub:'ZAP · sqlmap',ic:'attacker',color:RED,active:false})}
  ${node({id:'waf',x:95,y:300,w:88,h:52,title:'WAF',sub:'웹 공격',ic:'shield',active:false})}
  ${node({id:'alb',x:262,y:300,w:88,h:52,title:'ALB',sub:':8080',ic:'lb',active:false})}
  ${node({id:'dvwa',x:410,y:300,w:100,h:52,title:'DVWA',sub:'웹 대상',ic:'host',active:false})}
  ${node({id:'docker',x:575,y:170,w:112,title:'도커 호스트',sub:'Nginx · Flask',ic:'host',active:false})}
  ${node({id:'dash',x:575,y:300,w:112,title:'보안 대시보드',sub:'이 화면',ic:'host',active:false})}
  ${node({id:'mysql',x:930,y:160,w:100,h:52,title:'MySQL',sub:'실서비스 DB',ic:'db',active:false})}
 </g>
 <text x="214" y="352" class="hp-mp-note">웹 공격은 WAF→ALB 경로(별도)</text>

 ${EDGES.map(e=>edge(e,steps,first)).join('')}

 <g class="hp-mp-main">
  ${node({id:'inner',x:706,y:214,w:124,h:66,title:'내부 공격자',sub:'EC2 · 침투 가정',ic:'attacker',color:RED,active:connected||steps===null?connected:false})}
  ${node({id:'honeypot',x:1070,y:252,w:142,h:70,title:'허니팟',sub:hpDetail,ic:'spark',color:AMBER,active:connected})}
  ${connected?`<circle class="hp-mp-pulse" cx="1070" cy="252" r="64" fill="url(#hp-pulse)"/>`:''}
  <g class="hp-mp-gate" data-gate="${blocked?'closed':'open'}"><circle cx="841" cy="238" r="17" fill="#f3f6f5" stroke="${gateColor}" stroke-width="${blocked?2.4:1.4}"${blocked?' filter="url(#hp-glow)"':''}/>${icon('shield',841,238,20,gateColor)}</g>
  ${cut}
  ${node({id:'bedrock',x:1150,y:500,w:110,h:58,title:'Bedrock',sub:'Claude Haiku 4.5',ic:'spark',color:SOFT,active:done('analysis')})}
  ${node({id:'logs',x:262,y:500,w:100,h:58,title:'Logs',sub:'/honeypot/*',ic:'logs',color:SOFT,active:done('alarm')})}
  ${node({id:'alarm',x:414,y:500,w:96,h:58,title:'알람',sub:'HoneypotHit',ic:'bell',color:SOFT,active:done('alarm')})}
  ${node({id:'eb',x:554,y:500,w:100,h:58,title:'EventBridge',sub:'ALARM 이벤트',ic:'bolt',color:MINT,active:done('judge')})}
  ${node({id:'lambda',x:694,y:500,w:110,h:58,title:'asr_trigger',sub:'규칙 판정',ic:'lambda',color:MINT,active:done('judge')})}
  ${node({id:'ssm',x:836,y:500,w:110,h:58,title:'SSM',sub:'Automation',ic:'gear',color:MINT,active:done('ssm')})}
  ${node({id:'ddb',x:1000,y:500,w:120,h:58,title:'DynamoDB',sub:'차단 목록·이력',ic:'db',color:MINT,active:done('judge')})}
 </g>
 ${MAP_STAGES.map(st=>badge(st,steps,first)).join('')}
</svg>`;
}

// 지도 아래 글자 목록(색·그림에 의존하지 않는 같은 정보). 스크린리더·인쇄용.
export function stageList(steps){
 const first=steps?steps.find(s=>s.at)?.at:null;
 return `<ol class="hp-map-list">${MAP_STAGES.map(st=>{
  const s=stepOf(steps,st.key),state=steps?(s?.state||'missing'):'idle';
  const [text,mark,color]=STATE[state]||['대기','·',GRAY];
  const after=s?.at&&first?`+${Math.max(0,Math.round((s.at-first)/1000))}초`:'';
  return `<li data-stage="${st.key}" data-state="${state}"><b style="border-color:${color};color:${color}">${st.n}</b><span>${esc(st.label)}</span><em style="color:${color}">${mark} ${esc(text)}</em><small>${esc(after)}</small></li>`;
 }).join('')}</ol>`;
}

// 다시 재생: 애니메이션 클래스를 껐다 켠다(강제 리플로 후).
export function replayMap(root){
 const svg=root?.querySelector('.hp-map-svg');if(!svg)return;
 svg.classList.remove('play');void svg.getBoundingClientRect();svg.classList.add('play');
}

// 이벤트·시나리오 경로 지도(flow-map.js)가 같은 아이콘·노드 모양을 쓴다.
export {icon,node,STATE};
