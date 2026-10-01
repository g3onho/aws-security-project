// 보안 이벤트·보안 시나리오 "경로 지도": 아키텍처(honeypot-map 과 같은 그림) 위에 한 탐지가 어디까지 갔는지 그린다.
// 새 API·AI 가 없다 — 이벤트 상세 DTO(source·sourceIp·autoRemediation·actionState·verification)와 조치 기록,
// 시나리오 카탈로그(sources·response)와 실습 실행 상태만 그림에 옮긴다. 기록이 없는 단계를 성공으로 그리지 않는다.
// 상태: done 완료 · pending 진행/대기 · failed 실패 · missing 기록 없음 · unknown 읽지 못함 · design 설계 경로(관측 근거 없음).
// 이벤트 필드는 AWS·공격자가 조종할 수 있는 문자열이므로 esc() 를 거쳐 텍스트·툴팁으로만 넣는다.
import {esc} from '../components/format.js?v=v46';
import {icon,node,setFont} from './honeypot-map.js?v=v46';

const MINT='#0e8f80',SOFT='#4186be',AMBER='#a88a0d',RED='#d63a44',GRAY='#57665c';
export const FLOW_STATE={done:['완료','✓',MINT],pending:['진행·대기','…',AMBER],failed:['실패','✕',RED],missing:['기록 없음','–',GRAY],
 unknown:['읽지 못함','?',AMBER],design:['설계 경로','·',SOFT],idle:['대기','·',GRAY]};

export const FLOW_STAGES=[
 {key:'origin',n:1,label:'출발·공격',x:392,y:184},
 {key:'detect',n:2,label:'탐지',x:700,y:340},
 {key:'hub',n:3,label:'통합(Security Hub)',x:760,y:522},
 {key:'store',n:4,label:'상관분석·저장',x:890,y:530},
 {key:'judge',n:5,label:'자동 조치 판정',x:955,y:470},
 {key:'act',n:6,label:'조치 실행',x:1085,y:470},
 {key:'verify',n:7,label:'재검증',x:1130,y:330},
];
const DET={gd:{x:250,t:'GuardDuty',s:'행위 기반',ic:'shield'},insp:{x:360,t:'Inspector',s:'CVE 스캔',ic:'bug'},
 cfg:{x:470,t:'Config',s:'설정 평가',ic:'gear'},cw:{x:580,t:'CloudWatch',s:'WAF·Flow·알람',ic:'bell'}};
const KEYWORDS=[['GuardDuty','gd'],['Inspector','insp'],['Trivy','insp'],['Config','cfg'],['Access Analyzer','cfg'],
 ['CloudWatch','cw'],['WAF','cw'],['Flow','cw'],['CloudTrail','cw']];

// 이벤트 source → 탐지 원천 노드. Security Hub 가 직접 낸 finding 은 'sh'(통합 창구가 곧 탐지원).
export function detectorOf(source){
 const s=String(source||'');
 if(/security\s*hub/i.test(s))return 'sh';
 const hit=KEYWORDS.find(([word])=>s.toLowerCase().includes(word.toLowerCase()));
 return hit?hit[1]:null;
}
export function resourceKind(resource){
 const r=String(resource||'');
 if(/^arn:[^:]*:s3:/.test(r)||/^s3:/.test(r))return ['S3 버킷','bucket'];
 if(/:iam:|^AWS::IAM/i.test(r))return ['IAM','attacker'];
 if(/(^|\/)sg-[0-9a-f]+/.test(r))return ['보안 그룹','shield'];
 if(/(^|\/)i-[0-9a-f]+/.test(r))return ['EC2 인스턴스','host'];
 if(/rds|db-/i.test(r))return ['DB','db'];
 return ['대상 자원','host'];
}

const done=(detail,at)=>({state:'done',detail,at});
const st=(state,detail,at=null)=>({state,detail,at});

// ── 이벤트 → 7단계 상태 ──────────────────────────────────────────────────────
const RUN_OK=new Set(['EXECUTED','VERIFY_QUEUED','VERIFYING','VERIFIED','VERIFICATION_FAILED','VERIFICATION_ERROR']);
export function eventStages(e,history=null){
 const at=e.observedAt?Date.parse(e.observedAt):null;
 const a=e.autoRemediation||null,state=e.actionState||'PENDING_APPROVAL';
 const records=history?.items||[];
 const first=records.length?Math.min(...records.map(r=>r.createdAt?Date.parse(r.createdAt):Infinity).filter(Number.isFinite)):null;
 const stages={};
 stages.origin=e.sourceIp?done(`출발지 ${e.sourceIp}${e.sourceLocation?` · ${typeof e.sourceLocation==='string'?e.sourceLocation:(e.sourceLocation.country||e.sourceLocation.city||'')}`:''}`,at)
  :st('missing','출발지 IP 없음(구성·취약점 탐지는 외부 출발지가 없다)');
 stages.detect=done(`${e.source||'탐지'}${e.findingType?` · ${e.findingType}`:e.controlId?` · ${e.controlId}`:''}`,at);
 stages.hub=done('탐지 결과가 통합 저장소에 들어왔다(이 이벤트가 존재함)',at);
 stages.store=done(e.severityBumped?`상관분석: 위험도 상향${(e.relatedCves||[]).length?` · CVE ${e.relatedCves.length}개`:''}`:'저장·상관분석 완료',at);
 stages.judge=a?done(`${a.label||a.mode}${a.reason?` — ${a.reason}`:''}`,Number.isFinite(first)?first:null)
  :st('unknown','자동 조치 판정 정보가 없다');
 const auto=a&&['auto','conditional'].includes(a.mode);
 if(state==='EXECUTION_FAILED')stages.act=st('failed','실행 실패');
 else if(state==='CANCELLED')stages.act=st('missing','승인 취소됨');
 else if(state==='RECONCILING')stages.act=st('unknown','상태 확인 중(결과가 불확실해 새 실행을 막는다)');
 else if(RUN_OK.has(state))stages.act=done('SSM 실행 완료(재검증 전)');
 else if(['APPROVED','QUEUED','RUNNING'].includes(state))stages.act=st('pending',{APPROVED:'승인됨·실행 접수 전',QUEUED:'실행 접수',RUNNING:'실행 중'}[state]);
 else if(e.actionable===false&&!auto)stages.act=st('missing','조치 대상 아님(탐지됨)');
 else stages.act=st('pending',auto?'자동 실행 대기·조건 확인':'승인 대기');
 stages.verify=state==='VERIFIED'?done('동일 조건 재검증 통과')
  :state==='VERIFICATION_FAILED'?st('failed','재검증 실패 — 문제가 남아 있다')
  :state==='VERIFICATION_ERROR'?st('unknown','재검증 점검 자체가 실패')
  :['VERIFY_QUEUED','VERIFYING'].includes(state)?st('pending','재검증 중')
  :st('missing',RUN_OK.has(state)?'재검증 전':'조치 전이라 재검증 없음');
 return {stages,detectors:[detectorOf(e.source)].filter(Boolean),targetTitle:resourceKind(e.resource)[0],
  targetSub:String(e.resource||'').slice(-15),targetIcon:resourceKind(e.resource)[1],mode:'event'};
}

// ── 시나리오 → 설계 경로 + 실습 실행 상태 ──────────────────────────────────────
export function scenarioStages(s,items=null){
 const detectors=[...new Set(KEYWORDS.filter(([w])=>(s.sources||[]).some(x=>x.toLowerCase().includes(w.toLowerCase()))).map(([,k])=>k))];
 if((s.sources||[]).some(x=>/security\s*hub/i.test(x)))detectors.push('sh');
 const response=String(s.response||'');
 const auto=response.includes('자동'),manual=response.includes('수동'),none=/^없음$|없음\)?$/.test(response.trim());
 const mine=(items||[]).filter(i=>i.sec===s.id||(s.id==='SEC-06B'&&i.sec==='SEC-08'));
 const label=x=>({Success:'완료',Failed:'실패',TimedOut:'시간초과',Cancelled:'취소',InProgress:'실행 중',Pending:'대기',Delayed:'지연'}[x]||x);
 let origin;
 if(!items)origin=st('unknown','이 화면에서 실행 이력을 읽지 못했다');
 // 조회 전용(SEC-01/03/09 등)은 [전부 실행]이 건드리지 않는다 — 자동/수동 조치 대상이 아니라
 // 상시 관측만 하는 설계라, '기록 없음'이 아니라 완료로 보여주고 왜 그런지 여기에 적는다.
 else if(s.support==='observe-only')origin=done('조회 전용 — [전부 실행] 대상 아님. 탐지·관측만 상시 수행하고 자동/수동 조치는 하지 않는 설계(카탈로그 기준)');
 else if(!mine.length)origin=st('missing','이번 실행 기록 없음(전부 실행 전이거나 이 시나리오는 실행 대상 아님)');
 else if(mine.some(i=>['Failed','TimedOut'].includes(i.status)))origin=st('failed',`실행 ${mine.map(i=>label(i.status)).join('·')}`);
 else if(mine.every(i=>i.status==='Success'))origin=done(`실행 ${mine.length}건 완료`);
 else origin=st('pending',`실행 ${mine.map(i=>label(i.status)).join('·')}`);
 const dsn=(detail)=>st('design',detail);
 const stages={origin,
  detect:dsn(detectors.length?`탐지 원천: ${s.sources.join(' · ')}`:'직접 탐지 원천 없음(수동 점검·결과 파일 확인)'),
  hub:dsn('탐지 결과는 통합 창구(Security Hub)로 모인다'),store:dsn('상관분석·저장(DynamoDB)'),
  judge:none?st('missing','자동 조치 판정 없음'):dsn(`대응: ${response}`),
  act:none?st('missing','조치 없음'):auto?dsn('자동 조치(SSM Automation)'):manual?dsn('수동 승인 후 조치'):dsn(`대응: ${response}`),
  verify:none?st('missing','재검증 대상 아님'):dsn('실행 뒤 동일 조건 재검증')};
 return {stages,detectors,targetTitle:s.id,targetSub:s.purpose.length>9?s.purpose.slice(0,8)+'…':s.purpose,targetIcon:'host',mode:'scenario'};
}

// ── 그림 ─────────────────────────────────────────────────────────────────────
const EDGES=[
 {id:'origin',d:'M155 168 L630 200',stage:'origin',role:'attack',order:0,label:'공격·실행',lx:330,ly:158},
 ...Object.entries(DET).map(([k,v])=>({id:'det-'+k,d:`M700 263 V404 H${v.x} V444`,stage:'detect',role:'observe',order:1,det:k})),
 {id:'det-sh',d:'M700 263 V404 H760 V444',stage:'detect',role:'observe',order:1,det:'sh'},
 ...Object.entries(DET).map(([k,v])=>({id:'hub-'+k,d:`M${v.x} 496 V548 H760 V496`,stage:'hub',role:'observe',order:2,det:k})),
 {id:'sh-eb',d:'M808 470 H842',stage:'hub',role:'observe',order:2},
 {id:'eb-corr',d:'M890 496 V564',stage:'store',role:'observe',order:3},
 {id:'corr-ddb',d:'M938 590 H972',stage:'store',role:'observe',order:3},
 {id:'eb-asr',d:'M938 470 H972',stage:'judge',role:'respond',order:4},
 {id:'asr-ssm',d:'M1068 470 H1102',stage:'act',role:'respond',order:5},
 {id:'act',d:'M1150 444 V214 H770',stage:'act',role:'respond',order:5,label:'조치',lx:1160,ly:300},
 {id:'verify',d:'M1130 444 V236 H770',stage:'verify',role:'respond',order:6,label:'재검증',lx:1030,ly:262},
];
const ROLE={attack:RED,observe:SOFT,respond:MINT};

function edgeState(e,model){
 if(e.det&&!model.detectors.includes(e.det))return 'dim';
 return model.stages[e.stage]?.state||'idle';
}
function edgeSvg(e,model){
 const s=edgeState(e,model);
 if(s==='dim')return `<path class="hp-mp-edge dim" d="${e.d}" fill="none" stroke="#e2e9e7" stroke-width="1.4" stroke-dasharray="3 6"/>`;
 const lit=s==='done'||s==='pending',color=lit?ROLE[e.role]:s==='failed'?RED:s==='unknown'?AMBER:s==='design'?SOFT:'#d6dfdb';
 const cls=s==='done'?'done':s==='pending'?'pending':s==='failed'?'failed':s==='unknown'?'unknown':s==='design'?'design':'off';
 const dash=s==='failed'||s==='unknown'?' stroke-dasharray="2 6"':s==='design'?' stroke-dasharray="5 6"':'';
 const label=e.label?`<text x="${e.lx}" y="${e.ly}" class="hp-mp-e" fill="${lit?color:GRAY}">${e.label}</text>`:'';
 return `<g class="hp-mp-eg ${cls}" style="--d:${(e.order*.45).toFixed(2)}s" data-edge="${e.id}" data-state="${s}">
  <path d="${e.d}" fill="none" stroke="#e6ecea" stroke-width="5" stroke-linecap="round"/>
  <path class="hp-mp-line" d="${e.d}" fill="none" stroke="${color}" stroke-width="${s==='done'?2.6:1.8}" stroke-linecap="round"${dash}/>${label}</g>`;
}
function badgeSvg(stage,model){
 const info=model.stages[stage.key]||{state:'idle'};
 const [text,mark,color]=FLOW_STATE[info.state]||FLOW_STATE.idle;
 const tip=`${stage.n}. ${stage.label} · ${text}${info.detail?' — '+info.detail:''}`;
 return `<g class="hp-mp-badge" style="--d:${(stage.n*.45-.2).toFixed(2)}s" data-stage="${stage.key}" data-state="${info.state}" tabindex="0" role="img" aria-label="${esc(tip)}">
  <title>${esc(tip)}</title><circle cx="${stage.x}" cy="${stage.y}" r="12.5" fill="#f3f6f5" stroke="${color}" stroke-width="1.8"/>
  <text x="${stage.x}" y="${stage.y+4}" text-anchor="middle" class="hp-mp-n" fill="${color}">${stage.n}</text>
  <text x="${stage.x+15}" y="${stage.y-10}" class="hp-mp-m" fill="${color}">${mark}</text></g>`;
}
const on=s=>['done','pending','failed','unknown','design'].includes(s);

export function flowSvg(model){
 setFont(11.5,10.5);
 const S=k=>model.stages[k]?.state;
 const det=k=>model.detectors.includes(k)&&on(S('detect'));
 const lit=(k,role)=>({active:on(S(k)),color:ROLE[role]});
 const N=(id,x,y,t,s,ic,activeKey,role,w=96,h=52)=>node({id,x,y,w,h,title:t,sub:s,ic,color:ROLE[role],active:on(S(activeKey))});
 return `<svg class="hp-map-svg flow-svg" viewBox="0 0 1240 650" role="group" aria-label="아키텍처 위 탐지 경로" xmlns="http://www.w3.org/2000/svg">
 <defs><filter id="hp-glow" x="-30%" y="-30%" width="160%" height="160%"><feGaussianBlur stdDeviation="3.2" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
  <pattern id="hp-grid" width="28" height="28" patternUnits="userSpaceOnUse"><path d="M28 0H0V28" fill="none" stroke="#ebf2f0" stroke-width="1"/></pattern>
  <linearGradient id="hp-zone" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0e8f80" stop-opacity=".07"/><stop offset="1" stop-color="#0e8f80" stop-opacity=".01"/></linearGradient></defs>
 <rect width="1240" height="650" fill="#f3f6f5"/><rect width="1240" height="650" fill="url(#hp-grid)"/>
 <g class="hp-mp-zones">
  <rect x="14" y="60" width="166" height="330" rx="12" fill="none" stroke="#e1e8e5" stroke-dasharray="4 6"/><text x="28" y="82" class="hp-mp-z">INTERNET · EDGE</text>
  <rect x="200" y="50" width="1024" height="342" rx="14" fill="url(#hp-zone)" stroke="#d2ded9" stroke-width="1.4"/><text x="216" y="72" class="hp-mp-z">VPC 10.0.0.0/16</text>
  <rect x="216" y="92" width="256" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="230" y="112" class="hp-mp-z">PUBLIC · WEB</text>
  <rect x="490" y="92" width="316" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="504" y="112" class="hp-mp-z">PRIVATE · APP</text>
  <rect x="826" y="92" width="386" height="284" rx="10" fill="#f1f6f4" stroke="#dde6e2"/><text x="840" y="112" class="hp-mp-z">PRIVATE · DB</text>
  <rect x="200" y="416" width="1024" height="218" rx="14" fill="none" stroke="#dde6e2" stroke-dasharray="2 5"/><text x="216" y="438" class="hp-mp-z">탐지 · 수집(SIEM) → 자동 조치(SOAR)</text>
 </g>
 <g class="hp-mp-ctx">
  ${node({id:'ext',x:95,y:168,w:120,title:'외부 공격자',sub:model.stages.origin?.state==='done'?'출발지 확인':'ZAP · sqlmap',ic:'attacker',color:RED,active:S('origin')==='done'})}
  ${node({id:'waf',x:95,y:300,w:88,h:52,title:'WAF',sub:'웹 공격',ic:'shield',color:SOFT,active:false})}
  ${node({id:'alb',x:262,y:300,w:88,h:52,title:'ALB',sub:':8080',ic:'lb',active:false})}
  ${node({id:'dvwa',x:410,y:300,w:100,h:52,title:'DVWA',sub:'웹 대상',ic:'host',active:false})}
  ${node({id:'docker',x:570,y:150,w:112,title:'도커 호스트',sub:'Nginx · Flask',ic:'host',active:false})}
  ${node({id:'dash',x:570,y:300,w:112,title:'보안 대시보드',sub:'이 화면',ic:'host',active:false})}
  ${node({id:'mysql',x:930,y:160,w:100,h:52,title:'MySQL',sub:'실서비스 DB',ic:'db',active:false})}
  ${node({id:'honeypot',x:1050,y:320,w:120,h:52,title:'허니팟',sub:'미끼 서버',ic:'spark',color:AMBER,active:false})}
 </g>
 ${EDGES.map(e=>edgeSvg(e,model)).join('')}
 <g class="hp-mp-main">
  ${node({id:'target',x:700,y:225,w:140,h:76,title:esc(model.targetTitle),sub:esc(model.targetSub),ic:model.targetIcon,color:model.mode==='scenario'?SOFT:AMBER,active:true})}
  ${Object.entries(DET).map(([k,v])=>node({id:'det-'+k,x:v.x,y:470,w:104,h:52,title:v.t,sub:v.s,ic:v.ic,color:SOFT,active:det(k)})).join('')}
  ${node({id:'sh',x:760,y:470,w:118,h:52,title:'Security Hub',sub:'통합 finding',ic:'hub',color:SOFT,active:on(S('hub'))})}
  ${node({id:'eb',x:890,y:470,w:118,h:52,title:'EventBridge',sub:'이벤트',ic:'bolt',color:MINT,active:on(S('store'))})}
  ${node({id:'asr',x:1020,y:470,w:118,h:52,title:'asr_trigger',sub:'규칙 판정',ic:'lambda',color:MINT,active:on(S('judge'))})}
  ${node({id:'ssm',x:1150,y:470,w:118,h:52,title:'SSM',sub:'Automation',ic:'gear',color:MINT,active:on(S('act'))})}
  ${node({id:'corr',x:890,y:590,w:118,h:52,title:'correlator',sub:'상관분석',ic:'lambda',color:SOFT,active:on(S('store'))})}
  ${node({id:'ddb',x:1020,y:590,w:118,h:52,title:'DynamoDB',sub:'findings·이력',ic:'db',color:SOFT,active:on(S('store'))})}
 </g>
 ${FLOW_STAGES.map(s=>badgeSvg(s,model)).join('')}
</svg>`;
}

export function flowList(model){
 const first=Math.min(...FLOW_STAGES.map(s=>model.stages[s.key]?.at).filter(Number.isFinite));
 return `<ol class="hp-map-list">${FLOW_STAGES.map(s=>{
  const i=model.stages[s.key]||{state:'idle'},[text,mark,color]=FLOW_STATE[i.state]||FLOW_STATE.idle;
  const after=Number.isFinite(i.at)&&Number.isFinite(first)?`+${Math.max(0,Math.round((i.at-first)/1000))}초`:'';
  return `<li data-stage="${s.key}" data-state="${i.state}"><b style="border-color:${color};color:${color}">${s.n}</b><span>${esc(s.label)}</span><em style="color:${color}">${mark} ${esc(text)}</em><small>${esc(i.detail||after)}</small></li>`;
 }).join('')}</ol>`;
}
export const flowBlock=(model,note='')=>`<div class="hp-map flow-map">${flowSvg(model)}</div>${flowList(model)}${note?`<p class="muted hp-note">${esc(note)}</p>`:''}`;

export const FLOW_NOTE_EVENT='이 지도는 이 이벤트의 실제 기록(탐지 소스·자동 조치 판정·조치 상태)으로 그렸습니다. 값이 없는 단계는 \'정상\'이 아니라 \'기록 없음\'으로 표시합니다.';
export const FLOW_NOTE_SCENARIO='점선은 설계된 경로(카탈로그 기준)이고, ① 단계의 색만 이번 실행 기록입니다. 설계 경로는 실제로 관측된 사실이 아닙니다.';
