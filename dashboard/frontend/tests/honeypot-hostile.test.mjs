import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install, loadD3Force, blockItem, stats, session, detail, steps, status, NOW} from './honeypot-fixtures.mjs';

// 공격자가 조종하는 값(명령·사용자명·응답·AI 요약·IP 자리에 온 문자열)이 화면에서 요소·속성·스크립트가 되지 않는다.
const HOSTILE=['<img src=x onerror="window.__pwned=1">','"><svg onload="window.__pwned=1">','<script>window.__pwned=1</script>',"'><a href=javascript:1>x</a>"];
test('hostile session content is rendered as text only, and a double click sends one change request',async t=>{
 const network=makeFetchMock();
 const items=[blockItem('10.0.2.55'),blockItem(HOSTILE[1],{ruleNumber:5,naclRule:5,releaseReason:HOSTILE[0],releasedBy:HOSTILE[2],lastError:HOSTILE[3]})];
 install(network,{items,
  statsData:stats({topIps:[{ip:HOSTILE[1],sessions:2,commands:3,auth:1,firstSeen:NOW,lastSeen:NOW}],topCommands:[{key:HOSTILE[0],count:2}],topUsers:[{key:HOSTILE[2],count:1}],
   graph:{nodes:[{id:'ip:'+HOSTILE[1],type:'ip',label:HOSTILE[1],sessions:1},{id:'s:a00000000001',type:'session',label:'a00000000001',intent:HOSTILE[0],commands:1},
    {id:'c:'+HOSTILE[0],type:'command',label:HOSTILE[0],count:1}],links:[{source:'ip:'+HOSTILE[1],target:'s:a00000000001'},{source:'s:a00000000001',target:'c:'+HOSTILE[0]}],hidden:{ips:0,sessions:0,commands:0}}}),
  sessions:{items:[session('a00000000001',HOSTILE[1],{intent:HOSTILE[0]})],nextCursor:null,total:1},
  timeline:{ip:HOSTILE[1],steps:steps().map(s=>({...s,detail:HOSTILE[0],source:HOSTILE[2],label:s.label})),sessions:[]},
  statusData:status({verdict:{state:'partial',label:HOSTILE[0],reasons:[HOSTILE[1],HOSTILE[2]]}})});
 network.respond('/api/honeypot/sessions/a00000000001',()=>ok(detail('a00000000001',{srcIp:HOSTILE[1],
  commands:[{at:NOW,command:HOSTILE[0],response:HOSTILE[1]}],authAttempts:[{at:NOW,user:HOSTILE[2],passwordLength:3,password:null}],
  analysis:{summary:HOSTILE[0],iocs:HOSTILE.slice(),intent:'recon',severity:'high',aiApplied:true}})));
 // 오류 응답도 만들 수 있게 fetch 를 감싼다(변경 요청 409).
 const base=network.fetch,conflicts=[];
 network.fetch=async(url,options={})=>{
  const parsed=new URL(String(url),'http://localhost/');
  if(parsed.pathname==='/api/blocklist/10.0.2.55/release'&&conflicts.length===0&&options.method==='POST'){
   network.calls.push({pathname:parsed.pathname,url:parsed,options});conflicts.push(1);
   return {ok:false,status:409,json:async()=>({error:{code:'VERSION_CONFLICT',message:'차단 정보가 바뀌었습니다. 새로고침해주세요.',details:{}},meta:{schemaVersion:'1'}})};
  }
  return base(url,options);
 };
 const {dom,w,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 loadD3Force(w);w.__pwned=0;
 const client=await import(pathToFileURL(path.join(ROOT,'static/js/store/api/client.js')).href+'?v=v44');client.setTimers({sleep:async()=>{}});
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'));
 click('nav [data-view="honeypot"]');
 await until(()=>$('.hp-steps')&&$('[data-block]'),'honeypot did not render');
 click('[data-hp-session="a00000000001"]');
 await until(()=>$('.hp-terminal'),'detail did not render');

 const box=$('#honeypot');
 // 요소·속성으로 새어 나가지 않았다
 assert.equal(box.querySelectorAll('img,script,a[href^="javascript"]').length,0);
 assert.equal(box.querySelectorAll('[onerror],[onload],[onclick]').length,0);
 assert.equal([...box.querySelectorAll('svg')].filter(s=>s.hasAttribute('onload')).length,0);
 assert.equal(w.__pwned,0);
 // 값은 글자로 보인다
 const text=box.textContent;
 for(const value of HOSTILE)assert(text.includes(value),'shown as text: '+value);
 // 속성값에 넣은 문자열이 따옴표를 깨고 속성을 만들지 못했다
 for(const node of box.querySelectorAll('[data-hp-ip],[data-hp-node],[data-block]'))
  assert.deepEqual([...node.attributes].map(a=>a.name).filter(n=>/^on/.test(n)||n==='src'),[]);
 // 버튼이 가리키는 IP 는 원문 그대로 다시 읽힌다(이스케이프·복원)
 assert.equal(document.querySelector('[data-block][data-state="blocked"] [data-hp-ip]').dataset.hpIp,'10.0.2.55');
 assert.equal([...document.querySelectorAll('[data-hp-ip]')].some(n=>n.dataset.hpIp===HOSTILE[1]),true);

 // 더블 클릭: 변경 요청은 한 번만 나간다. 409 는 사유와 함께 보이고 목록을 다시 읽는다.
 click('[data-hp-release="10.0.2.55"]');
 $('[data-hp-reason]').value='중복 방지 확인';
 const before=network.count('/api/blocklist'),posts=()=>network.calls.filter(c=>c.pathname==='/api/blocklist/10.0.2.55/release').length;
 click('[data-hp-submit]');click('[data-hp-submit]');click('[data-hp-submit]');
 await until(()=>$('.hp-message[data-kind="error"]'),'conflict message missing');
 assert.equal(posts(),1,'one request for repeated clicks');
 assert(box.textContent.includes('차단 정보가 바뀌었습니다'));
 await until(()=>network.count('/api/blocklist')>before,'list was not reloaded after the conflict');
 assert.equal(w.__pwned,0);
 assert.deepEqual(errors,[]);
});
