import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT} from './dom-test-support.mjs';

const {scenarioRoute,routeSvg,routeOf}=await import(pathToFileURL(path.join(ROOT,'static/js/ui/pages/scenario-map.js')).href);
const sc=(id,sources,response)=>({id,purpose:'목적 '+id,sources,response});
const now=Date.now();
const ev=(source,at,extra={})=>({id:'e1',source,observedAt:new Date(at).toISOString(),actionState:'PENDING_APPROVAL',actionable:true,autoRemediation:{mode:'auto',label:'자동'},...extra});

test('routes differ per scenario',()=>{
 assert.notEqual(routeOf('SEC-01').t,routeOf('SEC-06A').t);
 const a=routeSvg(scenarioRoute(sc('SEC-01',['AWS Config'],'자동'),[]));
 const b=routeSvg(scenarioRoute(sc('SEC-06A',['GuardDuty'],'자동'),[]));
 assert.notEqual(a,b);
});
test('events after the run fill steps as estimates; none -> missing; no run time -> design only',()=>{
 const s=sc('SEC-01',['AWS Config'],'자동');
 const hit=scenarioRoute(s,[{sec:'SEC-01',status:'Success'}],{events:[ev('AWS Config',now)],since:now-1000});
 assert.equal(hit.stages.detect.state,'done');assert(hit.stages.detect.detail.startsWith('추정'));
 assert.equal(hit.stages.origin.state,'done');
 const old=scenarioRoute(s,[],{events:[ev('AWS Config',now-3600e3)],since:now});
 assert.equal(old.stages.detect.state,'missing');assert.equal(old.stages.verify.state,'missing');
 const none=scenarioRoute(s,[],{events:[ev('AWS Config',now)],since:null});
 assert.equal(none.stages.detect.state,'design');
 const other=scenarioRoute(s,[],{events:[ev('GuardDuty',now)],since:now-1000});
 assert.equal(other.stages.detect.state,'missing','다른 탐지 원천의 이벤트는 일치로 보지 않는다');
});
test('scenario without response keeps judge/act/verify as missing even with events',()=>{
 const m=scenarioRoute(sc('SEC-09',['CloudTrail'],'없음'),[],{events:[ev('CloudTrail',now)],since:now-1000});
 assert.equal(m.stages.detect.state,'done');assert.equal(m.stages.judge.state,'missing');
});
