import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT} from './dom-test-support.mjs';

const mod=await import(pathToFileURL(path.join(ROOT,'static/js/ui/pages/flow-map.js')).href);
const {eventStages,scenarioStages,flowBlock,detectorOf}=mod;
const base={id:'E1',source:'Security Hub',resource:'arn:aws:ec2:ap-northeast-2:1:security-group/sg-1',observedAt:'2026-09-29T00:00:00Z'};
const S=(m,k)=>m.stages[k].state;

test('event stages come from real fields and never show missing data as success',()=>{
 let m=eventStages({...base,actionState:'EXECUTION_FAILED',autoRemediation:{mode:'auto',label:'자동',reason:'r'}});
 assert.equal(S(m,'act'),'failed');assert.equal(S(m,'verify'),'missing');assert.equal(S(m,'origin'),'missing');
 m=eventStages({...base,actionState:'VERIFIED',sourceIp:'1.2.3.4',autoRemediation:{mode:'auto',label:'자동'}});
 assert.equal(S(m,'act'),'done');assert.equal(S(m,'verify'),'done');assert.equal(S(m,'origin'),'done');
 m=eventStages({...base,actionState:'PENDING_APPROVAL',actionable:false,autoRemediation:{mode:'none',label:'없음'}});
 assert.equal(S(m,'act'),'missing');
 m=eventStages({...base,actionState:'RECONCILING'});assert.equal(S(m,'act'),'unknown');assert.equal(S(m,'judge'),'unknown');
 m=eventStages({...base,actionState:'VERIFICATION_ERROR'});assert.equal(S(m,'verify'),'unknown');
 assert.equal(detectorOf('GuardDuty'),'gd');assert.equal(detectorOf('알 수 없는 것'),null);
});
test('scenario stages mark design path as design and take execution only from run items',()=>{
 const s={id:'SEC-02',purpose:'서비스 포트',sources:['Security Hub','Inspector'],response:'수동 승인'};
 let m=scenarioStages(s,null);assert.equal(S(m,'origin'),'unknown');assert.equal(S(m,'detect'),'design');
 m=scenarioStages(s,[]);assert.equal(S(m,'origin'),'missing');
 m=scenarioStages(s,[{sec:'SEC-02',status:'Failed'}]);assert.equal(S(m,'origin'),'failed');
 m=scenarioStages(s,[{sec:'SEC-02',status:'Success'}]);assert.equal(S(m,'origin'),'done');
 m=scenarioStages({...s,id:'SEC-06B'},[{sec:'SEC-08',status:'InProgress'}]);assert.equal(S(m,'origin'),'pending');
 m=scenarioStages({...s,response:'없음'},[]);assert.equal(S(m,'act'),'missing');assert.equal(S(m,'judge'),'missing');
});
test('hostile strings are escaped in svg and list',()=>{
 const evil='<img src=x onerror=alert(1)>';
 const html=flowBlock(eventStages({...base,source:evil,resource:evil,sourceIp:evil,actionState:'EXECUTED',autoRemediation:{mode:'auto',label:evil,reason:evil}}));
 assert(!html.includes('<img'));assert(html.includes('&lt;img'));
 const sc=flowBlock(scenarioStages({id:evil,purpose:evil,sources:[evil],response:evil},[]));
 assert(!sc.includes('<img'));
});
