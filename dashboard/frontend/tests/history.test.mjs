import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

// v20: 대응 이력은 탐지 목록이 아니라 DynamoDB 자동조치 기록(source=automatic)과 수동 기록을 보여준다.
test('response history shows automatic records, repeat counts and warnings without calling execution a resolution',async t=>{
 const network=makeFetchMock(),iso=new Date().toISOString(),old=new Date(Date.now()-3*86400000).toISOString();
 network.respond('/api/history',{data:{items:[
  {id:'auto:ssm-exec-1',source:'automatic',decision:'auto-executed',automationStatus:'SUCCESS',actionState:'EXECUTED',
   findingType:'EC2.19 open port',resource:'arn:aws:ec2:::security-group/sg-0abc',occurrenceCount:1,executionId:'exec-1',
   eventId:'SH-1',createdAt:iso,lastSeenAt:iso,verification:'NOT_RUN'},
  {id:'auto:fnd-1',source:'automatic',decision:'manual-notified',automationStatus:'NOTIFIED',actionState:'PENDING_APPROVAL',
   findingType:'MFA should be enabled',resource:'arn:aws:iam::111:user/admin',occurrenceCount:4,executionId:null,
   eventId:'SH-2',createdAt:iso,lastSeenAt:iso,verification:'NOT_RUN'},
  {id:'auto:fnd-old',source:'automatic',decision:'manual-notified',automationStatus:'NOTIFIED',actionState:'PENDING_APPROVAL',
   findingType:'Three days old record',resource:'arn:aws:iam::111:user/old',occurrenceCount:1,executionId:null,
   eventId:'SH-3',createdAt:old,lastSeenAt:old,verification:'NOT_RUN'}],jobs:[],nextCursor:null},
  meta:{schemaVersion:'1',asOf:iso,partial:true,warnings:['자동조치 이력이 많아 일부만 표시합니다.']}});
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content').textContent.includes('Contract test event'),'overview did not render');
 click('nav [data-view="responses"]');
 await until(()=>$('#audit-log')?.textContent.includes('EC2.19 open port'),'automatic record did not render');
 const text=$('#audit-log').textContent;
 assert(text.includes('자동 실행')&&text.includes('실행 완료 · 재검증 전'));
 assert(text.includes('수동 대응 필요')&&text.includes('담당자 알림'));
 assert(text.includes('exec-1')&&text.includes('자동 2건'));
 assert(text.includes('자동조치 이력이 많아 일부만 표시합니다.'),'warning must be visible');
 assert(!text.includes('해결'),'execution must not be shown as resolved');
 // v20.5: 1주일을 받아 기간 트랙은 이력 수를 세고, 표에는 선택 기간(기본 1일)만 남긴다.
 const call=network.calls.find(c=>c.pathname==='/api/history');
 assert.equal(Date.parse(call.url.searchParams.get('to'))-Date.parse(call.url.searchParams.get('from')),7*86400000);
 assert(!text.includes('Three days old record'),'선택 기간 밖 기록은 표에서 뺀다');
 await until(()=>$('#time-label').textContent.includes('대응 이력'),'트랙은 대응 이력 수를 센다');
 assert.match($('#time-label').textContent,/대응 이력 2건/);
 assert.match($('#period-track [data-hours="168"]').title,/대응 이력 3건/);
 assert.equal($('#content').textContent.includes('Contract test event'),false,'responses view must not list detections');
 assert.deepEqual(errors,[]);
});
