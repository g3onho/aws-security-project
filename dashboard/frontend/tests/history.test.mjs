import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

// v20: 조치 이력(v23 이름 변경, 옛 '대응 이력')은 탐지 목록이 아니라 DynamoDB 자동조치 기록(source=automatic)과 수동 기록을 보여준다.
// v23: 자동 실행과 수동 대응 필요를 나누고, 판정 이유와 조치 직후 SSM 보고값(전/후)을 보여준다. 실행 ID 는 본문 대신 툴팁.
test('response history shows automatic records, repeat counts and warnings without calling execution a resolution',async t=>{
 const network=makeFetchMock(),iso=new Date().toISOString(),old=new Date(Date.now()-3*86400000).toISOString();
 network.respond('/api/history',{data:{items:[
  {id:'auto:ssm-exec-1',source:'automatic',decision:'auto-executed',automationStatus:'SUCCESS',actionState:'EXECUTED',
   findingType:'EC2.19 open port',resource:'arn:aws:ec2:::security-group/sg-0abc',occurrenceCount:1,executionId:'exec-1',
   eventId:'SH-1',createdAt:iso,lastSeenAt:iso,verification:'NOT_RUN',reason:'보안그룹 전체 공개 규칙 회수(화이트리스트 + 태그)',
   execution:{status:'Success',removed:['TCP 3306 ← 0.0.0.0/0'],added:[],changed:true,source:'ssm-output',verification:'NOT_RUN'}},
  {id:'auto:fnd-1',source:'automatic',decision:'manual-notified',automationStatus:'NOTIFIED',actionState:'PENDING_APPROVAL',
   findingType:'MFA should be enabled',resource:'arn:aws:iam::111:user/admin',occurrenceCount:4,executionId:null,
   eventId:'SH-2',createdAt:iso,lastSeenAt:iso,verification:'NOT_RUN'},
  {id:'auto:fnd-old',source:'automatic',decision:'manual-notified',automationStatus:'NOTIFIED',actionState:'PENDING_APPROVAL',
   findingType:'Three days old record',resource:'arn:aws:iam::111:user/old',occurrenceCount:1,executionId:null,
   eventId:'SH-3',createdAt:old,lastSeenAt:old,verification:'NOT_RUN'}],jobs:[],external:[{id:'external:SH-9',eventId:'SH-9',title:'Old open finding',resource:'arn:aws:s3:::bucket-x',severity:'HIGH',resolvedAt:iso}],remediations:[{id:'rem-1',eventId:'SH-1',actor:'admin',state:'NOT_RESOLVED',playbookId:'ASR-RevokeSecurityGroupIngress',title:'보안그룹 전체 공개 규칙 회수',reason:'화면 확인',resource:'arn:aws:ec2:::security-group/sg-0abc',region:'ap-northeast-2',eventTitle:'EC2.19 open port',controlId:'EC2.19',executionId:'exec-9',ssmStatus:'Success',before:{text:'전체 공개 규칙 1개'},verification:{passed:false,text:'전체 공개 규칙 1개',checkedAt:iso},createdAt:iso,updatedAt:iso}],nextCursor:null},
  meta:{schemaVersion:'1',asOf:iso,partial:true,warnings:['자동조치 이력이 많아 일부만 표시합니다.']}});
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="responses"]');
 await until(()=>$('#audit-log')?.textContent.includes('EC2.19 open port'),'automatic record did not render');
 const text=$('#audit-log').textContent;
 const rowsOf=()=>[...$('#audit-log').querySelectorAll('tbody tr')];
 assert($('#content').innerHTML.includes('실행 완료 · 재검증 전')&&!$('#content .hist-state'),'자동 실행 성공은 재검증 전으로 표시');
 assert(!text.includes('MFA should be enabled'),'알림만 보낸 판정은 조치 이력이 아니다(보안 이벤트에서 확인)');
 assert(!$('#audit-log details.hist-bucket')&&!$('#audit-log .history-block'),'블록·구간 묶음 없이 한 목록');
 assert.equal(rowsOf().length,3,'자동 1 + 대시보드 1 + 외부 해결 1');
 const chips=rowsOf().map(r=>[...r.querySelectorAll('.hist-chip')].map(c=>c.textContent).join('|'));
 assert(chips.includes('자동|실행 성공'),'자동 실행 성공은 해결이 아니라 실행 성공일 뿐');
 assert(chips.includes('대시보드|실행 성공'),'대시보드 조치도 실행 성공으로만 표시');
 assert(chips.includes('외부 해결(추정)'),'외부 해결은 시도가 아니라 실행·재검증 칩이 없다');
 assert(text.includes('외부에서 해결된 것으로 추정'),'외부 해결은 추정이라고 밝힌다');
 assert($('#audit-log [title$="SSM 실행 exec-1"]'),'실행 ID 는 툴팁으로 남긴다');
 assert(text.includes('보안그룹 전체 공개 규칙 회수'),'판정 이유가 보인다');
 assert(text.includes('자동조치 이력이 많아 일부만 표시합니다.'),'warning must be visible');
 assert(!text.includes('해결 확인 · 재검증 통과'),'재검증을 통과하지 못한 조치는 해결 확인이 아니다');
 assert.match($('#audit-log .history-summary').textContent,/시도 2건\(이벤트 1개\) · 실행 성공 2 · 실행 실패 0/,'요약은 시도·이벤트 수 기준');
 assert($('#audit-log .history-summary').textContent.includes('실행 성공이 해결은 아닙니다'));
 assert(!$('#audit-log .hist-filters')&&!$('#audit-log [data-hist-who]'),'방식·결과는 필터 탭이 아니라 표시만 한다');
 // v20.5: 1주일을 받아 기간 트랙은 이력 수를 세고, 표에는 선택 기간(기본 1일)만 남긴다.
 const call=network.calls.find(c=>c.pathname==='/api/history');
 assert.equal(Date.parse(call.url.searchParams.get('to'))-Date.parse(call.url.searchParams.get('from')),7*86400000);
 assert(!text.includes('Three days old record'),'선택 기간 밖 기록은 표에서 뺀다');
 await until(()=>$('#time-label').textContent.includes('조치 이력'),'트랙은 조치 이력 수를 센다');
 assert.match($('#time-label').textContent,/조치 이력 2건/);
 assert.match($('#period-track [data-hours="168"]').title,/조치 이력 3건/);
 assert.equal($('nav [data-view="responses"]').textContent.includes('조치 이력'),true,'메뉴 이름은 조치 이력');
 assert.equal($('#content').textContent.includes('Contract test event'),false,'responses view must not list detections');
 assert.deepEqual(errors,[]);
});
