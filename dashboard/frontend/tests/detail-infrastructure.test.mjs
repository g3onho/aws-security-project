import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents, SUMMARY} from './detail-fixtures.mjs';

// v23 화면 개편: 문제 → 왜 위험 → 고치는 법 → 고쳐졌나(조치 기록). 앱 모듈은 파일당 한 번만 뜨므로 화면마다 파일을 나눈다.
test('infrastructure lists EC2 status and CloudWatch alarms while tiers stay summarized on overview',async t=>{
 const network=makeFetchMock();
 network.respond('/api/infra/status',envelope({components:[{id:'ap-northeast-2/i-1/i-1',name:'docker-host',resource:'i-1',region:'ap-northeast-2',
   status:'healthy',source:'EC2',detail:'running',observedAt:iso(),kind:'server',role:'service-3tier'}],dependencies:[],
  tiers:[{id:'tier/web',name:'Nginx',role:'웹',status:'unknown',observedAt:null,source:null,detail:'점검 결과 없음'},
         {id:'tier/app',name:'Flask',role:'애플리케이션',status:'unknown',observedAt:null,source:null,detail:'점검 결과 없음'},
         {id:'tier/db',name:'MySQL',role:'데이터베이스',status:'unknown',observedAt:null,source:null,detail:'점검 결과 없음'}],
  alarms:[{name:'soar-sec-dev-ssh-reject',label:'SSH(22) 접속 거부 급증 (Flow Logs)',kind:'ssh-reject',scenario:'SEC-06B',state:'ALARM',noData:false,
           metric:'SSHRejectCount',comparison:'GreaterThanOrEqualToThreshold',threshold:10,periodSeconds:300,evaluationPeriods:1,notifies:true,
           autoResponse:{mode:'auto',label:'공격 IP 자동 차단',detail:'NACL Deny'},updatedAt:iso()},
          {name:'soar-sec-dev-mysql-bruteforce',label:'MySQL 로그인 실패 급증',kind:'mysql-bruteforce',scenario:'SEC-06A',state:'OK',noData:true,
           metric:'MySQLAuthFailure',threshold:10,notifies:true,autoResponse:null,updatedAt:iso()}]}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'));
 click('nav [data-view="infrastructure"]');
 await until(()=>$('#content').textContent.includes('서버 가동 상태'),'server status did not render');
 const text=$('#content').textContent;
 assert(text.includes('docker-host')&&text.includes('running')&&text.includes('service-3tier'));
 assert(!text.includes('3계층 서비스'),'3계층 요약은 통합관제 화면에 둔다');
 assert.equal($('#content').querySelectorAll('.service-node').length,0,'인프라 화면에 중복 계층 흐름을 두지 않는다');
 assert(text.includes('경보')&&text.includes('공격 IP 자동 차단')&&text.includes('데이터 없음'));
 assert.equal($('#content').querySelectorAll('.alarm-status-group').length,2,'경보와 확인 필요 두 구역만 둔다(정상은 표시하지 않음)');
 assert($('#content .alarm-status-group.alarm').textContent.includes('SSH(22) 접속 거부 급증'));
 assert($('#content .alarm-status-group.alarm').textContent.includes('공격 IP 자동 차단'));
 assert(!$('#content .alarm-status-board').textContent.includes('MySQL 로그인 실패 급증'),'사건이 있어야 지표가 생기는 경보의 데이터 없음은 정상이라 보드에 올리지 않는다');
 assert.equal($('#content .alarm-status-group.check').textContent.includes('해당 경보 없음'),true);
 assert.equal($('#content .alarm-details').open,false,'조건과 변경 시각은 펼쳐서 확인한다');
 assert(!text.includes('3계층 서비스1개 구성요소'),'EC2 목록을 3계층처럼 잇지 않는다');
 assert.deepEqual(errors,[]);
});
