import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents, SUMMARY} from './detail-fixtures.mjs';

// v23 화면 개편: 문제 → 왜 위험 → 고치는 법 → 고쳐졌나(조치 기록). 앱 모듈은 파일당 한 번만 뜨므로 화면마다 파일을 나눈다.
test('infrastructure separates EC2 servers, marks the three tiers unknown and lists CloudWatch alarms',async t=>{
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
 await until(()=>$('#content').textContent.includes('Contract test event'));
 click('nav [data-view="infrastructure"]');
 await until(()=>$('#content').textContent.includes('서버 가동 상태'),'server status did not render');
 const text=$('#content').textContent;
 assert(text.includes('docker-host')&&text.includes('running')&&text.includes('service-3tier'));
 assert(text.includes('Nginx')&&text.includes('Flask')&&text.includes('MySQL')&&text.includes('확인 불가'));
 assert.equal($('#content').querySelectorAll('.service-node.unknown').length,3,'3계층은 확인 불가 — 정상으로 칠하지 않는다');
 assert(text.includes('경보')&&text.includes('공격 IP 자동 차단')&&text.includes('데이터 없음'));
 assert(!text.includes('3계층 서비스1개 구성요소'),'EC2 목록을 3계층처럼 잇지 않는다');
 assert.deepEqual(errors,[]);
});
