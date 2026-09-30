import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents, SUMMARY} from './detail-fixtures.mjs';

// v23 화면 개편: 문제 → 왜 위험 → 고치는 법 → 고쳐졌나(조치 기록). 앱 모듈은 파일당 한 번만 뜨므로 화면마다 파일을 나눈다.
test('vulnerability groups explain the risk and how to fix it',async t=>{
 const network=makeFetchMock();
 network.respond('/api/vulnerabilities',envelope({items:[{id:'v1',cveId:'CVE-2026-1234',resource:'i-fixture',resourceName:'docker-host',
  severity:'HIGH',source:'Inspector',region:'ap-northeast-2',observedAt:iso(),package:'linux-image-aws',cvss:7.8,installedVersion:'6.8.0-1',
  fixedVersion:'6.8.0-2',description:'A use-after-free flaw was found in the Linux kernel.',exploitAvailable:'YES',epss:0.0123,
  updateCommand:'sudo apt-get update && sudo apt-get install --only-upgrade -y linux-image-aws',updateCommandSource:'generated',
  fixMethod:'package-update',rebootRequired:true,referenceUrl:'https://nvd.nist.gov/vuln/detail/CVE-2026-1234',imageTags:[]}],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'));
 click('nav [data-view="vulnerabilities"]');
 await until(()=>$('#vulns .cve-group'),'vulnerability groups did not render');
 const group=$('#vulns .cve-group');
 assert(group.querySelectorAll('summary .sev-chip').length>0,'패키지 행은 심각도 칩(건수)을 보여준다(v27 목록)');
 assert(group.querySelector('summary .sev-bar'),'심각도 구성은 막대로 보여준다');
 assert(group.querySelector('summary .vg-main').textContent.includes('linux-image-aws'));
 assert(group.textContent.includes('왜 위험한가')&&group.textContent.includes('use-after-free'));
 assert(group.textContent.includes('sudo apt-get update && sudo apt-get install --only-upgrade -y linux-image-aws'));
 assert(group.textContent.includes('적용 전 확인'),'대시보드가 만든 명령임을 밝힌다');
 assert(group.textContent.includes('업데이트 후 재부팅해야 적용됩니다'));
 assert.equal(group.querySelector('a.doc-link').getAttribute('href'),'https://nvd.nist.gov/vuln/detail/CVE-2026-1234');
 click('#vulns [data-vuln-filter="HIGH"]');
 await until(()=>$('#vulns [data-vuln-filter="HIGH"]')?.getAttribute('aria-pressed')==='true','위험도 버튼이 필터를 적용하지 않았다');
 assert.deepEqual(errors,[]);
});
