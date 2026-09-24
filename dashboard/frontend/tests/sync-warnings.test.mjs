import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM, snapshot, vulnerabilities} from './dom-test-support.mjs';

// v21: 탐지·취약점을 DynamoDB 적재에서 읽을 때 동기화 지연·실패 경고(meta.warnings)를 숨기지 않는다.
test('sync delay warnings from events and vulnerabilities are visible',async t=>{
 const network=makeFetchMock();
 const withWarning=(payload,warning)=>({...payload,meta:{...payload.meta,warnings:[warning]}});
 network.respond('/api/events',()=>withWarning(snapshot(),'탐지 동기화가 45분 동안 완료되지 않았습니다.'));
 network.respond('/api/vulnerabilities',()=>withWarning(vulnerabilities(),'최근 취약점 동기화가 실패했습니다.'));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#worker-state').textContent.includes('탐지 동기화가 45분'),'event sync warning is hidden');
 click('nav [data-view="vulnerabilities"]');
 await until(()=>$('#content').textContent.includes('최근 취약점 동기화가 실패했습니다.'),'vulnerability sync warning is hidden');
 assert($('#content').textContent.includes('CVE-2026-0001'),'rows stay visible with the warning');
 assert.deepEqual(errors,[]);
});
