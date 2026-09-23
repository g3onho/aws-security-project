import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, appDOM, until} from './dom-test-support.mjs';

test('unconfigured source is shown as an error without invented events or metrics', async t => {
  const response = (data, status=200) => ({ok: status < 400, status, json: async () => data});
  const {dom, $, errors} = appDOM({fetch: async url => {
    const pathname = new URL(url, 'http://localhost/').pathname;
    if(pathname === '/api/auth/session') return response({user: {name:'operator'}, csrfToken:'test-csrf'});
    if(pathname === '/api/legacy/config') return response({mode:'live', asOf:Date.now(), role:'operator', writeEnabled:false, dataSourceConnected:false});
    if(pathname === '/api/legacy/health') return response({checks:{dataSource:'not_configured'}, aws_connected:false});
    if(pathname === '/static/data/countries.geojson') return response({features:[]});
    return response({code:'DATA_SOURCE_NOT_CONFIGURED', title:'실데이터 공급자가 연결되지 않았습니다.'}, 503);
  }});
  t.after(() => dom.window.close());
  await import(pathToFileURL(path.join(ROOT, 'static/js/app.js')).href);
  await until(() => !$('#load-state').hidden && $('#load-state').textContent.includes('실데이터 공급자'));
  assert.equal($('#content').querySelectorAll('canvas,tr[data-id]').length, 0);
  assert.equal($('#data-mode').textContent, '데이터 소스 미연결');
  assert.equal($('#notification-count').hidden, true);
  assert.equal(errors.length, 0);
});
