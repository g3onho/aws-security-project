import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install} from './honeypot-fixtures.mjs';

test('an undeployed honeypot shows one notice and never asks for data it cannot have',async t=>{
 const network=makeFetchMock();install(network,{statusData:{deployed:false,verdict:{state:'not_deployed',label:'허니팟 미배포',reasons:[]},cards:{},canWrite:false}});
 const {dom,$,click,charts,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'));
 click('nav [data-view="honeypot"]');
 await until(()=>$('#honeypot')?.textContent.includes('허니팟 미배포'),'notice missing');
 assert(!$('#honeypot').textContent.includes('차단 IP 관리'));
 assert.equal(charts.filter(c=>c.canvas.isConnected).length,0);
 for(const p of ['/api/honeypot/stats','/api/honeypot/sessions','/api/blocklist','/api/honeypot/timeline'])assert.equal(network.count(p),0,p);
 assert.deepEqual(errors,[]);
});
