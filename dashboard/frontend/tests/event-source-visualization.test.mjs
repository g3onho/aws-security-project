import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso} from './detail-fixtures.mjs';

const event=(id,source,severity)=>({id,title:`${id} 탐지`,scenario:'SEC-01',severity,source,
 region:'ap-northeast-2',resource:`i-${id}`,observedAt:iso(),updatedAt:iso(),
 actionState:'PENDING_APPROVAL',version:1,allowedActions:[],beforeState:null,afterState:null,verification:'NOT_RUN'});

test('overview restores the time trend and events shows one severity donut per source',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',envelope({items:[
  event('sh-critical','Security Hub','CRITICAL'),
  event('sh-high-1','Security Hub','HIGH'),
  event('sh-high-2','Security Hub','HIGH'),
  event('sh-high-3','Security Hub','HIGH'),
  event('gd-high','GuardDuty','HIGH'),
  event('waf-medium','WAF','MEDIUM'),
  event('config-low','Config','LOW'),
  event('inspector-low-1','Inspector','LOW'),
  event('inspector-low-2','Inspector','LOW'),
 ],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview event trend did not render');
 assert.equal($('#content .event-source-donut-widget'),null,'소스 도넛은 통합 관제에 중복하지 않는다');
 assert.equal($('#content .event-trend-chart').querySelectorAll('.event-trend-column').length,12,'선택 기간을 시간 구간으로 나눈다');
 click('nav [data-view="events"]');
 await until(()=>$('#content .event-link'));
 const widget=$('#content .event-source-donut-widget');
 assert.equal(widget.closest('.panel'),$('#content .event-severity-filters').closest('.panel'),'소스 구성을 최근 이벤트의 위험도 필터 아래에 둔다');
 assert.equal(widget.querySelectorAll('.source-severity-card').length,4,'고정한 탐지 소스마다 위험도 원형 그래프를 만든다');
 assert.equal(widget.querySelectorAll('button').length,0,'원형 그래프에는 필터 버튼을 추가하지 않는다');
 const card=source=>$('#content .event-source-donut-widget').querySelector(`.source-severity-card[data-source="${source}"]`);
 for(const [source,total,counts] of [
  ['Security Hub','4',{Critical:'1',High:'3',Medium:'0',Low:'0'}],
  ['GuardDuty','1',{Critical:'0',High:'1',Medium:'0',Low:'0'}],
  ['WAF','1',{Critical:'0',High:'0',Medium:'1',Low:'0'}],
  ['Config','1',{Critical:'0',High:'0',Medium:'0',Low:'1'}],
 ]){
  assert.equal(card(source).querySelector('.source-severity-total').textContent,total,`${source} 전체 건수`);
  for(const [severity,n] of Object.entries(counts))assert.equal(card(source).querySelector(`[data-severity-count="${severity}"] b`).textContent,n,`${source} ${severity}`);
 }
 assert($('#content .event-source-extra-note').textContent.includes('2건'),'기타 소스 이벤트는 차트에서 누락하지 않고 별도로 센다');
 assert.equal($('#content .event-severity-filters').querySelectorAll('[data-event-severity]').length,4,'위험도 버튼 네 개를 유지한다');
 click('#content [data-event-severity="High"]');
 await until(()=>$('#content .table-footer').textContent.includes('총 4건'),'위험도 버튼 필터가 이벤트 목록에 적용된다');
 assert.equal(card('Security Hub').querySelector('.source-severity-total').textContent,'3','소스 그래프는 현재 위험도 필터를 반영한다');
 assert.equal(card('WAF').querySelector('.source-severity-total').textContent,'0');
 assert.equal($('#content .event-severity-filters [data-event-severity="High"]').getAttribute('aria-pressed'),'true');
 assert.deepEqual(errors,[]);
});
