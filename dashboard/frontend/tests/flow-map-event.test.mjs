import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {envelope, iso, detailedEvents} from './detail-fixtures.mjs';

test('event detail draws the architecture flow map and refines it with the remediation record',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',detailedEvents);
 network.respond('/api/history',()=>envelope({items:[{id:'auto:1',source:'automatic',decision:'auto-executed',automationStatus:'SUCCESS',actionState:'EXECUTED',eventId:'EVT-0003',createdAt:iso(),lastSeenAt:iso(),occurrenceCount:1,reason:'x',execution:{status:'Success',removed:[],added:[],changed:true,source:'ssm-output',verification:'NOT_RUN'}}],jobs:[],nextCursor:null}));
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="events"]');
 await until(()=>$('#content .event-link'),'event list did not render');
 click('#content .event-link');
 await until(()=>$('#event-dialog').open&&$('#event-flow svg.flow-svg'),'flow map did not render');
 assert($('#event-flow').textContent.includes('경로 지도')||$('#dialog-content').textContent.includes('경로 지도'));
 assert.equal($('#event-flow ol.hp-map-list').children.length,7,'7단계 목록(색에만 의존하지 않는 글자 상태)');
 assert($('#event-flow [data-edge="det-sh"]'),'Security Hub 탐지 경로');
 assert.equal($('#event-flow .hp-mp-badge[data-stage="detect"]').dataset.state,'done');
 assert(/기록 없음|없/.test($('#event-flow li[data-stage="origin"]').textContent),'출발지 없으면 정상이 아니라 기록 없음');
 assert(!$('#event-flow svg').classList.contains('play'),'상세 창에서는 애니메이션 없이 정적으로 그린다');
 assert.deepEqual(errors,[]);
});
