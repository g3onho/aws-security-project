import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {detailedEvents, SUMMARY} from './detail-fixtures.mjs';

// 보안 이벤트 화면 위쪽: 대시보드에서 조치할 수 있는 항목만 모아 보여 준다(조치 이력은 넣지 않는다).
test('events page puts summaries first and filters to manual-response items with a toggle next to the title',async t=>{
 const network=makeFetchMock();
 network.respond('/api/events',()=>{const p=detailedEvents();p.data.items[0].dashboardAction={playbookId:'ASR-RevokeSecurityGroupIngress',title:'보안그룹 전체 공개 규칙 회수',category:'manual'};return p;});
 const {dom,$,click,errors}=appDOM(network);t.after(()=>dom.window.close());
 await import(pathToFileURL(path.join(ROOT,'static/js/app.js')).href);
 await until(()=>$('#content .event-trend-widget'),'overview did not render');
 click('nav [data-view="events"]');
 await until(()=>$('#content .manual-toggle'),'수동 대응 토글이 제목 옆에 보여야 한다');
 const filters=$('#content .event-severity-filters'),donut=$('#content .event-source-donut-widget'),listPanel=$('#content .manual-toggle').closest('.panel');
 assert(filters&&donut&&!filters.closest('.panel')&&!donut.closest('.panel'),'위험도 필터·소스 그래프는 패널로 묶지 않고 따로 둔다');
 assert(!$('#content .event-overview-panel'));
 assert(donut.compareDocumentPosition(listPanel)&dom.window.Node.DOCUMENT_POSITION_FOLLOWING,'요약이 최근 보안 이벤트보다 위');
 assert.equal($('#content .heading-left h2').textContent,'최근 보안 이벤트');
 assert($('#content .manual-toggle').textContent.includes('수동 대응 1건'));
 assert(!$('#content .remediable-panel'),'따로 떠 있던 조치 패널은 없다');
 assert.equal($('#content tbody').querySelectorAll('tr.event-row,tr.event-group-row').length>=1,true,'버튼은 목록을 거르지 않는다');
 click('#content .manual-toggle');
 await until(()=>$('#bulk-dialog').open&&$('#bulk-dialog .bulk-item'),'수동 대응 팝업이 열려야 한다');
 assert.equal($('#bulk-dialog').querySelectorAll('.bulk-item').length,1);
 click('#bulk-dialog [data-bulk="close"]');
 click('#content .event-link');
 await until(()=>$('#event-dialog').open,'상세가 열려야 한다');
 assert(!$('#event-history'),'상세에는 조치 이력을 넣지 않는다');
 assert.deepEqual(errors,[]);
});
