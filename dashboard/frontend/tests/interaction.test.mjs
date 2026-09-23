import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, NOW, tick, until, snapshot, makeFetchMock, appDOM} from './dom-test-support.mjs';

test('dashboard interactions keep selection, history and async detail state consistent', async t => {
  const network = makeFetchMock();
  const events = Array.from({length: 18}, (_, index) => ({
    ...snapshot().items[0], id: `EVT-${String(index + 3).padStart(4, '0')}`,
    title: `Fixture event ${index + 3}`, severity: index === 0 ? 'HIGH' : 'LOW',
    unit: '건', criterion: '공개 규칙 0건', criterionVersion: 'fixture-v1', beforeAt: NOW,
    evidence: 'fixture evidence', recommendation: 'fixture remediation',
    plan: {target: `resource-${index}`, change: 'fixture change', document: 'TEST-PLAYBOOK', version: '1'},
  }));
  network.respond('/api/snapshot', ({url}) => {
    let items = events;
    if (url.searchParams.get('severity')) items = items.filter(event => event.severity === url.searchParams.get('severity'));
    if (url.searchParams.get('status')) items = items.filter(event => event.status === url.searchParams.get('status'));
    return {...snapshot(), items, regionalItems: items, summary: {total: items.length, resolved: 0, regions: {'ap-northeast-2': items.length}}};
  });
  for (const event of events) {
    network.respond(`/api/events/${event.id}`, () => event);
    network.respond(`/api/events/${event.id}/approve`, () => {
      event.status = 'APPROVED'; event.approver = 'operator'; return event;
    });
  }
  network.respond('/api/events/EVT-0003/executions/job-a', {execution: {status: 'RUNNING'}});
  const {dom, w, $, click, change, errors} = appDOM(network);
  const idle = () => until(() => !$('#content').hasAttribute('aria-busy'));
  const key = (target, value, extra = {}) => target.dispatchEvent(new w.KeyboardEvent('keydown', {key: value, bubbles: true, cancelable: true, ...extra}));
  const cancelDialog = async () => {
    const dialog = $('#event-dialog');
    if (!dialog.open) return;
    if (dialog.dispatchEvent(new w.Event('cancel', {cancelable: true}))) dialog.close();
    await tick();
  };
  const navigate = async view => { click(`nav [data-view="${view}"]`); await idle(); };
  const openEvent = async id => {
    const selector = `.event-link[data-event="${id}"]`;
    $(selector).focus(); click(selector);
    await until(() => $('#dialog-title')?.textContent === events.find(event => event.id === id).title);
  };
  t.after(async () => { await cancelDialog(); dom.window.close(); });
  await import(pathToFileURL(path.join(ROOT, 'static/js/app.js')).href);
  await until(() => $('#severity-chart') && !$('#content').hasAttribute('aria-busy'));

  await t.test('notification close paths synchronize aria-expanded and restore focus on Escape', async () => {
    click('#notifications');
    assert.equal($('#notification-panel').hidden, false);
    assert.equal($('#notifications').getAttribute('aria-expanded'), 'true');
    key($('#notification-panel .notification-row'), 'Escape');
    assert.equal($('#notification-panel').hidden, true);
    assert.equal($('#notifications').getAttribute('aria-expanded'), 'false');
    assert.equal(w.document.activeElement, $('#notifications'));
    click('#notifications');
    $('#page-title').dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
    assert.equal($('#notification-panel').hidden, true);
    assert.equal($('#notifications').getAttribute('aria-expanded'), 'false');
    click('#notifications');
    $('#notification-panel .notification-row').focus();
    $('#search').focus(); await tick();
    assert.equal($('#notification-panel').hidden, true);
    assert.equal($('#notifications').getAttribute('aria-expanded'), 'false');
    click('#notifications');
    click('[data-notify="승인 대기"]'); await idle();
    assert.equal($('#notification-panel').hidden, true);
    assert.equal($('#notifications').getAttribute('aria-expanded'), 'false');
    assert.equal($('#status').value, '승인 대기');
    assert.equal(new URLSearchParams(w.location.search).get('view'), 'events');
    click('#clear-filters'); await idle();
  });

  await t.test('select-all checkbox and mixed selection reflect the actual approval count', async () => {
    await navigate('events');
    $('#pick-all').click();
    assert.equal(w.document.querySelectorAll('.row-pick:checked').length, 15);
    assert.equal($('#bulk-count').textContent, '15');
    assert.equal($('#pick-all').checked, true);
    assert.equal($('#pick-all').indeterminate, false);
    $('.row-pick').click();
    assert.equal($('#bulk-count').textContent, '14');
    assert.equal($('#pick-all').checked, false);
    assert.equal($('#pick-all').indeterminate, true);
    $('#pick-all').click();
    $('#pick-all').click();
    assert.equal($('#bulk-count').textContent, '0');
    assert.equal($('#pick-all').indeterminate, false);
  });

  await t.test('paging updates URL and bulk approval cannot act on hidden selections', async () => {
    $('.row-pick').click();
    assert.equal($('#bulk-count').textContent, '1');
    click('[data-page="next"]'); await tick();
    assert.equal(new URLSearchParams(w.location.search).get('page'), '2');
    assert.equal($('#bulk-count').textContent, '0');
    const before = network.calls.filter(call => call.options.method === 'POST').length;
    click('#bulk-approve'); await tick();
    assert.equal(network.calls.filter(call => call.options.method === 'POST').length, before);
    click('[data-page="prev"]'); await tick();
    assert.equal(new URLSearchParams(w.location.search).get('page'), null);
  });

  await t.test('filter changes prune selection before bulk approval', async () => {
    $('.row-pick').click();
    assert.equal($('#bulk-count').textContent, '1');
    change('#severity', 'Low'); await idle();
    assert.equal($('#bulk-count').textContent, '0');
    const before = network.calls.filter(call => call.options.method === 'POST').length;
    click('#bulk-approve'); await tick();
    assert.equal(network.calls.filter(call => call.options.method === 'POST').length, before);
    click('#clear-filters'); await idle();
  });

  await t.test('closing a detail via native Escape clears URL and returns focus to its trigger', async () => {
    const trigger = $('.event-link[data-event="EVT-0003"]');
    await openEvent('EVT-0003');
    assert.equal(new URLSearchParams(w.location.search).get('event'), 'EVT-0003');
    await cancelDialog();
    assert.equal($('#event-dialog').open, false);
    assert.equal(new URLSearchParams(w.location.search).get('event'), null);
    assert.equal(w.document.activeElement, trigger);
  });

  await t.test('detail close button does not leave an event in URL when close event is asynchronous', async () => {
    await openEvent('EVT-0003');
    click('.dialog-close'); await tick();
    assert.equal($('#event-dialog').open, false);
    assert.equal(new URLSearchParams(w.location.search).get('event'), null);
  });

  await t.test('browser back and forward close and restore detail without adding history entries', async () => {
    await openEvent('EVT-0003');
    const length = w.history.length;
    w.history.back();
    await until(() => !$('#event-dialog').open && !new URLSearchParams(w.location.search).has('event'));
    w.history.forward();
    await until(() => $('#event-dialog').open && $('#dialog-title')?.textContent === events[0].title);
    assert.equal(w.history.length, length);
    await cancelDialog();
  });

  await t.test('a queued close event cannot erase a different detail requested by history', async () => {
    await openEvent('EVT-0004');
    w.history.pushState({}, '', '/?view=events&event=EVT-0003');
    w.dispatchEvent(new w.PopStateEvent('popstate'));
    await idle(); await tick();
    assert.equal(new URLSearchParams(w.location.search).get('event'), 'EVT-0003');
    await until(() => $('#event-dialog').open && $('#dialog-title')?.textContent === events[0].title);
    await cancelDialog();
  });

  await t.test('keyboard navigation and refresh shortcuts do not operate the page behind a dialog', async () => {
    await openEvent('EVT-0003');
    const before = network.count('/api/snapshot');
    const view = new URLSearchParams(w.location.search).get('view');
    key($('.dialog-close'), '1'); key($('.dialog-close'), 'r');
    await tick(); await tick();
    assert.equal(network.count('/api/snapshot'), before);
    assert.equal(new URLSearchParams(w.location.search).get('view'), view);
    await cancelDialog();
  });

  await t.test('a pending poll detail cannot replace another event opened in the meantime', async () => {
    events[0].activeExecutionId = 'job-a'; events[0].status = 'EXECUTING'; events[0].execution = 'RUNNING';
    await openEvent('EVT-0003');
    const pending = network.hold('/api/events/EVT-0003');
    await until(() => pending.length === 1, 'poll did not request event details');
    await cancelDialog();
    await openEvent('EVT-0004');
    pending[0].resolve({...events[0], title: 'obsolete poll detail'});
    await tick(); await tick();
    assert.equal($('#dialog-title').textContent, events[1].title);
    assert.equal(new URLSearchParams(w.location.search).get('event'), 'EVT-0004');
    network.release('/api/events/EVT-0003');
    events[0].activeExecutionId = null; events[0].status = 'PENDING_APPROVAL'; events[0].execution = 'NOT_RUN';
    await cancelDialog();
  });

  await t.test('late evidence from an old dialog is not inserted into a newly opened event', async () => {
    const pending = network.hold('/api/events/EVT-0003/evidence');
    await openEvent('EVT-0003'); click('[data-action="evidence"]');
    await until(() => pending.length === 1);
    await cancelDialog(); await openEvent('EVT-0004');
    pending[0].resolve({items: [{no: 1, label: 'OLD EVIDENCE', value: 'stale-only-value', source: 'fixture'}]});
    await tick(); await tick();
    assert.equal($('#dialog-content').textContent.includes('stale-only-value'), false);
    assert.equal($('#dialog-title').textContent, events[1].title);
    network.release('/api/events/EVT-0003/evidence');
    await cancelDialog();
  });

  await t.test('immediate navigation consumes the pending search debounce without a second request', async () => {
    const input = $('#search'); input.value = 'typed-before-navigation';
    input.dispatchEvent(new w.Event('input', {bubbles: true}));
    const before = network.count('/api/snapshot');
    await navigate('responses');
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.equal(network.count('/api/snapshot') - before, 1);
    assert.equal(new URLSearchParams(w.location.search).get('q'), input.value);
    click('#clear-filters'); await idle();
  });

  await t.test('reset consumes search debounce and keeps URL, input and requested filter consistent', async () => {
    const input = $('#search'); input.value = 'discard-this-query';
    input.dispatchEvent(new w.Event('input', {bubbles: true}));
    const before = network.count('/api/snapshot');
    click('#clear-filters'); await idle();
    await new Promise(resolve => setTimeout(resolve, 300));
    assert.equal(network.count('/api/snapshot') - before, 1);
    assert.equal(input.value, '');
    assert.equal(new URLSearchParams(w.location.search).has('q'), false);
    const last = network.calls.filter(call => call.pathname === '/api/snapshot').at(-1);
    assert.equal(last.url.searchParams.get('q'), '');
  });

  await t.test('malformed URL filters are normalized before requesting data', async () => {
    const requestedAfter = Date.now();
    w.history.replaceState({}, '', '/?view=events&hours=-1&back=-3&page=2.5&region=invalid&severity=BOGUS&status=bogus&source=bad');
    w.dispatchEvent(new w.PopStateEvent('popstate'));
    await idle();
    const last = network.calls.filter(call => call.pathname === '/api/snapshot').at(-1).url.searchParams;
    assert.ok(Number(last.get('from')) < Number(last.get('to')));
    assert.ok(Number(last.get('to')) >= requestedAfter);
    assert.ok(Number(last.get('to')) <= Date.now());
    assert.notEqual(last.get('region'), 'invalid');
    assert.equal(last.get('severity'), ''); assert.equal(last.get('status'), ''); assert.equal(last.get('source'), '');
    const page = Number(new URLSearchParams(w.location.search).get('page') || 1);
    assert.ok(Number.isInteger(page) && page >= 1);
  });

  assert.deepEqual(errors, [], 'no window errors should escape event handlers');
});
