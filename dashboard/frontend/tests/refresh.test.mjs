import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, NOW, tick, until, snapshot, vulnerabilities, makeFetchMock, appDOM} from './dom-test-support.mjs';

test('dashboard refreshes preserve content and ignore outdated requests', async t => {
  const network = makeFetchMock();
  const {dom, $, click, change, charts, errors} = appDOM(network);
  t.after(() => dom.window.close());
  await import(pathToFileURL(path.join(ROOT, 'static/js/app.js')).href);
  await until(() => $('#severity-chart') && !$('#content').hasAttribute('aria-busy'), 'initial dashboard did not render');
  const loading = () => $('#network-activity').classList.contains('is-loading');
  const activityIdle = () => until(() => !loading(), 'network activity did not settle');

  await t.test('top activity status starts immediately and remains visible for a fast request in reduced-motion mode', async () => {
    const indicator = $('#network-activity');
    assert.ok(indicator, 'the persistent top activity slot must exist');
    assert.equal(indicator.tagName, 'DIV');
    assert.equal(indicator.getAttribute('role'), 'status');
    assert.equal(indicator.getAttribute('aria-label'), '데이터 불러오는 중');
    assert.equal(indicator.querySelector('.sr-only').textContent, '데이터 불러오는 중');
    assert.equal(dom.window.matchMedia('(prefers-reduced-motion: reduce)').matches, true);
    await activityIdle();
    const started = performance.now();
    click('#refresh');
    assert.equal(loading(), true, 'activity must be visible before the request returns');
    assert.equal($('#load-state').hidden, true, 'the old banner is reserved for errors');
    await until(() => !$('#content').hasAttribute('aria-busy'));
    assert.equal(loading(), true, 'a fast response must not immediately hide the activity status');
    await activityIdle();
    assert.ok(performance.now() - started >= 340, 'fast activity should last at least 350ms (10ms timer tolerance)');
    assert.equal($('#network-activity'), indicator, 'the top activity slot remains mounted while idle');
    assert.equal(indicator.hidden, false, 'idle visibility is controlled by CSS without removing its layout slot');
  });

  await t.test('same-view refresh retains canvas and updates the existing Chart without animation', async () => {
    const canvas = $('#severity-chart');
    const section = $('#content').firstElementChild;
    const chart = charts.find(item => item.canvas === canvas);
    assert.ok(chart, 'chart was constructed');
    click('#refresh');
    await until(() => !$('#content').hasAttribute('aria-busy'));
    assert.equal($('#severity-chart'), canvas);
    assert.equal($('#content').firstElementChild, section);
    assert.equal(chart.destroyed, false);
    assert.ok(chart.updates.includes('none'), 'chart refresh must use update("none")');
    assert.equal(charts.filter(item => item.canvas.id === 'severity-chart').length, 1);
  });

  await t.test('selecting the active menu and time range sends no requests', async () => {
    await activityIdle();
    const before = network.calls.length;
    const canvas = $('#severity-chart');
    click('nav [data-view="overview"]');
    click('[data-hours="24"]');
    await tick(); await tick();
    assert.equal(network.calls.length, before);
    assert.equal($('#severity-chart'), canvas);
    assert.equal($('#load-state').hidden, true);
    assert.equal(loading(), false);
  });

  await t.test('snapshot failure keeps previous content; successful retry clears the error', async () => {
    const pending = network.hold('/api/snapshot');
    const canvas = $('#severity-chart');
    const content = $('#content').textContent;
    click('#refresh');
    await until(() => pending.length === 1);
    pending[0].reject(new Error('snapshot fixture unavailable'));
    await until(() => !$('#content').hasAttribute('aria-busy') && $('#retry'));
    assert.equal($('#content').textContent, content);
    assert.equal($('#severity-chart'), canvas);
    assert.equal($('#content').dataset.stale, 'true');
    assert.equal($('#load-state').hidden, false);
    assert.equal($('#refresh').disabled, false);
    assert.ok($('#load-state').textContent.includes('snapshot fixture unavailable'));
    await activityIdle();
    assert.equal($('#load-state').hidden, false, 'an error remains readable after network activity ends');
    click('#retry');
    await until(() => pending.length === 2);
    assert.equal(loading(), true);
    assert.equal($('#load-state').hidden, true);
    pending[1].resolve(snapshot('snapshot recovered'));
    await until(() => !$('#content').hasAttribute('aria-busy'));
    assert.ok($('#content').textContent.includes('snapshot recovered'));
    assert.equal($('#content').hasAttribute('data-stale'), false);
    assert.equal($('#load-state').hidden, true);
    assert.equal($('#load-state').classList.contains('error'), false);
    assert.equal($('#severity-chart'), canvas);
    await activityIdle();
    network.release('/api/snapshot');
  });

  await t.test('slow refresh keeps content visible; superseded completion cannot clear newer loading state', async () => {
    const pending = network.hold('/api/snapshot');
    const canvas = $('#severity-chart');
    const section = $('#content').firstElementChild;
    click('#refresh');
    await until(() => pending.length === 1);
    assert.equal(loading(), true, 'even a new fast request immediately exposes top activity');
    assert.equal($('#load-state').hidden, true, 'the old banner must stay hidden during loading');
    assert.equal($('#content').firstElementChild, section);
    await new Promise(resolve => setTimeout(resolve, 400));
    assert.equal(loading(), true, 'slow requests keep the top activity status visible');
    assert.equal($('#load-state').hidden, true, 'slow requests must not restore the old loading banner');
    assert.equal($('#severity-chart'), canvas);
    change('#severity', 'High');
    await until(() => pending.length === 2);
    pending[0].resolve(snapshot('older-response'));
    await tick(); await tick();
    assert.equal($('#refresh').disabled, true);
    assert.equal($('#content').getAttribute('aria-busy'), 'true');
    assert.equal(loading(), true, 'an older completion cannot clear newer activity');
    pending[1].resolve(snapshot('newer-response'));
    await until(() => !$('#content').hasAttribute('aria-busy'));
    assert.ok($('#content').textContent.includes('newer-response'));
    assert.equal($('#content').textContent.includes('older-response'), false);
    assert.equal($('#severity-chart'), canvas);
    await activityIdle();
    network.release('/api/snapshot');
  });

  await t.test('late snapshot cannot overwrite data from a newer completed request', async () => {
    const pending = network.hold('/api/snapshot');
    click('#refresh'); await until(() => pending.length === 1);
    change('#severity', 'Critical'); await until(() => pending.length === 2);
    pending[1].resolve(snapshot('latest-first'));
    await until(() => $('#content').textContent.includes('latest-first'));
    await new Promise(resolve => setTimeout(resolve, 400));
    assert.equal($('#content').hasAttribute('aria-busy'), false);
    assert.equal(loading(), true, 'a late in-flight request must remain tracked after the newer refresh completes');
    pending[0].resolve(snapshot('stale-last'));
    await tick(); await tick();
    assert.equal($('#content').textContent.includes('stale-last'), false);
    assert.equal($('#refresh').disabled, false);
    assert.equal($('#load-state').hidden, true);
    await activityIdle();
    network.release('/api/snapshot');
  });

  await t.test('CVE paging and page-size changes use loaded data and retain table controls', async () => {
    click('nav [data-view="vulnerabilities"]');
    await until(() => $('#vulns .cve-link'));
    const size = $('#vuln-size');
    const scroll = $('#vulns .table-scroll');
    const before = network.count('/api/vulnerabilities');
    assert.equal($('#vulns .cve-link').textContent, 'CVE-2026-00001');
    scroll.scrollTop = 120; scroll.scrollLeft = 40;
    click('[data-vuln-page="next"]');
    await tick();
    assert.equal($('#vulns .cve-link').textContent, 'CVE-2026-00051');
    assert.equal(network.count('/api/vulnerabilities'), before);
    assert.equal(scroll.scrollTop, 0);
    assert.equal(scroll.scrollLeft, 40);
    scroll.scrollTop = 120;
    change('#vuln-size', '25');
    await tick();
    assert.equal($('#vulns .cve-link').textContent, 'CVE-2026-00001');
    assert.equal($('#vulns tbody').children.length, 25);
    assert.equal(network.count('/api/vulnerabilities'), before);
    assert.equal($('#vuln-size'), size);
    assert.equal(size.value, '25');
    assert.equal(scroll.scrollTop, 0);
    assert.equal(scroll.scrollLeft, 40);
  });

  await t.test('panel failure preserves the CVE table and a successful retry removes its error', async () => {
    const pending = network.hold('/api/vulnerabilities');
    const box = $('#vulns');
    const table = $('#vulns table');
    const firstCve = $('#vulns .cve-link');
    click('#refresh');
    await until(() => pending.length === 1);
    pending[0].reject(new Error('vulnerability fixture unavailable'));
    await until(() => !$('#content').hasAttribute('aria-busy') && $('#vulns .panel-error'));
    assert.equal($('#vulns'), box);
    assert.equal($('#vulns table'), table);
    assert.equal($('#vulns .cve-link'), firstCve);
    assert.ok($('#vulns .panel-error').textContent.includes('vulnerability fixture unavailable'));
    await activityIdle();
    assert.equal($('#load-state').hidden, true, 'panel errors must not turn the old global banner into a loading notice');
    click('#refresh');
    await until(() => pending.length === 2);
    pending[1].resolve(vulnerabilities('recovered-panel'));
    await until(() => !$('#content').hasAttribute('aria-busy'));
    assert.equal($('#vulns .panel-error'), null);
    assert.ok(box.textContent.includes('recovered-panel'));
    assert.equal($('#vulns table'), table);
    network.release('/api/vulnerabilities');
  });

  await t.test('standalone panel requests own activity through success and failure without refreshing the snapshot', async () => {
    await activityIdle();
    const pending = network.hold('/api/vulnerabilities');
    const snapshots = network.count('/api/snapshot');
    const box = $('#vulns');
    const table = $('#vulns table');
    click('.vuln-group-head[data-vuln-target]');
    assert.equal(loading(), true);
    await until(() => pending.length === 1);
    assert.equal($('#content').hasAttribute('aria-busy'), false);
    assert.equal(box.getAttribute('aria-busy'), 'true');
    assert.equal(network.count('/api/snapshot'), snapshots);
    await new Promise(resolve => setTimeout(resolve, 400));
    assert.equal(loading(), true, 'panel-only activity must outlast the minimum display time');
    assert.equal($('#load-state').hidden, true);
    pending[0].resolve(vulnerabilities('standalone-panel'));
    await until(() => !box.hasAttribute('aria-busy'));
    assert.ok(box.textContent.includes('standalone-panel'));
    assert.equal($('#vulns table'), table);
    await activityIdle();

    click('button[data-vuln-target=""]');
    assert.equal(loading(), true);
    await until(() => pending.length === 2);
    pending[1].reject(new Error('standalone panel unavailable'));
    await until(() => $('#vulns .panel-error'));
    await activityIdle();
    assert.equal(box.hasAttribute('aria-busy'), false);
    assert.equal(network.count('/api/snapshot'), snapshots);
    assert.ok(box.textContent.includes('standalone-panel'), 'failed panel-only activity preserves the prior data');
    assert.ok($('#vulns .panel-error').textContent.includes('standalone panel unavailable'));
    assert.equal($('#load-state').hidden, true);
    network.release('/api/vulnerabilities');
    click('#refresh');
    await until(() => !$('#content').hasAttribute('aria-busy') && !$('#vulns .panel-error'));
    await activityIdle();
  });

  for (const panel of [
    {view: 'vulnerabilities', selector: '#vulns', route: '/api/vulnerabilities', data: vulnerabilities},
    {view: 'vulnerabilities', selector: '#coverage', route: '/api/scenarios', data: marker => ({items: [], catalogVersion: marker})},
    {view: 'responses', selector: '#audit-log', route: '/api/audit', data: marker => ({items: [{at: NOW, actor: 'operator', event_id: null, action: marker, detail: ''}]})},
    {view: 'incidents', selector: '#incidents', route: '/api/incidents', data: marker => ({items: [], incidentCatalogVersion: marker})},
  ]) {
    await t.test(`${panel.selector} retains loaded content and ignores reverse-order responses`, async () => {
      click(`nav [data-view="${panel.view}"]`);
      await until(() => !$('#content').hasAttribute('aria-busy') && $(panel.selector)
        && !$(panel.selector).textContent.includes('불러오는 중'));
      const box = $(panel.selector);
      const original = box.firstElementChild;
      const pending = network.hold(panel.route);
      click('#refresh');
      await until(() => pending.length === 1);
      assert.equal($(panel.selector), box);
      assert.equal(box.firstElementChild, original, 'a background request must preserve visible content');
      change('#severity', $('#severity').value === 'High' ? 'Low' : 'High');
      await until(() => pending.length === 2);
      pending[1].resolve(panel.data('latest-panel-response'));
      await until(() => box.textContent.includes('latest-panel-response'));
      assert.equal(loading(), true, 'superseded panel requests still contribute to total network activity');
      pending[0].resolve(panel.data('stale-panel-response'));
      await tick(); await tick();
      assert.equal(box.textContent.includes('stale-panel-response'), false);
      assert.ok(box.textContent.includes('latest-panel-response'));
      network.release(panel.route);
      await activityIdle();
    });
  }
  assert.deepEqual(errors, [], 'no runtime errors should be emitted by the application');
});
