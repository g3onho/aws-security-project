import assert from 'node:assert/strict';
import test from 'node:test';

const storeUrl = new URL('../../frontend/static/js/store.js', import.meta.url);
let instance = 0;
const freshStore = () => import(`${storeUrl.href}?test=${instance++}`);
const json = value => new Response(JSON.stringify(value), {
  status: 200, headers: {'Content-Type': 'application/json'},
});
const event = (overrides = {}) => ({
  id: 'EVT-0003', title: 'Contract test event', resource: 'sg-fixture',
  scenario: 'SEC-03', region: 'ap-northeast-2', source: 'Config',
  actionState: 'PENDING_APPROVAL', severity: 'HIGH', status: 'PENDING_APPROVAL',
  mode: 'MANUAL', execution: 'NOT_RUN', verification: 'NOT_RUN',
  at: 1000, version: 7, planHash: 'server-plan-hash', actionable: true,
  allowedActions: ['approve'], history: [], before: {value: 1}, ...overrides,
});
function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}
function fixture(t, override = () => undefined) {
  const calls = [], redirects = [];
  const oldLocation = Object.getOwnPropertyDescriptor(globalThis, 'location');
  Object.defineProperty(globalThis, 'location', {
    configurable: true, value: {assign: path => redirects.push(path)},
  });
  t.after(() => {
    if (oldLocation) Object.defineProperty(globalThis, 'location', oldLocation);
    else delete globalThis.location;
  });
  t.mock.method(globalThis, 'fetch', async (url, options = {}) => {
    calls.push({url, options});
    const overridden = override(url, options);
    if (overridden !== undefined) return overridden;
    const path = url.split('?')[0];
    if (path === '/api/auth/session') return json({user: {name: 'operator', role: 'operator'}, csrfToken: 'session-csrf'});
    if (path === '/api/auth/logout') return json({ok: true});
    if (path === '/api/legacy/config') return json({mode: 'live', writeEnabled: true, role: 'operator', asOf: 100000});
    if (path === '/api/legacy/snapshot') return json({items: [event()], regionalItems: [event()], summary: {total: 1}, snapshot: 'revision', asOf: 100000, collectedAt: 100001});
    if (path === '/api/legacy/metrics') return json({resource: null});
    if (path === '/api/legacy/health') return json({checks: {worker: 'ok'}});
    if (path === '/api/legacy/events/EVT-0003') return json(event());
    if (path === '/api/legacy/events/EVT-0003/approve') return json(event({status: 'APPROVED', actionState: 'APPROVED', version: 8, allowedActions: ['execute', 'cancel']}));
    if (path === '/api/legacy/export/events.csv') return new Response('\ufeff"ID"\r\n"EVT-0003"', {headers: {'Content-Type': 'text/csv'}});
    if (path === '/api/legacy/vulnerabilities') return json({items: [], groups: [], summary: {bySeverity: {}}});
    if (['/api/legacy/services', '/api/legacy/audit', '/api/legacy/nacls', '/api/legacy/scenarios', '/api/legacy/incidents'].includes(path)) return json({items: []});
    throw new Error(`Unexpected request: ${url}`);
  });
  return {calls, redirects};
}

test('all legacy reads are rewritten while auth and already-prefixed paths are preserved', async t => {
  const {calls} = fixture(t);
  const store = await freshStore();
  store.state.view = 'infrastructure';
  await store.api.load();
  await store.api.scenarios();
  await store.api.incidents();
  await store.api.vulnerabilities();
  await store.api.nacls();
  await store.api.audit();
  await store.request('/api/legacy/audit');
  await store.request('/health?probe=1');
  assert.equal(calls[0].url, '/api/auth/session');
  assert(calls.every(call => call.url.startsWith('/api/legacy/') || call.url.startsWith('/api/auth/')));
  assert(calls.some(call => call.url === '/api/legacy/health?probe=1'));
  assert(calls.some(call => call.url.startsWith('/api/legacy/metrics?') && call.url.includes('scope=all')));
  assert(calls.filter(call => call.url === '/api/legacy/audit').length === 2);
  assert(calls.every(call => call.options.credentials === 'same-origin'));
  assert.equal(store.selectEvents()[0].rawActionState, 'PENDING_APPROVAL');
});

test('CSV export uses the legacy route and releases its download URL', async t => {
  const {calls} = fixture(t);
  const store = await freshStore();
  const anchor = {click: t.mock.fn()};
  const original = Object.getOwnPropertyDescriptor(globalThis, 'document');
  Object.defineProperty(globalThis, 'document', {configurable: true, value: {createElement: () => anchor}});
  t.after(() => original ? Object.defineProperty(globalThis, 'document', original) : delete globalThis.document);
  t.mock.method(URL, 'createObjectURL', () => 'blob:test-download');
  const revoke = t.mock.method(URL, 'revokeObjectURL', () => undefined);
  t.mock.method(globalThis, 'setTimeout', fn => { fn(); return 0; });
  await store.api.init();
  await store.api.export();
  assert(calls.at(-1).url.startsWith('/api/legacy/export/events.csv?'));
  assert.equal(anchor.href, 'blob:test-download');
  assert.equal(anchor.click.mock.callCount(), 1);
  assert.deepEqual(revoke.mock.calls[0].arguments, ['blob:test-download']);
});

for (const [label, patch] of [
  ['unknown severity', {severity: 'ALIEN'}],
  ['unknown event status', {status: 'MAYBE_DONE'}],
  ['unknown execution status', {execution: 'MAYBE_SUCCEEDED'}],
  ['unknown verification status', {verification: 'MAYBE_PASSED'}],
  ['missing allowedActions', {allowedActions: undefined}],
  ['non-array allowedActions', {allowedActions: 'approve'}],
  ['unknown allowed action', {allowedActions: ['unsafe-plan']}],
]) {
  test(`malformed DTO (${label}) raises a contract error and does not become an empty list`, async t => {
    let invalid = false;
    fixture(t, url => invalid && url.startsWith('/api/legacy/snapshot?')
      ? json({items: [event(patch)], regionalItems: [event()], summary: {total: 1}}) : undefined);
    const store = await freshStore();
    await store.api.load();
    const previous = store.selectEvents();
    invalid = true;
    await assert.rejects(store.api.load(), /형식/);
    assert.equal(store.selectEvents(), previous);
    assert.equal(store.selectEvents().length, 1);
    assert.equal(store.api.get('EVT-0003').version, 7);
  });
}

test('mutations submit the server version, original status/hash and current CSRF token', async t => {
  const {calls} = fixture(t);
  const store = await freshStore();
  await store.api.load();
  await store.api.change('EVT-0003', 'approve', {expected_version: 999, expected_status: 'RESOLVED', plan_hash: 'forged'});
  const {options} = calls.find(call => call.url.endsWith('/approve'));
  assert.deepEqual(JSON.parse(options.body), {expected_version: 7, expected_status: 'PENDING_APPROVAL', plan_hash: 'server-plan-hash'});
  assert.equal(options.headers.get('X-CSRF-Token'), 'session-csrf');
  assert.match(options.headers.get('Idempotency-Key'), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  assert.equal(store.api.get('EVT-0003').version, 8);
  assert.equal(store.api.get('EVT-0003').rawStatus, 'APPROVED');
});

test('server-disallowed and unsupported actions cannot make mutation requests', async t => {
  const {calls} = fixture(t, url => url === '/api/legacy/events/EVT-0003' ? json(event({allowedActions: []})) : undefined);
  const store = await freshStore();
  await store.api.init();
  await store.api.detail('EVT-0003');
  const count = calls.length;
  await assert.rejects(store.api.change('EVT-0003', 'approve'), /허용되지/);
  await assert.rejects(store.api.change('EVT-0003', 'plan'), /허용되지/);
  assert.equal(calls.length, count);
});

test('logout clears state and late detail/load responses cannot repopulate the cache', async t => {
  const lateDetail = deferred(), lateSnapshot = deferred();
  let delay = false, loadSignal;
  const {redirects} = fixture(t, (url, options) => {
    if (delay && url === '/api/legacy/events/late') return lateDetail.promise;
    if (delay && url.startsWith('/api/legacy/snapshot?')) { loadSignal = options.signal; return lateSnapshot.promise; }
    return undefined;
  });
  const store = await freshStore();
  await store.api.load();
  store.state.search = 'private user filter';
  delay = true;
  const detail = store.api.detail('late');
  const load = store.api.load();
  await store.api.logout();
  assert.equal(loadSignal.aborted, true);
  lateDetail.resolve(json(event({id: 'late', version: 99})));
  lateSnapshot.resolve(json({items: [event()], regionalItems: [event()], summary: {total: 1}}));
  await assert.rejects(detail, error => error.name === 'AbortError');
  assert.equal(await load, false);
  assert.deepEqual(store.selectEvents(), []);
  assert.deepEqual(store.selectEvents({ignoreRegion: true}), []);
  assert.equal(store.api.get('EVT-0003'), undefined);
  assert.equal(store.api.get('late'), undefined);
  assert.equal(store.DATA_AS_OF, 0);
  assert.equal(store.state.search, '');
  assert.deepEqual(store.summary, {});
  assert.equal(store.config.role, 'viewer');
  assert.equal(redirects.at(-1), '/login');
});

test('an initialization response arriving after logout cannot restore the old user', async t => {
  const configResponse = deferred(), requested = deferred();
  fixture(t, url => {
    if (url === '/api/legacy/config') { requested.resolve(); return configResponse.promise; }
    return undefined;
  });
  const store = await freshStore();
  const init = store.api.init();
  await requested.promise;
  await store.api.logout();
  configResponse.resolve(json({mode: 'live', writeEnabled: true, role: 'operator', asOf: 100000}));
  await assert.rejects(init, error => error.name === 'AbortError');
  assert.equal(store.DATA_AS_OF, 0);
  assert.equal(store.config.role, 'viewer');
  assert.equal(store.config.user, undefined);
});
