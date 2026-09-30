import test from 'node:test';
import assert from 'node:assert/strict';
import {until} from './dom-test-support.mjs';
import {ok} from './honeypot-fixtures.mjs';
import {boot, REPORT} from './page-exports-support.mjs';

test('log save downloads a CSV per screen without calling the AI', async t => {
  const {$, click, network, downloads, blobs, bodies} = await boot(t);
  click('nav [data-view="honeypot"]');
  await until(() => $('#honeypot .hp-pad'), 'honeypot screen');
  click('#page-log-save');
  await until(() => downloads.some(name => /^honeypot-sessions-\d{8}-\d{4}\.csv$/.test(name)), 'honeypot csv');
  const csv = await blobs.at(-1).text();
  assert.deepEqual([...new Uint8Array(await blobs.at(-1).arrayBuffer()).slice(0, 3)], [0xEF, 0xBB, 0xBF], 'UTF-8 BOM for Excel');   // Blob.text() 는 BOM 을 떼어 낸다
  assert(csv.startsWith('"세션 ID"') && csv.includes('10.0.2.55') && !/pass/i.test(csv));
  network.respond('/api/drills/catalog', () => ok({types: [], scenarios: [{id: 'SEC-02', purpose: '서비스 포트·헤더', types: [], sources: ['원천'], response: '수동', support: 'prep-needed', supportLabel: '준비 필요', observation: 'connected'}],
    environment: {dataSourceConnected: true, providerState: 'connected', region: 'ap-northeast-2', isolationVerified: 'unknown', executionMode: 'live', webScanReady: false}, supportLegend: {}}));
  network.respond('/api/drills', () => ok({items: [{runId: 'r1', type: 'run-all', title: '전부 실행', secs: ['SEC-02'], state: '접수', createdAt: '2026-09-29T00:00:00Z', actor: 'op'}], nextCursor: null}));
  click('nav [data-view="drills"]');
  await until(() => $('#drills .drill-workspace'), 'drills screen');
  click('#page-log-save');
  await until(() => downloads.some(name => /^drills-\d{8}-\d{4}\.csv$/.test(name)), 'drills csv');
  assert((await blobs.at(-1).text()).includes('"r1","run-all","전부 실행","SEC-02"'));
  assert.equal(bodies.length, 0, 'log save never calls the AI');
});
