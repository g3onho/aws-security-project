import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';

// v39.3: [전부 실행]이 끝나면 실행 진행 화면 안의 버튼 하나로, 서버가 그 실행의 결과를 직접 읽어 AI 요약 보고서를 만든다.
// 사람이 파일을 내려받아 다시 올릴 필요가 없다 — 요청 본문은 view 와 runId 뿐이다.
const iso = new Date().toISOString();
const env = data => ({data, meta: {schemaVersion: '1', asOf: iso, requestId: 'fixture', partial: false, warnings: []}});
const REPORT = {view: 'drill-run', title: '보안 시나리오 실행 결과 AI 요약 보고서', generatedAt: iso, model: 'fake-haiku', cached: false,
  period: {from: iso, to: iso, hours: 0, endOffset: 0}, filters: {}, facts: {'항목 수': 2, '필수 항목 값': {'실패 항목': []}},
  unavailable: [], warnings: [], usage: {inputTokens: 40, outputTokens: 12}, markdown: '## 1. 요약\n실행 결과 **2건**'};

test('run progress screen offers an AI report button that is enabled only after every item ends', async t => {
  const network = makeFetchMock();
  network.respond('/api/drills/catalog', () => env({types: [], scenarios: [], supportLegend: {},
    environment: {dataSourceConnected: true, providerState: 'connected', region: 'eu-west-3', isolationVerified: 'unknown', executionMode: 'live', webScanReady: true}}));
  network.respond('/api/drills', () => env({items: [], nextCursor: null}));
  network.respond('/api/drills/run-all/start', () => env({runId: 'run-1', launched: [{sec: 'SEC-02'}, {sec: 'SEC-08'}], skipped: []}));
  network.respond('/api/drills/run-all/run-1/status', () => env({runId: 'run-1', skipped: [], items: [
    {sec: 'SEC-02', label: 'SEC-02', status: 'Success'}, {sec: 'SEC-08', label: 'SEC-08 · 도쿄', status: 'Success'}]}));
  const bodies = [];
  network.respond('/api/assistant/report', call => { bodies.push(JSON.parse(call.options.body)); return env(REPORT); });

  const {dom, $, click, errors} = appDOM(network); t.after(() => dom.window.close());
  await import(pathToFileURL(path.join(ROOT, 'static/js/app.js')).href);
  await until(() => $('#content .event-trend-widget'), 'overview did not render');
  click('nav [data-view="drills"]');
  await until(() => $('#drills [data-run-all-start]'), 'run-all button did not render');
  assert.equal($('#drills [data-run-report]'), null, '실행 전에는 버튼이 없다');

  click('#drills [data-run-all-start]');
  await until(() => $('#drills').textContent.includes('실행 ID: run-1'), 'progress did not render');
  const early = [...$('#drills').querySelectorAll('button')].find(b => b.textContent.includes('이번 실행 AI 요약 보고서'));
  assert(early, '진행 화면 안에 버튼이 있다');
  assert(early.hasAttribute('disabled'), '끝나기 전(첫 상태 확인 전)에는 잠겨 있다');

  // 첫 상태 확인은 약 3초 뒤에 온다. 공용 until 은 3초 상한이라 여기서만 넉넉히 기다린다.
  for (let i = 0; i < 100 && !$('#drills [data-run-report]'); i++) await new Promise(r => setTimeout(r, 100));
  assert($('#drills [data-run-report]'), 'button was not enabled after all items ended');
  click('#drills [data-run-report]');
  await until(() => bodies.length === 1, 'report was not requested');
  assert.deepEqual(bodies[0], {view: 'drill-run', runId: 'run-1'}, '본문은 view 와 runId 뿐(결과 JSON 을 브라우저가 싣지 않는다)');
  await until(() => $('#report-dialog .report-md'), 'report did not render');
  assert(($('#report-dialog').textContent).includes('보안 시나리오 실행 결과'));
  assert.deepEqual(errors, []);
});
