import test from 'node:test';
import assert from 'node:assert/strict';
import {until, tick} from './dom-test-support.mjs';
import {ok} from './honeypot-fixtures.mjs';
import {boot, REPORT} from './page-exports-support.mjs';

test('a failed report shows the server reason; only a 503 (AI off) locks the AI button', async t => {
  const {$, click} = await boot(t);
  const original = globalThis.fetch;
  let mode = 429;
  globalThis.fetch = (url, options) => String(url).startsWith('/api/assistant/report')
    ? Promise.resolve({ok: false, status: mode, json: async () => ({title: mode === 429 ? '보고서 요청이 너무 잦습니다.' : 'AI 기능이 꺼져 있습니다.'})})
    : original(url, options);
  t.after(() => { globalThis.fetch = original; });
  click('nav [data-view="honeypot"]');
  await until(() => $('#honeypot .hp-pad'), 'honeypot screen');
  click('#page-ai-report');
  await until(() => $('#report-dialog .panel-error'), 'error was not shown');
  assert.equal($('#report-dialog .panel-error').textContent, '보고서 요청이 너무 잦습니다.');
  assert.equal($('#page-ai-report').disabled, false, 'a rate limit does not lock the button');
  assert.equal($('[data-report="save"]').disabled, true, 'nothing to save after a failure');
  click('[data-report="close"]');
  await tick();   // 닫힘 이벤트(대기열)가 지나간 뒤에 다시 연다
  mode = 503;
  click('#page-ai-report');
  await until(() => $('#report-dialog .panel-error')?.textContent === 'AI 기능이 꺼져 있습니다.', '503 message');
  assert.equal($('#page-ai-report').disabled, true);
  assert.equal($('#page-ai-report').title, 'AI 기능이 꺼져 있습니다');
  assert.equal($('#page-log-save').disabled, false, 'log save is independent of the AI');
});
