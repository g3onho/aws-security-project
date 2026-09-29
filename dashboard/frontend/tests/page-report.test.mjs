import test from 'node:test';
import assert from 'node:assert/strict';
import {until} from './dom-test-support.mjs';
import {ok} from './honeypot-fixtures.mjs';
import {boot, REPORT} from './page-exports-support.mjs';

test('AI report sends only the filters the screen uses, escapes model text, and saves Markdown', async t => {
  const {$, $$, w, click, bodies, blobs, downloads, errors} = await boot(t);
  click('nav [data-view="events"]');
  await until(() => $('#export'), 'events screen');
  click('#page-ai-report');
  await until(() => $('#report-dialog .report-md'), 'report did not render');
  assert.deepEqual(bodies[0], {view: 'events', hours: 24, endOffset: 0, region: '', resource: '', severity: '', status: '', source: '', search: ''});
  assert.equal($('#report-dialog').open, true);
  const dialog = $('#report-dialog');
  assert.deepEqual([...dialog.querySelectorAll('.report-md h3')].map(h => h.textContent), ['1. 요약', '2. 주요 수치']);
  assert.equal(dialog.querySelector('.report-md strong').textContent, '1건');
  assert.equal(dialog.querySelectorAll('.report-md td').length, 2);
  // 모델 본문은 텍스트로만: 태그·링크가 만들어지지 않는다.
  assert.equal(dialog.querySelector('.report-md img, .report-md a, .report-md script'), null);
  assert(dialog.querySelector('.report-md').textContent.includes('<img src=x'));
  assert(dialog.querySelector('.report-md').textContent.includes('[링크](http://evil.example)'));
  assert.equal(w.__pwn, undefined);
  assert(dialog.querySelector('.report-warn').textContent.includes('999'));
  assert(dialog.textContent.includes('읽지 못한 원천: CloudWatch 경보'));
  click('[data-report="save"]');
  assert.equal(blobs.length, 1);
  assert.match(downloads.at(-1), /^events-ai-report-\d{8}-\d{4}\.md$/);
  const text = await blobs[0].text();
  assert(text.startsWith('# 보안 이벤트 AI 요약 보고서') && text.includes('## 경고') && text.includes('| 필수 · CRITICAL | 1 |'));
  assert.deepEqual(errors, []);
});
