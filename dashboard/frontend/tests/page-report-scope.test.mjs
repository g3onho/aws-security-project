import test from 'node:test';
import assert from 'node:assert/strict';
import {until} from './dom-test-support.mjs';
import {ok} from './honeypot-fixtures.mjs';
import {boot, REPORT} from './page-exports-support.mjs';

test('hidden filters are not sent: vulnerabilities and drills use their own scope', async t => {
  const {$, click, bodies} = await boot(t);
  click('nav [data-view="vulnerabilities"]');
  await until(() => $('#vulns'), 'vulnerabilities screen');
  click('#page-ai-report');
  await until(() => bodies.length === 1);
  assert.deepEqual(bodies[0], {view: 'vulnerabilities', region: '', search: ''});
  click('[data-report="close"]');
  click('nav [data-view="drills"]');
  await until(() => $('#drills'), 'drills screen');
  click('#page-ai-report');
  await until(() => bodies.length === 2);
  assert.deepEqual(bodies[1], {view: 'drills'});
});
