import test from 'node:test';
import assert from 'node:assert/strict';
import {until} from './dom-test-support.mjs';
import {ok} from './honeypot-fixtures.mjs';
import {boot, REPORT} from './page-exports-support.mjs';

test('buttons show only on the five screens and never call the AI on their own', async t => {
  const {$, click, network, bodies, errors} = await boot(t);
  assert.equal($('#page-exports').hidden, true, 'hidden on the overview');
  assert.equal(network.count('/api/assistant/status'), 0, 'no automatic status call');
  const seen = {};
  for (const view of ['events', 'vulnerabilities', 'infrastructure', 'responses', 'drills', 'honeypot', 'overview']) {
    click(`nav [data-view="${view}"]`);
    seen[view] = !$('#page-exports').hidden;
  }
  assert.deepEqual(seen, {events: true, vulnerabilities: true, infrastructure: true, responses: false, drills: true, honeypot: true, overview: false});
  await until(() => !$('#refresh').disabled, 'last view did not finish loading');
  assert.equal(bodies.length, 0, 'the model is only called when the button is pressed');
  assert.deepEqual(errors, []);
});
