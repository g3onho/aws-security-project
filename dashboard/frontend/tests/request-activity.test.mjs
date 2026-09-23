import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequestActivity} from '../static/js/request-activity.js';

function fixture(options = {}) {
  let time = 0, nextId = 0;
  const timers = new Map();
  const classes = new Set(['is-loading']);
  const attributes = new Map();
  const element = {
    hidden: false,
    style: {visibility: '', display: ''},
    classList: {
      add: value => classes.add(value),
      remove: value => classes.delete(value),
      contains: value => classes.has(value),
    },
    setAttribute: (key, value) => attributes.set(key, value),
    getAttribute: key => attributes.get(key),
  };
  const activity = createRequestActivity(element, {
    now: () => time,
    setTimer(callback, delay) {
      const id = nextId++;
      timers.set(id, {callback, due: time + delay});
      return id;
    },
    clearTimer: id => timers.delete(id),
    ...options,
  });
  return {
    activity, element, timers,
    loading: () => classes.has('is-loading'),
    advance(milliseconds) {
      const target = time + milliseconds;
      for (;;) {
        const next = [...timers.entries()].sort((a, b) => a[1].due - b[1].due)[0];
        if (!next || next[1].due > target) break;
        const [id, timer] = next;
        time = timer.due;
        timers.delete(id);
        timer.callback();
      }
      time = target;
    },
  };
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

test('starts immediately, keeps its layout slot, and holds fast work for 350ms', () => {
  const f = fixture();
  assert.equal(f.loading(), false);
  assert.equal(f.element.getAttribute('aria-hidden'), 'true');
  const finish = f.activity.begin();
  assert.equal(f.loading(), true);
  assert.equal(f.element.getAttribute('aria-hidden'), 'false');
  f.advance(10);
  finish();
  f.advance(339);
  assert.equal(f.loading(), true);
  f.advance(1);
  assert.equal(f.loading(), false);
  assert.equal(f.element.getAttribute('aria-hidden'), 'true');
  assert.equal(f.element.hidden, false);
  assert.deepEqual(f.element.style, {visibility: '', display: ''});
});

test('a long request stays visible without a timer and hides when finished', () => {
  const f = fixture();
  const finish = f.activity.begin();
  f.advance(5000);
  assert.equal(f.loading(), true);
  assert.equal(f.timers.size, 0);
  finish();
  assert.equal(f.loading(), false);
  assert.equal(f.timers.size, 0);
});

test('overlapping requests finish independently and duplicate finishes are harmless', () => {
  const f = fixture();
  const first = f.activity.begin();
  f.advance(100);
  const second = f.activity.begin();
  f.advance(300);
  second();
  second();
  assert.equal(f.loading(), true);
  assert.equal(f.timers.size, 0);
  first();
  assert.equal(f.loading(), false);
});

test('a new request cancels pending hiding and keeps the original visible deadline', () => {
  const f = fixture();
  f.activity.begin()();
  const cancelledTimer = [...f.timers.values()][0];
  f.advance(200);
  const finish = f.activity.begin();
  assert.equal(f.timers.size, 0, 'timer ID zero must also be cancelled');
  cancelledTimer.callback();
  assert.equal(f.loading(), true, 'a cancelled callback cannot hide active work');
  f.advance(100);
  finish();
  f.advance(49);
  assert.equal(f.loading(), true);
  f.advance(1);
  assert.equal(f.loading(), false, 'continuous visibility is measured from the first request');
});

test('stale timers and old finish functions cannot shorten a later visible interval', () => {
  const f = fixture();
  const oldFinish = f.activity.begin();
  oldFinish();
  const stale = [...f.timers.values()][0].callback;
  f.advance(350);
  f.advance(50);
  const newFinish = f.activity.begin();
  oldFinish();
  newFinish();
  stale();
  f.advance(349);
  assert.equal(f.loading(), true);
  assert.equal(f.timers.size, 1);
  f.advance(1);
  assert.equal(f.loading(), false);
});

test('an early timer callback schedules only the remaining minimum duration', () => {
  const f = fixture();
  f.activity.begin()();
  const [id, timer] = [...f.timers.entries()][0];
  f.advance(100);
  f.timers.delete(id);
  timer.callback();
  assert.equal(f.loading(), true);
  assert.equal(f.timers.size, 1);
  assert.equal([...f.timers.values()][0].due, 350);
  f.advance(250);
  assert.equal(f.loading(), false);
});

test('run returns values and always releases activity after synchronous throws or rejection', async () => {
  const f = fixture();
  assert.equal(await f.activity.run(() => 42), 42);
  const syncError = new Error('synchronous failure');
  await assert.rejects(f.activity.run(() => { throw syncError; }), error => error === syncError);
  const asyncError = new Error('asynchronous failure');
  await assert.rejects(f.activity.run(() => Promise.reject(asyncError)), error => error === asyncError);
  f.advance(350);
  assert.equal(f.loading(), false);
  assert.equal(f.timers.size, 0);
});

test('a rejected run cannot hide another pending run', async () => {
  const f = fixture();
  const first = deferred(), second = deferred();
  const firstRun = f.activity.run(() => first.promise);
  const secondRun = f.activity.run(() => second.promise);
  assert.equal(f.loading(), true);
  f.advance(500);
  first.reject(new Error('first failed'));
  await assert.rejects(firstRun, /first failed/);
  assert.equal(f.loading(), true);
  second.resolve('second completed');
  assert.equal(await secondRun, 'second completed');
  assert.equal(f.loading(), false);
});

test('destroy clears pending timers and ignores stale callbacks and new tracking', async () => {
  const f = fixture();
  f.activity.begin()();
  const stale = [...f.timers.values()][0].callback;
  f.activity.destroy();
  f.activity.destroy();
  assert.equal(f.timers.size, 0);
  assert.equal(f.loading(), false);
  assert.equal(f.element.getAttribute('aria-hidden'), 'true');
  stale();
  f.activity.begin()();
  assert.equal(await f.activity.run(() => 'still runs'), 'still runs');
  f.advance(1000);
  assert.equal(f.loading(), false);
  assert.equal(f.timers.size, 0);
});

test('destroy does not cancel work and late completion cannot restore activity', async () => {
  const f = fixture();
  const work = deferred();
  const finish = f.activity.begin();
  const result = f.activity.run(() => work.promise);
  f.activity.destroy();
  finish();
  finish();
  work.resolve('completed');
  assert.equal(await result, 'completed');
  assert.equal(f.loading(), false);
  assert.equal(f.timers.size, 0);
});

test('the minimum duration is configurable, including zero', () => {
  const f = fixture({minimumDuration: 100});
  f.activity.begin()();
  f.advance(99);
  assert.equal(f.loading(), true);
  f.advance(1);
  assert.equal(f.loading(), false);
  const immediate = fixture({minimumDuration: 0});
  immediate.activity.begin()();
  assert.equal(immediate.loading(), false);
  assert.equal(immediate.timers.size, 0);
});

test('invalid timer settings fail at construction', () => {
  for (const minimumDuration of [-1, NaN, Infinity, '350']) {
    assert.throws(() => fixture({minimumDuration}), TypeError);
  }
  for (const option of ['now', 'setTimer', 'clearTimer']) {
    assert.throws(() => fixture({[option]: null}), TypeError);
  }
});
