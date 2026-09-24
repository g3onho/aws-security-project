import test from 'node:test';
import assert from 'node:assert/strict';
import {createJobWatcher} from '../static/js/ui/components/jobs.js';

const result = status => ({execution: {status}});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

function fixture(overrides = {}) {
  const timers = new Map(), loaded = [], settled = [], errors = [];
  let nextId = 0;
  const watcher = createJobWatcher({
    loadJob: async (...args) => { loaded.push(args); return result('SUCCEEDED'); },
    onSettled: async (...args) => { settled.push(args); },
    onError: async (...args) => { errors.push(args); },
    setTimer(callback, delay) { const id = ++nextId; timers.set(id, {callback, delay}); return id; },
    clearTimer: id => timers.delete(id),
    ...overrides,
  });
  return {
    watcher, timers, loaded, settled, errors,
    fire() {
      const entry = timers.entries().next().value;
      assert.ok(entry, 'a polling timer should be scheduled');
      const [id, timer] = entry;
      timers.delete(id);
      return timer.callback();
    },
  };
}

test('RUNNING schedules another poll; a terminal result awaits onSettled once', async () => {
  const callback = deferred();
  let calls = 0, callbackDone = false;
  const f = fixture({
    loadJob: async () => result(++calls === 1 ? 'RUNNING' : 'SUCCEEDED'),
    onSettled: async (eventId, response) => {
      assert.equal(eventId, 'event-a');
      assert.equal(response.execution.status, 'SUCCEEDED');
      await callback.promise; callbackDone = true;
    },
  });
  f.watcher.watch('event-a', 'job-a');
  assert.equal(f.timers.size, 1);
  assert.equal([...f.timers.values()][0].delay, 800);
  assert.equal(calls, 0);
  await f.fire();
  assert.equal(calls, 1); assert.equal(f.timers.size, 1);
  const completed = f.fire();
  await Promise.resolve();
  assert.equal(calls, 2); assert.equal(f.timers.size, 0);
  assert.equal(callbackDone, false);
  callback.resolve(); await completed;
  assert.equal(callbackDone, true); assert.equal(f.timers.size, 0);
});

test('duplicate watch of the same event and job keeps a single existing timer', async () => {
  const f = fixture();
  f.watcher.watch('event-a', 'job-a');
  const originalTimer = [...f.timers.keys()][0];
  f.watcher.watch('event-a', 'job-a');
  assert.deepEqual([...f.timers.keys()], [originalTimer]);
  await f.fire();
  assert.deepEqual(f.loaded, [['event-a', 'job-a']]);
  assert.equal(f.settled.length, 1);
});

test('a replacement job cancels the previous scheduled poll for that event', async () => {
  const f = fixture();
  f.watcher.watch('event-a', 'old-job');
  f.watcher.watch('event-a', 'new-job');
  assert.equal(f.timers.size, 1);
  await f.fire();
  assert.deepEqual(f.loaded, [['event-a', 'new-job']]);
  assert.equal(f.settled.length, 1);
});

test('late success from a replaced in-flight job cannot settle or remove its replacement', async () => {
  const old = deferred();
  const f = fixture({loadJob: async (eventId, jobId) => jobId === 'old-job' ? old.promise : result('SUCCEEDED')});
  f.watcher.watch('event-a', 'old-job');
  const pending = f.fire();
  f.watcher.watch('event-a', 'new-job');
  old.resolve(result('SUCCEEDED')); await pending;
  assert.equal(f.settled.length, 0); assert.equal(f.timers.size, 1);
  await f.fire();
  assert.equal(f.settled.length, 1); assert.equal(f.timers.size, 0);
});

test('late rejection from a replaced job is ignored', async () => {
  const old = deferred();
  const f = fixture({loadJob: async (eventId, jobId) => jobId === 'old-job' ? old.promise : result('SUCCEEDED')});
  f.watcher.watch('event-a', 'old-job');
  const pending = f.fire();
  f.watcher.watch('event-a', 'new-job');
  old.reject(new Error('obsolete request')); await pending;
  assert.equal(f.errors.length, 0); assert.equal(f.timers.size, 1);
  await f.fire(); assert.equal(f.settled.length, 1);
});

test('independent events keep polling when another job request fails', async () => {
  const failure = new Error('network unavailable');
  const f = fixture({loadJob: async eventId => {
    if (eventId === 'event-a') throw failure;
    return result('FAILED');
  }});
  f.watcher.watch('event-a', 'job-a'); f.watcher.watch('event-b', 'job-b');
  await f.fire();
  assert.deepEqual(f.errors, [['event-a', failure]]);
  assert.equal(f.timers.size, 1);
  await f.fire();
  assert.equal(f.settled[0][0], 'event-b');
  assert.equal(f.settled[0][1].execution.status, 'FAILED');
  assert.equal(f.errors.length, 1); assert.equal(f.timers.size, 0);
});

test('hidden windows defer network work and resume on the next visible tick', async () => {
  let visible = false;
  const f = fixture({isVisible: () => visible, delay: 250});
  f.watcher.watch('event-a', 'job-a');
  await f.fire(); await f.fire();
  assert.equal(f.loaded.length, 0); assert.equal(f.timers.size, 1);
  assert.equal([...f.timers.values()][0].delay, 250);
  visible = true; await f.fire();
  assert.deepEqual(f.loaded, [['event-a', 'job-a']]);
  assert.equal(f.settled.length, 1); assert.equal(f.timers.size, 0);
});

test('stop cancels all queued timers and permits a fresh later watch', async () => {
  const f = fixture();
  f.watcher.watch('event-a', 'job-a'); f.watcher.watch('event-b', 'job-b');
  f.watcher.stop(); f.watcher.stop();
  assert.equal(f.timers.size, 0); assert.equal(f.loaded.length, 0);
  f.watcher.watch('event-a', 'new-job'); await f.fire();
  assert.deepEqual(f.loaded, [['event-a', 'new-job']]);
});

for (const rejected of [false, true]) {
  test(`stop invalidates an in-flight ${rejected ? 'rejection' : 'result'}`, async () => {
    const pending = deferred();
    const f = fixture({loadJob: () => pending.promise});
    f.watcher.watch('event-a', 'job-a');
    const poll = f.fire();
    f.watcher.stop();
    rejected ? pending.reject(new Error('late error')) : pending.resolve(result('RUNNING'));
    await poll;
    assert.equal(f.settled.length, 0); assert.equal(f.errors.length, 0); assert.equal(f.timers.size, 0);
  });
}

test('settlement can watch a new job for the same event without old cleanup removing it', async () => {
  let watcher, calls = 0;
  const f = fixture({onSettled: async eventId => {
    if (++calls === 1) watcher.watch(eventId, 'job-b');
  }});
  watcher = f.watcher;
  watcher.watch('event-a', 'job-a'); await f.fire();
  assert.equal(f.timers.size, 1);
  await f.fire();
  assert.deepEqual(f.loaded, [['event-a', 'job-a'], ['event-a', 'job-b']]);
  assert.equal(calls, 2); assert.equal(f.timers.size, 0);
});

test('malformed job responses report one error and stop instead of polling indefinitely', async () => {
  const f = fixture({loadJob: async () => ({execution: {status: 'UNKNOWN'}})});
  f.watcher.watch('event-a', 'job-a'); await f.fire();
  assert.equal(f.settled.length, 0); assert.equal(f.errors.length, 1);
  assert.match(f.errors[0][1].message, /Unexpected job status/);
  assert.equal(f.timers.size, 0);
});

test('callback failures end the job without leaving unhandled timer rejections', async () => {
  const failure = new Error('render failed');
  const received = [];
  const f = fixture({
    onSettled: async () => { throw failure; },
    onError: async (eventId, error) => { received.push([eventId, error]); throw new Error('report failed'); },
  });
  f.watcher.watch('event-a', 'job-a'); await assert.doesNotReject(f.fire());
  assert.deepEqual(received, [['event-a', failure]]);
  assert.equal(f.timers.size, 0);
});
