/** Poll local job results without tying their lifetime to the event dialog. */
export function createJobWatcher({
  loadJob,
  onSettled,
  onError = () => {},
  delay = 800,
  isVisible = () => true,
  setTimer = (callback, milliseconds) => setTimeout(callback, milliseconds),
  clearTimer = timer => clearTimeout(timer),
}) {
  if ([loadJob, onSettled, onError, isVisible, setTimer, clearTimer].some(value => typeof value !== 'function')) {
    throw new TypeError('Job watcher callbacks must be functions');
  }
  if (!Number.isFinite(delay) || delay < 0) throw new TypeError('Job polling delay must be non-negative');

  const jobs = new Map();
  const tokens = new Map();
  let generation = 0;
  const live = job => job.generation === generation && tokens.get(job.eventId) === job.token;
  const current = job => live(job) && jobs.get(job.eventId) === job;

  function remove(job) {
    if (job.timer !== null) clearTimer(job.timer);
    job.timer = null;
    if (jobs.get(job.eventId) === job) jobs.delete(job.eventId);
  }

  function schedule(job) {
    if (!current(job)) return;
    job.timer = setTimer(() => poll(job), delay);
  }

  async function poll(job) {
    job.timer = null;
    if (!current(job)) return;
    try {
      if (!isVisible()) {
        schedule(job);
        return;
      }
      const result = await loadJob(job.eventId, job.executionId);
      if (!current(job)) return;
      const status = result?.execution?.status;
      if (status === 'RUNNING') {
        schedule(job);
        return;
      }
      if (status !== 'SUCCEEDED' && status !== 'FAILED') {
        throw new Error(`Unexpected job status: ${String(status)}`);
      }
      // A terminal result no longer occupies the event's slot while its UI callback runs.
      remove(job);
      await onSettled(job.eventId, result);
    } catch (error) {
      if (!live(job)) return;
      remove(job);
      try {
        await onError(job.eventId, error);
      } catch {
        // A reporting callback must not create an unhandled timer rejection or restart polling.
      }
    } finally {
      if (live(job) && !jobs.has(job.eventId)) tokens.delete(job.eventId);
    }
  }

  function watch(eventId, executionId) {
    if (typeof eventId !== 'string' || !eventId || typeof executionId !== 'string' || !executionId) {
      throw new TypeError('An event ID and execution ID are required');
    }
    const previous = jobs.get(eventId);
    if (previous?.executionId === executionId) return;
    if (previous) remove(previous);
    const job = {eventId, executionId, token: Symbol(), generation, timer: null};
    tokens.set(eventId, job.token);
    jobs.set(eventId, job);
    schedule(job);
  }

  function stop() {
    generation++;
    for (const job of jobs.values()) remove(job);
    jobs.clear();
    tokens.clear();
  }

  return {watch, stop};
}
