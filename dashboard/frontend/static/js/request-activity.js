/** Keep one persistent activity indicator visible while requests overlap. */
export function createRequestActivity(element, {
  minimumDuration = 350,
  now = () => performance.now(),
  setTimer = (callback, delay) => setTimeout(callback, delay),
  clearTimer = timer => clearTimeout(timer),
} = {}) {
  if (!Number.isFinite(minimumDuration) || minimumDuration < 0) {
    throw new TypeError('The activity minimum duration must be non-negative');
  }
  if ([now, setTimer, clearTimer].some(callback => typeof callback !== 'function')) {
    throw new TypeError('Activity clock and timer callbacks must be functions');
  }

  let active = 0;
  let shownAt = null;
  let hideTimer = null;
  let hideGeneration = 0;
  let destroyed = false;

  function hide() {
    element.classList.remove('is-loading');
    element.setAttribute('aria-hidden', 'true');
    shownAt = null;
  }

  function cancelHide() {
    hideGeneration++;
    if (hideTimer !== null) clearTimer(hideTimer);
    hideTimer = null;
  }

  function settle() {
    if (destroyed || active > 0) return;
    const remaining = minimumDuration - (now() - shownAt);
    if (remaining <= 0) {
      hide();
      return;
    }
    const generation = ++hideGeneration;
    hideTimer = setTimer(() => {
      if (destroyed || generation !== hideGeneration || active > 0) return;
      hideTimer = null;
      // Recheck the clock in case a timer fires before its requested deadline.
      settle();
    }, remaining);
  }

  function begin() {
    if (destroyed) return () => {};
    cancelHide();
    active++;
    if (shownAt === null) shownAt = now();
    element.classList.add('is-loading');
    element.setAttribute('aria-hidden', 'false');
    let finished = false;
    return () => {
      if (finished || destroyed) return;
      finished = true;
      active--;
      settle();
    };
  }

  async function run(work) {
    const finish = begin();
    try {
      return await work();
    } finally {
      finish();
    }
  }

  function destroy() {
    if (destroyed) return;
    destroyed = true;
    cancelHide();
    active = 0;
    hide();
  }

  hide();
  return {begin, run, destroy};
}
