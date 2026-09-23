/**
 * Focused DOM regressions: no live server, browser automation or external requests.
 * Run from the repository root in PowerShell (Node 23.11.1 + jsdom 27.0.1 verified):
 *   $env:JSDOM_PATH = Join-Path $env:TEMP 'codex-dashboard-dom-tests'
 *   npm.cmd --prefix $env:JSDOM_PATH install jsdom@27.0.1 --no-audit --no-fund
 *   node --test dashboard/frontend/tests/rendering.test.mjs dashboard/frontend/tests/refresh.test.mjs dashboard/frontend/tests/interaction.test.mjs dashboard/frontend/tests/map-ui.test.mjs dashboard/frontend/tests/jobs.test.mjs dashboard/frontend/tests/downloads.test.mjs dashboard/frontend/tests/layout-motion.test.mjs dashboard/frontend/tests/request-activity.test.mjs
 * JSDOM_PATH is an npm prefix; no node_modules or package files are needed in the repo.
 */
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(process.env.JSDOM_PATH
  ? path.resolve(process.env.JSDOM_PATH, 'package.json') : import.meta.url);
export const {JSDOM} = require('jsdom');

export const NOW = 1789711200000;
export const tick = () => new Promise(resolve => setImmediate(resolve));
export async function until(predicate, message = 'condition was not reached') {
  const deadline = Date.now() + 3000;
  while (!predicate()) {
    if (Date.now() > deadline) throw new Error(message);
    await new Promise(resolve => setTimeout(resolve, 5));
  }
}

export function snapshot(title = 'Contract test event') {
  const event = {
    id: 'EVT-0003', title, scenario: 'SEC-03', severity: 'HIGH', source: 'Config',
    region: 'ap-northeast-2', environment: 'production', resource: 'sg-fixture-db',
    at: NOW - 3600000, status: 'PENDING_APPROVAL', actionState: 'PENDING_APPROVAL', mode: 'MANUAL',
    execution: 'NOT_RUN', verification: 'NOT_RUN', actionable: true,
    before: {value: 1}, history: [], sourceIp: null, notification: null,
    planHash: 'fixture-plan', version: 1, allowedActions: ['approve', 'cancel', 'execute', 'verify'], afterValue: null,
  };
  return {
    items: [event], regionalItems: [event], snapshot: title, asOf: NOW, collectedAt: NOW,
    summary: {total: 1, resolved: 0, regions: {'ap-northeast-2': 1}},
  };
}

export function vulnerabilities(marker = 'initial') {
  const items = Array.from({length: 75}, (_, index) => ({
    target: 'ecr/fixture:1', severity: 'HIGH', cveId: `CVE-2026-${String(index + 1).padStart(5, '0')}`,
    cvss: 7.5, package: 'fixture-package', installedVersion: '1.0', fixedVersion: '1.1', family: 'linux',
  }));
  return {
    items, total: items.length, catalogVersion: marker,
    summary: {bySeverity: {CRITICAL: 0, HIGH: 75, MEDIUM: 0, LOW: 0}, uniqueCves: 75, fixable: 75, targets: 1},
    groups: [{target: 'ecr/fixture:1', kind: 'IMAGE', source: 'Trivy', bySeverity: {HIGH: 75},
      total: 75, fixable: 75, scannedAt: NOW, actionable: true, eventId: 'EVT-0003', eventStatus: 'PENDING_APPROVAL'}],
  };
}

export function makeFetchMock() {
  const calls = [];
  const holds = new Map();
  const defaults = {
    '/api/auth/session': () => ({user: {name: 'operator', role: 'operator'}, csrfToken: 'fixture-csrf'}),
    '/api/config': () => ({mode: 'live', role: 'operator', writeEnabled: true, asOf: NOW}),
    '/api/snapshot': () => snapshot(),
    '/api/metrics': () => ({resource: null}),
    '/health': () => ({mode: 'live', checks: {worker: 'ok'}, aws_connected: false}),
    '/static/data/countries.geojson': () => ({features: []}),
    '/api/scenarios': () => ({items: [], catalogVersion: 'initial'}),
    '/api/vulnerabilities': () => vulnerabilities(),
    '/api/audit': () => ({items: []}),
    '/api/incidents': () => ({items: [], incidentCatalogVersion: 'initial'}),
  };
  const response = data => ({ok: true, status: 200, json: async () => structuredClone(data)});
  return {
    calls,
    count: pathname => calls.filter(call => call.pathname === pathname).length,
    respond(pathname, factory) { defaults[pathname] = typeof factory === 'function' ? factory : () => factory; },
    hold(pathname) { const pending = []; holds.set(pathname, pending); return pending; },
    release(pathname) { holds.delete(pathname); },
    async fetch(url, options = {}) {
      const parsed = new URL(String(url), 'http://localhost/');
      parsed.pathname = parsed.pathname === '/api/legacy/health' ? '/health' : parsed.pathname.replace(/^\/api\/legacy\//, '/api/');
      const call = {pathname: parsed.pathname, url: parsed, options};
      calls.push(call);
      if (holds.has(parsed.pathname)) {
        // Deliberately ignore AbortSignal: correctness must not depend on transport cancellation.
        return new Promise((resolve, reject) => {
          holds.get(parsed.pathname).push({
            ...call, resolve: data => resolve(response(data)), reject,
          });
        });
      }
      if (!defaults[parsed.pathname]) throw new Error(`Unexpected fixture request: ${parsed.pathname}`);
      return response(defaults[parsed.pathname](call));
    },
  };
}

export function appDOM(fetchMock) {
  const html = fs.readFileSync(path.join(ROOT, 'templates/index.html'), 'utf8')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/g, '').replace(/<link[^>]*>/g, '');
  const dom = new JSDOM(html, {url: 'http://localhost/', pretendToBeVisual: true});
  const w = dom.window;
  // Imported browser modules use global timers. Dispose them with their window,
  // just as a real navigation does, instead of leaving Node timers after a test.
  const nativeTimers = Object.fromEntries(['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval']
    .map(key => [key, globalThis[key]]));
  const timeouts = new Set(), intervals = new Set();
  globalThis.setTimeout = (callback, delay, ...args) => {
    const timer = nativeTimers.setTimeout(() => { timeouts.delete(timer); callback(...args); }, delay);
    timeouts.add(timer); return timer;
  };
  globalThis.clearTimeout = timer => { timeouts.delete(timer); nativeTimers.clearTimeout(timer); };
  globalThis.setInterval = (callback, delay, ...args) => {
    const timer = nativeTimers.setInterval(callback, delay, ...args);
    intervals.add(timer); return timer;
  };
  globalThis.clearInterval = timer => { intervals.delete(timer); nativeTimers.clearInterval(timer); };
  const closeWindow = w.close.bind(w);
  w.close = () => {
    for (const timer of timeouts) nativeTimers.clearTimeout(timer);
    for (const timer of intervals) nativeTimers.clearInterval(timer);
    Object.assign(globalThis, nativeTimers);
    closeWindow();
  };
  const errors = [];
  w.addEventListener('error', event => errors.push(event.error || event.message));
  w.scrollTo = (optionsOrX, y) => {
    w.scrollX = typeof optionsOrX === 'object' ? optionsOrX.left ?? w.scrollX : Number(optionsOrX) || 0;
    w.scrollY = typeof optionsOrX === 'object' ? optionsOrX.top ?? w.scrollY : Number(y) || 0;
  };
  w.matchMedia = () => ({matches: true, addEventListener() {}, removeEventListener() {}});
  w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
  w.HTMLDialogElement.prototype.close = function () {
    if (!this.open) return;
    this.open = false;
    // Native close events are queued; synchronously firing one hides URL/cleanup races.
    queueMicrotask(() => this.dispatchEvent(new w.Event('close')));
  };
  const charts = [];
  class ChartMock {
    constructor(canvas, config) {
      this.canvas = canvas; this.config = config; this.data = config.data; this.options = config.options;
      this.updates = []; this.destroyed = false; charts.push(this);
    }
    update(mode) { this.updates.push(mode); }
    destroy() { this.destroyed = true; }
  }
  w.Chart = ChartMock;
  w.fetch = fetchMock.fetch;
  Object.defineProperty(globalThis, 'window', {value: w, configurable: true, writable: true});
  for (const key of ['document', 'location', 'navigator', 'Node', 'HTMLElement', 'Element', 'SVGElement',
    'MouseEvent', 'Event', 'KeyboardEvent', 'CustomEvent', 'DOMParser', 'Blob', 'getComputedStyle',
    'matchMedia', 'fetch', 'Chart']) {
    Object.defineProperty(globalThis, key, {value: w[key], configurable: true, writable: true});
  }
  Object.defineProperty(globalThis, 'requestAnimationFrame', {
    value: callback => setTimeout(() => callback(performance.now()), 0), configurable: true, writable: true,
  });
  return {dom, w, charts, errors, $: selector => w.document.querySelector(selector),
    click(selector) {
      const element = w.document.querySelector(selector);
      if (!element) throw new Error(`Missing clickable element: ${selector}`);
      element.dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
    },
    change(selector, value) {
      const element = w.document.querySelector(selector);
      element.value = value;
      element.dispatchEvent(new w.Event('change', {bubbles: true}));
    },
  };
}
