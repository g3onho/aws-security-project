/**
 * 화면 스모크 테스트 — app.js 를 jsdom 에 올려 5개 화면을 실제로 렌더한다.
 *
 * 왜 있나: 파이썬 테스트는 API 만 본다. 화면이 통째로 죽어도 전부 통과한다.
 * 이 스크립트는 렌더 경로에서 나는 런타임 오류와 "자리는 있는데 데이터가 안 꽂히는"
 * 회귀(3계층 미연동, 조치 버튼 없음)를 잡는다.
 *
 * 사용:
 *   cd dashboard/backend && python tools/dump_fixtures.py   # /tmp/fixtures.json 생성
 *   cd ../frontend && npm i jsdom && node tests/dom-check.mjs
 */
import fs from 'fs';
import path from 'path';
import {fileURLToPath} from 'url';
import {JSDOM} from 'jsdom';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const FIXTURES = process.env.DASHBOARD_FIXTURES || path.join(ROOT, 'tests', 'fixtures.json');
const FIX = JSON.parse(fs.readFileSync(FIXTURES, 'utf8'));

const errors = [];
let html = fs.readFileSync(path.join(ROOT, 'templates/index.html'), 'utf8');
html = html.replace(/<script[^>]*><\/script>/g, '').replace(/<link[^>]*>/g, '');

const dom = new JSDOM(html, {url: 'http://localhost/', runScripts: 'outside-only', pretendToBeVisual: true});
const w = dom.window;
w.matchMedia = () => ({matches: false, addEventListener() {}});
w.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
w.HTMLDialogElement.prototype.close = function () { this.open = false; this.dispatchEvent(new w.Event('close')); };
Object.defineProperty(w, 'crypto', {value: {randomUUID: () => '11111111-2222-3333-4444-555555555555'}, configurable: true});
w.Chart = class { constructor() {} destroy() {} };
w.requestAnimationFrame = (fn) => { fn(0); return 1; };
w.onerror = (message) => errors.push('window.onerror: ' + message);
w.fetch = async (url) => {
  const key = Object.keys(FIX).find((k) => String(url).startsWith(k));
  if (!key) { errors.push('fetch 스텁 없음: ' + url); return {ok: false, status: 500, json: async () => ({title: 'no stub'})}; }
  return {ok: true, status: 200, json: async () => FIX[key], blob: async () => ({})};
};

globalThis.window = w;
globalThis.document = w.document;
for (const name of ['matchMedia', 'fetch', 'Chart', 'requestAnimationFrame', 'MouseEvent', 'Event',
                    'KeyboardEvent', 'HTMLElement', 'Node', 'getComputedStyle', 'SVGElement',
                    'navigator', 'URL', 'location', 'performance', 'CustomEvent', 'DOMParser', 'Blob']) {
  Object.defineProperty(globalThis, name, {value: w[name], configurable: true, writable: true});
}
Object.defineProperty(globalThis, 'crypto', {value: w.crypto, configurable: true, writable: true});

const settle = () => new Promise((r) => setTimeout(r, 150));
const count = (selector) => w.document.querySelectorAll(selector).length;
const checks = [];
function expect(label, ok, detail = '') {
  checks.push({label, ok, detail});
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
}

await import('file://' + path.join(ROOT, 'static/js/app.js'));
await settle();

for (const view of ['overview', 'vulnerabilities', 'incidents', 'infrastructure', 'responses', 'events']) {
  w.document.querySelector(`nav [data-view="${view}"]`).dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
  await settle();
  expect(`${view} 화면 렌더`, w.document.querySelector('#content').innerHTML.length > 500);
  expect(`${view} 로딩 배너 해제`, w.document.querySelector('#load-state').hidden);
}

w.document.querySelector('nav [data-view="infrastructure"]').dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
await settle();
expect('3계층 노드 3개', count('.service-node') === 3, `${count('.service-node')}개`);
expect('3계층 상태가 미연동 하드코딩이 아님', !w.document.querySelector('#content').innerHTML.includes('○ 미연동'));
expect('계층별 판정 근거 표기', count('.service-table tbody tr') === 3);
expect('호스트 선택기 존재', count('#host option') > 1, `${count('#host option')}개`);
expect('운영 서버 카드 전부 표시', count('.host-card') === 5, `${count('.host-card')}대`);
expect('지표 통계 표기', count('.metric-stats b') === 4);
expect('기간 프리셋 15분/1시간/1일/1주일',
  [...w.document.querySelectorAll('[data-hours]')].map(b => b.dataset.hours).join(',') === '0.25,1,24,168');

w.document.querySelector('nav [data-view="vulnerabilities"]').dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
await settle();
expect('SEC 커버리지 보드', count('.coverage-item') > 0, `${count('.coverage-item')}장`);
expect('취약점 대상 카드', count('.vuln-group') > 0, `${count('.vuln-group')}개`);
expect('대상별 조치 버튼', count('.vuln-group [data-row-action]') > 0, `${count('.vuln-group [data-row-action]')}개`);
expect('CVE 표 행', count('.table-scroll tbody tr') > 20, `${count('.table-scroll tbody tr')}행`);
expect('CVE 링크', count('.cve-link') > 0);
expect('설치→수정 버전 표기', count('code.fixed') > 0);

w.document.querySelector('nav [data-view="responses"]').dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
await settle();
expect('Before/After 요약', count('.improve-grid b') === 5);
expect('감사 로그', count('#audit-log table') === 1);

w.document.querySelector('nav [data-view="incidents"]').dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
await settle();
expect('침해사례 카드 10장', count('.incident-card') === 10, `${count('.incident-card')}장`);
expect('단계 레일 5단계 × 10장', count('.stage') === 50, `${count('.stage')}개`);
expect('탐지 단계가 실제 이벤트로 켜짐', count('.stage.done') > 0, `${count('.stage.done')}개 완료`);
expect('공격 재현 절차 표기', count('.incident-details ul li') > 0);

// ── 주소창 상태 동기화 ──
w.document.querySelector('nav [data-view="incidents"]').dispatchEvent(new w.MouseEvent('click', {bubbles: true}));
await settle();
expect('화면 전환이 주소에 반영', w.location.search.includes('view=incidents'), w.location.search);
w.document.querySelector('#severity').value = 'Critical';
w.document.querySelector('#severity').dispatchEvent(new w.Event('change', {bubbles: true}));
await settle();
expect('필터가 주소에 반영', w.location.search.includes('severity=Critical'), w.location.search);
expect('기본값은 주소에 안 담김', !w.location.search.includes('region=ap-northeast-2'), w.location.search);
w.history.back();
await settle();

expect('알림 패널 항목', count('.notification-row') === 4);
expect('JS 런타임 오류 없음', errors.length === 0, errors.join(' | '));

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} 통과`);
process.exit(failed.length ? 1 : 0);
