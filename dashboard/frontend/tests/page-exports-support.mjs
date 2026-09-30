// v28 화면 우측 상단 버튼 DOM 검증용 공통 부팅. 이 저장소의 관례대로 테스트 파일 하나에 시나리오 하나(app.js 는 프로세스당 한 번만 평가된다).
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {ROOT, until, makeFetchMock, appDOM} from './dom-test-support.mjs';
import {ok, install} from './honeypot-fixtures.mjs';

// v28: 화면 우측 상단 [로그 저장]·[AI 요약 보고서]. 5개 화면에서만 보이고, 서로 독립이며, 모델·집계는 서버가 한다.
export const REPORT = {view: 'events', title: '보안 이벤트 AI 요약 보고서', generatedAt: new Date().toISOString(), model: 'fake-nova-pro', cached: false,
  period: {from: '2026-09-28T00:00:00Z', to: '2026-09-29T00:00:00Z', hours: 24, endOffset: 0}, filters: {region: '', severity: '', status: '', source: '', search: '', resource: ''},
  facts: {'총 건수': 6, '필수 항목 값': {CRITICAL: 1, HIGH: 2}}, unavailable: ['CloudWatch 경보'], warnings: ['원천에 없는 수치 1개: 999'], usage: {inputTokens: 30, outputTokens: 10},
  markdown: '## 1. 요약\nCRITICAL **1건**\n<img src=x onerror="window.__pwn=1">\n## 2. 주요 수치\n| 항목 | 값 |\n|---|---|\n| HIGH | 2 |\n- 첫째 [링크](http://evil.example)\n1. 조치'};

export async function boot(t, {report = () => ok(REPORT)} = {}) {
  const network = makeFetchMock(); install(network);
  const bodies = [];
  network.respond('/api/assistant/report', call => { bodies.push(JSON.parse(call.options.body)); return report(call); });
  const app = appDOM(network); t.after(() => app.dom.window.close());
  const blobs = [], downloads = [];
  t.mock.method(URL, 'createObjectURL', blob => { blobs.push(blob); return 'blob:fixture'; });
  t.mock.method(URL, 'revokeObjectURL', () => {});
  app.dom.window.HTMLAnchorElement.prototype.click = function () { downloads.push(this.download); };
  await import(pathToFileURL(path.join(ROOT, 'static/js/app.js')).href);
  await until(() => app.$('#content .event-trend-widget'), 'overview did not render');
  return {...app, network, bodies, blobs, downloads};
}

