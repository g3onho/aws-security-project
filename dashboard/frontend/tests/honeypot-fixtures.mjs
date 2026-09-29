// 허니팟 화면 DOM 검증용 응답 자료. 시각은 서버 API 와 같은 ms 이고 값은 지어낸 것이다.
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import {ROOT} from './dom-test-support.mjs';

export const NOW = Date.now();
export const meta = (over = {}) => ({schemaVersion: '1', asOf: new Date().toISOString(), requestId: 'fixture', partial: false, warnings: [], ...over});
export const ok = (data, over) => ({data, meta: meta(over)});

// 실제 vendor 번들을 창에 심는다(그래프 배치 계산). 브라우저에서는 index.html 의 script 태그가 한다.
export function loadD3Force(w) {
  const code = fs.readFileSync(path.join(ROOT, 'static/vendor/d3-force.min.js'), 'utf8');
  w.d3force = vm.runInThisContext(code + '\n;d3force');
}

export const card = (state, text, detail = '', at = NOW - 60000) => ({state, text, detail, at});
export const status = (over = {}) => ({deployed: true, canWrite: true, asOf: new Date().toISOString(),
  verdict: {state: 'ok', label: '정상 동작', reasons: []},
  cards: {instance: card('ok', 'running', 'i-0abc · 10.0.1.50'), logs: card('ok', '수신 중', '최근 24시간 세션 3개'),
    ai: card('ok', '2/2', 'AI 분석이 적용된 세션 / 분석된 세션(명령 있음)'), alarm: card('ok', 'OK', 'soar-sec-dev-honeypot'),
    block: card('ok', 'SUCCESS', '미끼 접속 4회')}, ...over});

export const session = (id, ip, over = {}) => ({sessionId: id, srcIp: ip, startedAt: NOW - 600000, endedAt: NOW - 590000, authCount: 1, commandCount: 2,
  intent: 'recon', severity: 'medium', aiApplied: true, analyzed: true, ...over});

export const stats = (over = {}) => ({from: new Date(NOW - 86400000).toISOString(), to: new Date(NOW).toISOString(), bucketSeconds: 3600,
  timeline: Array.from({length: 4}, (_, i) => ({at: NOW - (3 - i) * 3600000, sessions: i === 3 ? 2 : 0, commands: i === 3 ? 3 : 0})),
  topIps: [{ip: '10.0.2.55', sessions: 2, commands: 3, auth: 2, firstSeen: NOW - 700000, lastSeen: NOW - 600000}],
  topCommands: [{key: 'whoami', count: 2}, {key: 'cat /etc/passwd', count: 1}], topUsers: [{key: 'root', count: 2}],
  intents: [{key: 'recon', count: 2}, {key: 'credential-access', count: 0}, {key: 'lateral-movement', count: 0}, {key: 'exfiltration', count: 0}, {key: 'impact', count: 0}, {key: 'unknown', count: 0}],
  severities: [{key: 'low', count: 0}, {key: 'medium', count: 2}, {key: 'high', count: 0}, {key: 'critical', count: 0}],
  totals: {sessions: 2, commands: 3, uniqueIps: 1, unanalyzed: 0},
  graph: {nodes: [{id: 'ip:10.0.2.55', type: 'ip', label: '10.0.2.55', sessions: 2},
    {id: 's:a00000000001', type: 'session', label: 'a00000000001', intent: 'recon', severity: 'medium', commands: 2},
    {id: 's:a00000000002', type: 'session', label: 'a00000000002', intent: 'recon', severity: 'medium', commands: 1},
    {id: 'c:whoami', type: 'command', label: 'whoami', count: 2}],
   links: [{source: 'ip:10.0.2.55', target: 's:a00000000001'}, {source: 'ip:10.0.2.55', target: 's:a00000000002'},
     {source: 's:a00000000001', target: 'c:whoami'}, {source: 's:a00000000002', target: 'c:whoami'}],
   hidden: {ips: 0, sessions: 0, commands: 0}}, ...over});

export const steps = () => [
  {key: 'connect', label: '접속(connect)', state: 'done', at: NOW - 600000, detail: '세션 2개', source: '허니팟 로그'},
  {key: 'auth', label: '로그인 시도(auth)', state: 'done', at: NOW - 599000, detail: '2회', source: '허니팟 로그'},
  {key: 'command', label: '명령(command)', state: 'done', at: NOW - 598000, detail: '3개', source: '허니팟 로그'},
  {key: 'analysis', label: '세션 종료·AI 분석', state: 'done', at: NOW - 590000, detail: 'recon · AI 적용', source: '허니팟 로그'},
  {key: 'alarm', label: '알람 ALARM', state: 'done', at: NOW - 540000, detail: '접속 후 60초', source: 'soar-sec-dev-honeypot'},
  {key: 'judge', label: 'asr_trigger 판정', state: 'done', at: NOW - 535000, detail: 'auto-executed · 미끼 접속 4회', source: '조치 이력 ssm-e1'},
  {key: 'ssm', label: 'SSM 실행', state: 'failed', at: NOW - 520000, detail: 'Failed', source: 'e1'},
  {key: 'nacl', label: 'NACL Deny 확인', state: 'missing', at: null, detail: '현재 NACL 에 이 IP 의 Deny 없음', source: 'NACL 1~99'}];

export const blockItem = (ip, over = {}) => ({ip, status: 'ACTIVE', ruleNumber: 3, naclId: 'acl-0123456789abcdef0', source: 'HONEYPOT', blockedAt: NOW - 500000,
  updatedAt: NOW - 500000, expiresAt: NOW + 3600000, allowlisted: false, releasedAt: null, releasedBy: null, releaseReason: null, releaseKind: null,
  lastError: null, version: 2, executionId: 'e1', unblockExecutionId: null, evidence: {hits: 4, alarm: 'soar-sec-dev-honeypot'},
  state: 'blocked', mismatch: null, inNacl: true, naclRule: 3, permanent: false,
  sessions: {sessionCount: 2, commandCount: 3, authCount: 2, lastSeenAt: NOW - 600000, intents: ['recon'], topCommands: [{key: 'whoami', count: 2}], sessionIds: ['a00000000001']}, ...over});

export const blocklist = (items, over = {}) => ({items, naclId: 'acl-0123456789abcdef0', from: new Date(NOW - 86400000).toISOString(),
  to: new Date(NOW).toISOString(), defaultTtlHours: 24, canWrite: true,
  durations: [{hours: 1, label: '1시간'}, {hours: 24, label: '24시간'}, {hours: 168, label: '7일'}, {hours: 0, label: '영구'}],
  counts: {applying: 0, blocked: items.filter(i => i.state === 'blocked').length, expiring: 0, releasing: 0, released: 0, expired: 0, failed: 0,
    mismatch: items.filter(i => i.mismatch).length, unrecorded: 0, allowlisted: items.filter(i => i.allowlisted).length}, ...over});

export const detail = (id, over = {}) => ({sessionId: id, srcIp: '10.0.2.55', srcPort: 51000, hasConnect: true, startedAt: NOW - 600000, endedAt: NOW - 590000,
  authCount: 1, commandCount: 2, intent: 'recon', severity: 'medium', aiApplied: true, analyzed: true,
  authAttempts: [{at: NOW - 599000, user: 'root', passwordLength: 7, password: null}],
  commands: [{at: NOW - 598000, command: 'whoami', response: 'root'}, {at: NOW - 597000, command: 'cat /etc/passwd', response: 'root:x:0:0:root:/root:/bin/bash'}],
  analysis: {summary: '공격자가 계정 정보를 훑어봤다.', iocs: ['cat /etc/passwd'], intent: 'recon', severity: 'medium', aiApplied: true},
  analysisNote: 'AI 분석은 참고용이며 차단·해제 판단에 쓰지 않는다.', ...over});

// 표준 응답 묶음: 응답 경로마다 자료를 등록한다.
export function install(network, {role = 'operator', items, statusData, statsData, sessions, timeline} = {}) {
  const list = items ?? [blockItem('10.0.2.55'), blockItem('10.0.2.56', {state: 'mismatch', mismatch: 'nacl-missing', ruleNumber: 4, naclRule: null, inNacl: false, sessions: null}),
    blockItem('10.0.2.99', {status: 'UNRECORDED', state: 'unrecorded', mismatch: 'record-missing', source: null, blockedAt: null, expiresAt: null, version: 0, sessions: {sessionCount: 0, commandCount: 0, authCount: 0, lastSeenAt: null, intents: [], topCommands: [], sessionIds: []}})];
  network.respond('/api/auth/session', () => ({user: {name: role === 'operator' ? 'admin' : 'user', role}, csrfToken: 'fixture-csrf'}));
  network.respond('/api/honeypot/status', () => ok(statusData ?? status({canWrite: role === 'operator'})));
  network.respond('/api/honeypot/stats', () => ok(statsData ?? stats()));
  network.respond('/api/honeypot/sessions', () => ok(sessions ?? {items: [session('a00000000001', '10.0.2.55'), session('a00000000002', '10.0.2.55', {commandCount: 1, analyzed: false, intent: null, severity: null, aiApplied: null})], nextCursor: null, total: 2}));
  network.respond('/api/honeypot/timeline', () => ok(timeline ?? {ip: '10.0.2.55', steps: steps(), sessions: []}));
  network.respond('/api/blocklist', () => ok(blocklist(list, {canWrite: role === 'operator'})));
  network.respond('/api/honeypot/sessions/a00000000001', call => ok(detail('a00000000001', call.url.searchParams.get('revealPasswords') === 'true'
    ? {authAttempts: [{at: NOW - 599000, user: 'root', passwordLength: 7, password: 'S3cret!'}]} : {})));
  return list;
}
