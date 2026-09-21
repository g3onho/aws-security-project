/* 로그인 화면.
 *
 * 서버 계약(app/auth.py):
 *   GET  /api/auth/session  → {user, csrfToken}   ← 토큰을 먼저 받아야 한다
 *   POST /api/auth/login    → X-CSRF-Token 헤더 필수, {username, password}
 *
 * 로그인 성공 시 서버가 세션 CSRF 토큰을 새로 발급하므로, 대시보드는
 * 진입 시 /api/auth/session 을 다시 호출해 최신 토큰을 받는다.
 */
const $ = (sel) => document.querySelector(sel);
const form = $('#login-form');
const errorBox = $('#login-error');
const submit = $('#submit');

let csrfToken = '';

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

async function readProblem(response) {
  // errors.py 는 RFC 7807 형식으로 내려준다. 파싱 실패해도 화면은 살아야 한다.
  try {
    const body = await response.json();
    return body.title || body.detail || `오류 ${response.status}`;
  } catch {
    return `오류 ${response.status}`;
  }
}

async function loadToken() {
  try {
    const response = await fetch('/api/auth/session', { credentials: 'same-origin' });
    if (!response.ok) throw new Error(await readProblem(response));
    const body = await response.json();
    csrfToken = body.csrfToken || '';
    if (body.user) window.location.replace('/');   // 이미 로그인된 세션
  } catch (error) {
    showError(`서버에 연결하지 못했습니다. ${error.message}`);
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  submit.disabled = true;
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
      body: JSON.stringify({ username: $('#username').value, password: $('#password').value }),
    });
    if (!response.ok) {
      // CSRF 토큰이 만료됐을 수 있으니 다시 받아 둔다.
      if (response.status === 403) await loadToken();
      throw new Error(await readProblem(response));
    }
    window.location.replace('/');
  } catch (error) {
    showError(error.message);
    $('#password').value = '';
    $('#password').focus();
  } finally {
    submit.disabled = false;
  }
});

loadToken();
