"""Local session authentication with server-side role and CSRF checks."""
import secrets
import time
from flask import Blueprint,current_app,g,request,session
from werkzeug.security import check_password_hash,generate_password_hash
from .storage import connect,audit
from .api.errors import ApiProblem

bp=Blueprint('auth',__name__,url_prefix='/api/auth')


# 발표 시연용으로 낮춘 값이다. 로그인 시도 제한(5회/60초)이 무차별 대입을 막아주지만,
# 같은 네트워크에 공개(--lan)하는 동안에는 이 값이 유일한 방어선이라는 점을 알고 쓴다.
MIN_PASSWORD = 4


def create_user(path,name,password,role='operator'):
    if not name or len(name)>64 or len(password)<MIN_PASSWORD or role not in ('viewer','operator'):
        raise ValueError(f'사용자 이름 1~64자, 암호 {MIN_PASSWORD}자 이상, 역할 viewer/operator가 필요합니다.')
    with connect(path,True) as db:
        db.execute('INSERT INTO users VALUES(?,?,?)',(name,generate_password_hash(password),role))


def set_password(path,name,password):
    """기존 계정의 암호만 바꾼다. 역할은 건드리지 않는다."""
    if len(password)<MIN_PASSWORD:
        raise ValueError(f'암호는 {MIN_PASSWORD}자 이상이어야 합니다.')
    with connect(path,True) as db:
        changed=db.execute('UPDATE users SET password=? WHERE name=?',
                           (generate_password_hash(password),name)).rowcount
    if not changed:
        raise ValueError(f'계정을 찾을 수 없습니다: {name}')


def install(app):
    app.register_blueprint(bp)

    @app.before_request
    def guard():
        if not request.path.startswith('/api/'):
            return
        if request.path in ('/api/auth/login','/api/auth/session'):
            return
        user=session.get('user')
        with connect(app.config['DATABASE']) as db:
            row=db.execute('SELECT name,role FROM users WHERE name=?',(user,)).fetchone()
        if not row:
            raise ApiProblem(401,'로그인이 필요합니다.',code='AUTH_REQUIRED')
        g.actor=row['name'];g.role=row['role']
        if request.method not in ('GET','HEAD','OPTIONS'):
            supplied=request.headers.get('X-CSRF-Token','')
            if not supplied or not secrets.compare_digest(supplied,session.get('csrf','')):
                raise ApiProblem(403,'요청 확인 토큰이 일치하지 않습니다.',code='CSRF_INVALID')
            if request.path!='/api/auth/logout' and row['role']!='operator':
                raise ApiProblem(403,'조회 전용 계정입니다.',code='FORBIDDEN')


@bp.get('/session')
def me():
    token=session.setdefault('csrf',secrets.token_urlsafe(32))
    with connect(current_app.config['DATABASE']) as db:
        user=db.execute('SELECT name,role FROM users WHERE name=?',(session.get('user'),)).fetchone()
    return dict(user=dict(user) if user else None,csrfToken=token)


@bp.post('/login')
def login():
    token=request.headers.get('X-CSRF-Token','')
    if not token or not secrets.compare_digest(token,session.get('csrf','')):
        raise ApiProblem(403,'로그인 화면을 새로고침해주세요.',code='CSRF_INVALID')
    data=request.get_json(silent=True) or {}
    if not isinstance(data,dict) or not isinstance(data.get('username'),str) or not isinstance(data.get('password'),str):
        raise ApiProblem(400,'아이디와 암호를 입력해주세요.',code='INVALID_PARAMETER')
    if len(data['username'])>64 or len(data['password'])>256:
        raise ApiProblem(400,'입력 길이를 확인해주세요.',code='INVALID_PARAMETER')
    key=(request.remote_addr or 'local')+':'+data['username']
    failed=False
    with connect(current_app.config['DATABASE'],True) as db:
        limit=db.execute('SELECT * FROM login_limits WHERE key=?',(key,)).fetchone()
        if limit and limit['until']>time.time() and limit['failures']>=5:
            raise ApiProblem(429,'로그인 시도가 많습니다. 잠시 후 다시 시도해주세요.',code='RATE_LIMITED')
        user=db.execute('SELECT * FROM users WHERE name=?',(data['username'],)).fetchone()
        if not user or not check_password_hash(user['password'],data['password']):
            count=(limit['failures'] if limit and limit['until']>time.time() else 0)+1
            db.execute('INSERT OR REPLACE INTO login_limits VALUES(?,?,?)',(key,count,time.time()+60))
            failed=True
        else:
            db.execute('DELETE FROM login_limits WHERE key=?',(key,))
            audit(db,user['name'],None,'login',{})
    if failed:
        raise ApiProblem(401,'아이디 또는 암호가 올바르지 않습니다.',code='AUTH_REQUIRED')
    session.clear();session.permanent=True
    session.update(user=user['name'],csrf=secrets.token_urlsafe(32))
    return dict(user=dict(name=user['name'],role=user['role']),csrfToken=session['csrf'])


@bp.post('/logout')
def logout():
    session.clear()
    return {'ok':True}
