"""Local dashboard server and persistent simulation worker. No static-only fallback."""
import argparse
import getpass
import os
import secrets
import time
from pathlib import Path

BACKEND=Path(__file__).resolve().parent
FRONTEND=BACKEND.parent/'frontend'


def create_app(overrides=None):
    from flask import Flask,render_template,redirect,session
    from app.config import Config
    from app.storage import migrate
    from app.api import bp
    from app.api.errors import register
    from app.auth import install
    app=Flask(__name__,template_folder=str(FRONTEND/'templates'),static_folder=str(FRONTEND/'static'))
    app.config.from_object(Config)
    instance=Path(os.environ.get('DASHBOARD_INSTANCE',str(BACKEND/'instance')))
    instance.mkdir(parents=True,exist_ok=True)
    app.config.update(USE_DEMO_DATA=os.environ.get('USE_DEMO_DATA','true').lower()=='true',
        WRITE_ENABLED=os.environ.get('WRITE_ENABLED','true').lower()=='true',DATABASE=str(instance/'local.sqlite3'),
        SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',SESSION_COOKIE_SECURE=False,
        PERMANENT_SESSION_LIFETIME=3600,MAX_CONTENT_LENGTH=64*1024)
    app.config.update(overrides or {})
    key_file=instance/'session.key'
    if not key_file.exists():
        try:
            with key_file.open('x',encoding='utf-8') as f:f.write(secrets.token_hex(32))
            key_file.chmod(0o600)
        except FileExistsError:pass
    app.secret_key=os.environ.get('FLASK_SECRET_KEY') or key_file.read_text(encoding='utf-8')
    migrate(app.config['DATABASE'])
    if app.config['USE_DEMO_DATA']:
        from app.adapters.local import LocalAdapter
        adapter=LocalAdapter(app.config['DATABASE'])
    else:
        from app.adapters.live import LiveAdapter
        adapter=LiveAdapter(Config)
        app.config['WRITE_ENABLED']=False
    app.extensions['dashboard_adapter']=adapter
    register(app);install(app);app.register_blueprint(bp)

    @app.get('/')
    def index():
        if not session.get('user'):return redirect('/login')
        return render_template('index.html')

    @app.get('/login')
    def login():return render_template('login.html')

    @app.get('/health')
    def health():
        checks=adapter.health_checks() if adapter.mode=='demo' else {'aws':'not_connected','worker':'not_available'}
        return dict(status='ok' if checks.get('worker')=='ok' else 'degraded',mode=adapter.mode,
            aws_connected=False,version=app.config['VERSION'],write_enabled=app.config['WRITE_ENABLED'],checks=checks)

    @app.after_request
    def headers(response):
        response.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
            'X-Frame-Options':'DENY','Referrer-Policy':'same-origin',
            'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"})
        return response
    return app


def worker(app,once=False):
    adapter=app.extensions['dashboard_adapter']
    if adapter.mode!='demo':raise SystemExit('로컬 작업 처리기는 데모 모드에서만 실행됩니다.')
    while True:
        adapter.work_once()
        if once:return
        time.sleep(.5)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=5050)
    parser.add_argument('--worker',action='store_true')
    parser.add_argument('--once',action='store_true')
    parser.add_argument('--init-admin',action='store_true')
    parser.add_argument('--add-user')
    parser.add_argument('--role',choices=['viewer','operator'],default='viewer')
    args=parser.parse_args();app=create_app()
    if args.init_admin or args.add_user:
        from app.auth import create_user
        from app.storage import connect
        if args.init_admin:
            with connect(app.config['DATABASE']) as db:
                exists=db.execute('SELECT 1 FROM users LIMIT 1').fetchone()
            if not exists:
                password=secrets.token_urlsafe(18)
                create_user(app.config['DATABASE'],'operator',password,'operator')
                path=Path(app.config['DATABASE']).parent/'initial-login.txt'
                path.write_text('주소: http://127.0.0.1:'+str(args.port)+'/login\n아이디: operator\n암호: '+password+'\n',encoding='utf-8')
                path.chmod(0o600)
                print('초기 로그인 정보: '+str(path))
            else:print('계정이 이미 있습니다. 기존 계정을 유지합니다.')
        else:create_user(app.config['DATABASE'],args.add_user,getpass.getpass('Password (12+ characters): '),args.role)
    elif args.worker:worker(app,args.once)
    else:
        from waitress import serve
        print(f'Local dashboard: http://127.0.0.1:{args.port}',flush=True)
        serve(app,host='127.0.0.1',port=args.port,threads=4)
