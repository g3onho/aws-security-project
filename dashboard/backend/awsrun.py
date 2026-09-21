"""실 AWS 모드로 대시보드를 띄운다.

    python awsrun.py            # http://127.0.0.1:5050
    python awsrun.py --port 5000

run.py 를 그대로 쓰되 환경변수만 미리 채운다. 매번 긴 명령을 붙여넣지 않으려고 둔 얇은 런처다.
값은 terraform 출력과 같아야 한다 — 리소스 이름을 바꿨다면 아래 DEFAULTS 도 같이 고친다.
이미 환경에 있는 값은 덮어쓰지 않으므로, 임시로 바꾸려면 환경변수를 먼저 주면 된다.
"""
import os
import runpy
import sys

DEFAULTS = {
    "USE_DEMO_DATA": "false",
    "AWS_REGION": "ap-northeast-2",
    "NAME_PREFIX": "soar-sec-dev",
    "CORRELATED_FINDINGS_TABLE": "soar-sec-dev-correlated-findings",
    "REMEDIATION_ACTIONS_TABLE": "soar-sec-dev-remediation-actions",
}

for key, value in DEFAULTS.items():
    os.environ.setdefault(key, value)

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)          # run.py 가 instance/ 와 ../frontend/ 를 상대경로로 찾는다
sys.path.insert(0, HERE)

print("실 AWS 모드 · " + os.environ["AWS_REGION"] + " · " + os.environ["NAME_PREFIX"], flush=True)
runpy.run_path(os.path.join(HERE, "run.py"), run_name="__main__")
