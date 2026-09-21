"""Run with Flask installed: python tests/flask-check.py.

v2.2.2 까지는 /health 응답이 `{'status','mode','aws_connected'}` 3필드로 고정이었고
이 파일이 완전 일치를 단언했다. 백엔드가 붙으면서 모드·버전·쓰기 플래그가 추가되어
(02-frontend-redesign.md §4) **모드별 분기 단언**으로 바꾼다.
"""
from pathlib import Path
import os
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault('USE_DEMO_DATA', 'true')
from run import create_app

client = create_app().test_client()

assert client.get('/').status_code == 200

health = client.get('/health').json
assert health['status'] == 'ok', health
assert health['mode'] == 'demo', health
assert health['aws_connected'] is False, health
assert isinstance(health['write_enabled'], bool), health
assert health['version'], health

for asset in ('js/app.js', 'js/store.js', 'js/data.js', 'css/app.css', 'css/tailwind.css',
              'vendor/chart.umd.js', 'data/countries.geojson'):
    assert client.get('/static/' + asset).status_code == 200, asset

# API 가 붙었는지 — 데모 모드에서도 스키마 유효 응답을 내야 한다.
events = client.get('/api/events').json
assert 'items' in events and 'total' in events, events
assert client.get('/api/scenarios').json['items'], 'SEC 커버리지 보드'
assert client.get('/api/export/events.csv').get_data(as_text=True).startswith('﻿')

print('PASS: Flask page, health, assets, and demo API')
