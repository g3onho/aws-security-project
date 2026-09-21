// store.js 의 toCSV 결과를 그대로 덤프한다.
// app/services/csv_export.py 가 바이트 단위로 같은 문자열을 만드는지 대조한다.
// 사용: node tests/dump_csv.mjs
import {createEvents} from '../../frontend/static/js/data.js';
import {toCSV} from './legacy_csv.mjs';

const rows = createEvents();
// 수식 인젝션 방어와 따옴표 이스케이프까지 함께 검증하려고 악성 값을 하나 끼워 넣는다.
const hostile = {
  ...rows[0],
  id: '=cmd|\'/c calc\'!A1',
  title: 'He said "hi"',
  resource: '-1+1',
  sourceIp: '@SUM(1+1)',
};
const sample = [...rows.slice(0, 40), hostile];
process.stdout.write(JSON.stringify({ids: sample.map(r => r.id), csv: toCSV(sample), hostile}));
