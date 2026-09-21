// data.js 의 생성 결과를 JSON 으로 덤프한다.
// app/adapters/demo.py 포팅이 원본과 같은지 대조하는 데 쓴다.
// 사용: node tests/dump_demo.mjs
import {createEvents, metricsFor, regions, DEMO_NOW} from '../../frontend/static/js/data.js';

const events = createEvents();
const metrics = {};
for (const hours of [1, 6, 24, 168]) {
  for (const offset of [0, 3, 17]) {
    for (const env of ['production', 'staging']) {
      for (const r of ['ap-northeast-2', 'us-east-1', 'global', 'sa-east-1']) {
        metrics[`${r}|${hours}|${offset}|${env}`] =
          metricsFor(regions.find(x => x.id === r), hours, offset, env);
      }
    }
  }
}
process.stdout.write(JSON.stringify({DEMO_NOW, count: events.length, events, metrics}));
