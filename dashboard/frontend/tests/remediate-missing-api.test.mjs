// 조치 API 자체가 없는 서버(404, HTTP_ERROR)와 이벤트·기록이 없다는 404(…_NOT_FOUND)를 구분한다.
import test from 'node:test';
import assert from 'node:assert/strict';
import {remediationApiMissing,remediationErrorText,REMEDIATION_API_MISSING} from '../static/js/ui/components/remediation.js';
const err=(status,code,message='x')=>Object.assign(new Error(message),{status,code});
test('라우트 없음 404 는 조치 API 미연결 안내로 바뀐다',()=>{
 assert.equal(remediationApiMissing(err(404,'HTTP_ERROR','Not Found')),true);
 assert.equal(remediationApiMissing(err(404,undefined,'서버 응답을 읽을 수 없습니다.')),true);
 assert.equal(remediationErrorText(err(404,'HTTP_ERROR','Not Found')),REMEDIATION_API_MISSING);
});
test('이벤트·기록 없음 404 와 그 밖의 오류는 원래 메시지를 유지한다',()=>{
 assert.equal(remediationApiMissing(err(404,'EVENT_NOT_FOUND')),false);
 assert.equal(remediationApiMissing(err(404,'REMEDIATION_NOT_FOUND')),false);
 assert.equal(remediationApiMissing(err(500,'INTERNAL_ERROR')),false);
 assert.equal(remediationErrorText(err(500,'INTERNAL_ERROR','요청을 처리하지 못했습니다.')),'요청을 처리하지 못했습니다.');
});
