// fetch·세션·CSRF·시간 제한·재시도(설계 2.2 "오류 복구").
// GET 만 제한된 지수 백오프+지터로 다시 시도한다. 변경 요청(POST 등)은 멱등성 계약이 없으므로 자동 재시도하지 않는다.
export const RETRY={retries:3,baseMs:400,maxMs:4000,timeoutMs:30000};
const RETRY_STATUS=new Set([429,502,503,504]);
const timers={
 sleep:(ms,signal)=>new Promise((resolve,reject)=>{
  if(signal?.aborted){reject(signal.reason??new DOMException('중단되었습니다.','AbortError'));return;}
  const id=setTimeout(resolve,ms);
  signal?.addEventListener('abort',()=>{clearTimeout(id);reject(signal.reason??new DOMException('중단되었습니다.','AbortError'));},{once:true});
 }),
 random:()=>Math.random(),
};
// 테스트가 대기 시간·난수를 바꿔 끼운다.
export function setTimers(overrides){Object.assign(timers,overrides);}
export function backoff(attempt){
 const cap=Math.min(RETRY.maxMs,RETRY.baseMs*2**attempt);
 return Math.round(cap/2+timers.random()*cap/2); // 지터: 여러 탭이 같은 순간에 몰리지 않게
}
class HttpError extends Error{constructor(message,status,code){super(message);this.status=status;this.code=code;}}

async function once(url,options,ctx){
 // 시간 제한과 호출자의 중단 신호를 하나로 묶는다(구현이 다른 AbortSignal 끼리도 동작하게 직접 연결).
 const controller=new AbortController();
 const timer=setTimeout(()=>controller.abort(new DOMException('응답 시간이 초과되었습니다.','TimeoutError')),RETRY.timeoutMs);
 const outer=options.signal;
 const forward=()=>controller.abort(outer.reason??new DOMException('중단되었습니다.','AbortError'));
 if(outer){if(outer.aborted)forward();else outer.addEventListener('abort',forward,{once:true});}
 try{
  const headers=new Headers(options.headers||{});
  if(options.body)headers.set('Content-Type','application/json');
  if(ctx.csrf?.())headers.set('X-CSRF-Token',ctx.csrf());
  return await fetch(url,{...options,credentials:'same-origin',headers,signal:controller.signal});
 }finally{clearTimeout(timer);outer?.removeEventListener?.('abort',forward);}
}

export async function request(url,options={},ctx={}){
 const method=String(options.method||'GET').toUpperCase(),retryable=method==='GET';
 for(let attempt=0;;attempt++){
  let response;
  try{response=await once(url,options,ctx);}
  catch(error){
   if(options.signal?.aborted)throw error;            // 사용자가 필터를 바꿔 중단: 재시도하지 않는다
   if(!retryable||attempt>=RETRY.retries)throw Error('서버에 연결할 수 없습니다. 잠시 후 다시 시도해주세요.');
   await timers.sleep(backoff(attempt),options.signal);continue;
  }
  if(response.status===401){ctx.onUnauthorized?.();throw Error('로그인이 필요합니다.');}
  if(retryable&&RETRY_STATUS.has(response.status)&&attempt<RETRY.retries){
   await timers.sleep(backoff(attempt),options.signal);continue;
  }
  let payload;try{payload=await response.json();}catch{throw new HttpError('서버 응답을 읽을 수 없습니다.',response.status);}
  if(!response.ok)throw new HttpError(payload?.title||payload?.error?.message||'서버 요청에 실패했습니다.',response.status,payload?.error?.code||payload?.code);
  return payload;
 }
}
