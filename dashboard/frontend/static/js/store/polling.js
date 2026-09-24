// 자동 새로고침을 Store 한 곳에서 관리한다(설계 2.2 폴링).
// 타이머는 하나만, 탭이 숨으면 멈추고 돌아오면 다시 건다(밀린 주기가 있으면 한 번 바로 실행).
export function createPoller({intervalMs=30000,doc=globalThis.document}={}){
 let timer=null,active=false,last=0,tick=()=>{},canRun=()=>true;
 const hidden=()=>doc?.visibilityState==='hidden';
 const run=()=>{if(!active||hidden()||!canRun())return;last=Date.now();tick();};
 const arm=()=>{clearInterval(timer);timer=null;if(active&&!hidden())timer=setInterval(run,intervalMs);};
 const onVisibility=()=>{arm();if(active&&!hidden()&&Date.now()-last>=intervalMs)run();};
 return {
  start(fn,guard){tick=fn;canRun=guard||(()=>true);active=true;last=Date.now();arm();doc?.addEventListener?.('visibilitychange',onVisibility);},
  stop(){active=false;clearInterval(timer);timer=null;doc?.removeEventListener?.('visibilitychange',onVisibility);},
  get running(){return active;},
  get armed(){return timer!==null;},
 };
}
