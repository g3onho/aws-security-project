// 패널 공통: 빈 상태·제목·캔버스 틀, 본문 교체, 비동기 패널 불러오기, 알림(toast).
import {$,state,ui} from '../context.js?v=v43';
import {esc} from './format.js?v=v43';
import {patchMarkup} from './rendering.js?v=v43';
import {animateLayout} from './layout-motion.js?v=v43';
let toastTimer,renderedView='';
export function toast(text){$('#toast').textContent=text;$('#toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('#toast').hidden=true,3500);}
export function empty(message='선택한 조건에 맞는 이벤트가 없습니다.'){return `<div class="empty"><strong>데이터 없음</strong>${message}</div>`;}
export function header(title,meta=''){return `<div class="panel-heading"><h2>${title}</h2><span class="meta">${meta}</span></div>`;}
export function canvas(id,label){return `<canvas id="${id}" role="img" aria-label="${esc(label)}">${esc(label)}</canvas>`;}
export function renderContent(html){
 const content=$('#content');
 if(renderedView!==state.view){content.replaceChildren();renderedView=state.view;patchMarkup(content,html);}
 else patchAnimated(content,html);
}
export function patchAnimated(container,html){return animateLayout(container,()=>patchMarkup(container,html));}
export function resetTableScroll(control){
 const table=control.closest('.panel')?.querySelector('.table-scroll');
 if(table)table.scrollTop=0;
}
const panelRequests=new WeakMap();
export const panelScope=()=>JSON.stringify([state.view,state.region,state.resource,state.environment,state.hours,state.endOffset,state.severity,state.status,state.source,state.search]);
export async function loadPanel(box,fetchData,markup,label){
 if(!box)return;
 const token={},serial=ui.refreshSerial,scope=panelScope();
 panelRequests.set(box,token);box.setAttribute('aria-busy','true');
 const current=()=>box.isConnected&&panelRequests.get(box)===token&&serial===ui.refreshSerial&&scope===panelScope();
 try{
  const data=await fetchData();if(!current())return;
  const html=markup(data);
  animateLayout(box,()=>{box.querySelector(':scope > .panel-error')?.remove();patchMarkup(box,html);});box.dataset.loaded='true';
 }catch(error){
  if(!current()||error.name==='AbortError')return;
  const message=`${label} 갱신 실패: ${error.message}`;
  if(box.dataset.loaded){
   animateLayout(box,()=>{
    let note=box.querySelector(':scope > .panel-error');
    if(!note){note=document.createElement('p');note.className='panel-error';note.setAttribute('role','status');box.prepend(note);}
    note.textContent=message+' · 이전 데이터를 표시하고 있습니다.';
   });
  }else patchAnimated(box,`<p class="panel-error" role="status">${esc(message)}</p>`);
 }finally{if(panelRequests.get(box)===token)box.removeAttribute('aria-busy');}
}
