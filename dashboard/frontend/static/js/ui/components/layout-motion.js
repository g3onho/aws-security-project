// Animate real layout height around a synchronous DOM update. Content and canvas nodes
// remain owned by the caller; no clones, transforms, observers or resize events are used.
const active=new WeakMap();
const running=new Set();
const number=value=>Number.parseFloat(value)||0;

function topLevel(nodes){
 const unique=[...new Set(nodes)];
 return unique.filter(node=>!unique.some(other=>other!==node&&other.contains(node)));
}

function roots(container){
 const panel=container.closest?.('.panel');
 const candidates=panel?[panel]:topLevel([...container.querySelectorAll('.panel')]);
 return topLevel((candidates.length?candidates:[container]).map(candidate=>{
  // A second update inside an animating wrapper resumes that wrapper instead of
  // creating simultaneous parent/child height animations.
  for(const node of running)if(node.contains(candidate))candidate=node;
  return candidate;
 }));
}

function geometry(node){
 if(!node.isConnected||!node.getClientRects().length)return null;
 const style=node.ownerDocument.defaultView.getComputedStyle(node);
 if(style.display==='none'||style.visibility==='hidden')return null;
 const height=node.getBoundingClientRect().height;
 if(!Number.isFinite(height))return null;
 const extras=style.boxSizing==='border-box'?0:number(style.paddingTop)+number(style.paddingBottom)+number(style.borderTopWidth)+number(style.borderBottomWidth);
 return {height,extras,style};
}

function release(node,record,cancel=false){
 if(!record||active.get(node)!==record)return;
 active.delete(node);running.delete(node);
 if(cancel)record.animation.cancel();
 // Preserve a style another owner deliberately changed during the animation.
 if(record.overflow&&node.style.getPropertyValue('overflow')==='clip'&&node.style.getPropertyPriority('overflow')===record.overflow.priority){
  if(record.overflow.value)node.style.setProperty('overflow',record.overflow.value,record.overflow.priority);
  else node.style.removeProperty('overflow');
 }
}

/**
 * Wrap only the synchronous rendering part of an API response:
 *   animateLayout(container, () => patchMarkup(container, markup))
 * The callback result is returned unchanged. Existing .panel roots are preferred;
 * wrappers without panels animate themselves. Reduced motion is honored by default.
 */
export function animateLayout(container,mutate,{duration=280,easing='cubic-bezier(.2,.7,.2,1)',reducedMotion}={}){
 if(!container?.querySelectorAll||typeof mutate!=='function')throw new TypeError('animateLayout requires an element and a synchronous update function');
 const targets=roots(container);
 // Capture the presented height before cancelling older animations, not their target.
 const before=new Map(targets.map(node=>[node,geometry(node)]));
 for(const node of [...running])if(targets.some(target=>target.contains(node)||node.contains(target)))release(node,active.get(node),true);
 const result=mutate();
 const view=container.ownerDocument.defaultView;
 const reduce=typeof reducedMotion==='function'?reducedMotion():reducedMotion??view.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
 if(reduce||!Number.isFinite(duration)||duration<=0)return result;
 // Measure every natural target before any height animation changes sibling layout.
 const changes=targets.map(node=>({node,from:before.get(node),to:geometry(node)}));
 for(const {node,from,to}of changes){
  if(!from||!to||typeof node.animate!=='function'||Math.abs(from.height-to.height)<.5)continue;
  const overflowX=to.style.overflowX||to.style.overflow;
  const overflowY=to.style.overflowY||to.style.overflow;
  let overflow=null;
  if((!overflowX||overflowX==='visible')&&(!overflowY||overflowY==='visible')){
   overflow={value:node.style.getPropertyValue('overflow'),priority:node.style.getPropertyPriority('overflow')};
   // clip avoids the formatting-context/margin changes caused by overflow:hidden.
   node.style.setProperty('overflow','clip',overflow.priority);
  }
  let animation;
  try{
   animation=node.animate([{height:`${Math.max(0,from.height-to.extras)}px`},{height:`${Math.max(0,to.height-to.extras)}px`}],{duration,easing,fill:'none'});
  }catch{
   if(overflow){if(overflow.value)node.style.setProperty('overflow',overflow.value,overflow.priority);else node.style.removeProperty('overflow');}
   continue;
  }
  const record={animation,overflow};active.set(node,record);running.add(node);
  animation.onfinish=()=>release(node,record);
  animation.oncancel=()=>release(node,record);
 }
 return result;
}
