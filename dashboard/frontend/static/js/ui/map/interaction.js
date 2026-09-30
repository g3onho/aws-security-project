import {project,mapPoint,wrapLon,clampPhi,ZOOM_MIN,ZOOM_MAX} from './globe.js?v=v45';

const SVG_NS='http://www.w3.org/2000/svg';
const clamp=(value,min,max)=>Math.max(min,Math.min(max,value));
const finite=value=>typeof value==='number'&&Number.isFinite(value);

function screenScale(svg){
 try{
  const matrix=svg.getScreenCTM?.();
  const x=Math.hypot(matrix?.a,matrix?.b),y=Math.hypot(matrix?.c,matrix?.d);
  if(finite(x)&&finite(y)&&x>0&&y>0)return {x,y};
 }catch{/* A hidden or detached SVG may not have a screen transform. */}
 return {x:1,y:1};
}

function viewportBounds(svg){
 const values=(svg.getAttribute('viewBox')||'0 0 1000 460').split(/[\s,]+/).map(Number);
 let [x,y,width,height]=values;
 const rect=svg.getBoundingClientRect();
 if(rect.width&&rect.height){
  const a=mapPoint(svg,rect.left,rect.top),b=mapPoint(svg,rect.right,rect.bottom);
  const right=Math.min(x+width,Math.max(a[0],b[0])),bottom=Math.min(y+height,Math.max(a[1],b[1]));
  x=Math.max(x,Math.min(a[0],b[0]));y=Math.max(y,Math.min(a[1],b[1]));
  width=right-x;height=bottom-y;
 }
 return {x,y,width,height};
}

/** Persistent SVG markers. Positions and labels change without replacing focusable nodes. */
export function createMarkerLayer(group){
 const document=group.ownerDocument,svg=group.ownerSVGElement,view=document.defaultView;
 const nodes=new Map();let latest=null,destroyed=false;
 const element=(tag,attributes={})=>{const node=document.createElementNS(SVG_NS,tag);for(const [key,value]of Object.entries(attributes))node.setAttribute(key,value);return node;};
 const create=id=>{
  const node=element('g',{'data-region':id,role:'button',tabindex:'0'}),title=element('title');
  const hit=element('ellipse',{class:'marker-hit-target',fill:'transparent'});
  const halo=element('circle',{class:'halo'}),pulse=element('circle',{class:'pulse'});
  const ring=element('circle',{class:'selected-ring'}),core=element('circle',{class:'core'});
  const rect=element('rect',{class:'region-marker-label',rx:'3'}),text=element('text',{class:'region-marker-label'});
  // Only this fixed hit area participates in pointer targeting. Pulsing circles, focus
  // rings and labels must not change the hovered element as their painted bounds change.
  node.style.pointerEvents='none';hit.style.pointerEvents='all';
  for(const decoration of [halo,pulse,ring,core,rect,text])decoration.style.pointerEvents='none';
  node.append(title,hit,halo,pulse,ring,core,rect,text);group.append(node);
  const record={node,title,hit,halo,pulse,ring,core,rect,text,measurement:null};nodes.set(id,record);return record;
 };
 const measure=record=>{
  const style=view?.getComputedStyle(record.text);
  const key=[record.text.textContent,style?.fontFamily,style?.fontSize,style?.fontWeight,style?.letterSpacing].join('|');
  if(record.measurement?.key===key)return record.measurement;
  record.text.setAttribute('x','0');record.text.setAttribute('y','0');
  let box,advance;
  try{box=record.text.getBBox();advance=record.text.getComputedTextLength();}catch{/* Hidden SVGs and DOM test environments may not expose geometry. */}
  const usable=box&&finite(box.width)&&box.width>0&&finite(box.height)&&box.height>0;
  const size=parseFloat(style?.fontSize)||11;
  // Never cache the fallback: a hidden map or a font still loading must be measured again.
  const measurement={key,x:usable?box.x:0,y:usable?box.y:-size*.8,width:usable?box.width:finite(advance)&&advance>0?advance:record.text.textContent.length*size*.65,height:usable?box.height:size};
  if(usable)record.measurement=measurement;
  return measurement;
 };
 const update=options=>{
  if(destroyed)return [];
  latest=options;
  const {regions,events,selectedRegion,rotation,zoom}=options;
  const bounds=options.bounds||viewportBounds(svg),scale=screenScale(svg);
  // Labels use CSS-pixel sizes even when a narrow screen scales the SVG viewBox down.
  const paddingX=8/scale.x,paddingY=8/scale.y;
  const counts=new Map();for(const event of events)counts.set(event.region,(counts.get(event.region)||0)+1);
  const present=new Set(),visible=[];
  for(const [index,region]of regions.entries()){
   if(!finite(region.lon)||!finite(region.lat))continue;
   present.add(region.id);const record=nodes.get(region.id)||create(region.id);
   const count=counts.get(region.id)||0,selected=region.id===selectedRegion;
   const radius=count?6+Math.sqrt(count)*3:4,[x,y,front]=project(region.lon,region.lat,rotation,zoom);
   const shown=front>0&&x>=bounds.x&&x<=bounds.x+bounds.width&&y>=bounds.y&&y<=bounds.y+bounds.height;
   record.node.setAttribute('class',`marker${count?'':' no-events'}${selected?' selected':''}`);
   record.node.setAttribute('transform',`translate(${x.toFixed(2)},${y.toFixed(2)})`);
   record.node.setAttribute('aria-label',`${region.name} 리전, ${count}건`);
   record.node.setAttribute('tabindex',shown?'0':'-1');
   record.node.setAttribute('aria-hidden',shown?'false':'true');
   record.node.style.display=shown?'':'none';
   const title=`${region.name} · ${region.id} · ${count}건`,label=`${region.en||region.name} · ${count}`;
   if(record.title.textContent!==title)record.title.textContent=title;
   if(record.text.textContent!==label)record.text.textContent=label;
   record.text.style.fontSize=`${11/scale.y}px`;
   record.text.style.letterSpacing=`${.2/scale.x}px`;
   record.hit.setAttribute('rx',10/scale.x);record.hit.setAttribute('ry',10/scale.y);
   record.halo.setAttribute('r',radius*1.45);record.pulse.setAttribute('r',radius);
   record.pulse.style.animationDelay=`-${index*.4}s`;
   record.ring.setAttribute('r',selected?'8':'5');record.core.setAttribute('r',count?'3.5':'2');
   if(shown)visible.push({id:region.id,record,x,y,radius});
  }
  for(const [id,record]of nodes)if(!present.has(id)){record.node.remove();nodes.delete(id);}
  const placed=[];
  for(const item of visible){
   const {record,x,y}=item,m=measure(record),width=m.width+paddingX*2,height=Math.max(22/scale.y,m.height+paddingY);
   // Labels always stay above their own marker. Do not flip or clamp them around
   // neighbors, overlays or viewport edges; CSS controls selected/hover/focus visibility.
   const gap=Math.max(item.radius*1.45,8)+6/scale.y;
   const left=-width/2,top=-height-gap;
   record.rect.setAttribute('x',left.toFixed(2));record.rect.setAttribute('y',top.toFixed(2));
   record.rect.setAttribute('width',width.toFixed(2));record.rect.setAttribute('height',height.toFixed(2));
   // Center the actual glyph bounds, including their side bearings and baseline offset.
   record.text.setAttribute('x',(left+paddingX-m.x).toFixed(2));
   record.text.setAttribute('y',(top+(height-m.height)/2-m.y).toFixed(2));
   placed.push({id:item.id,x:x+left,y:y+top,width,height});
  }
  return placed;
 };
 const fonts=()=>{for(const record of nodes.values())record.measurement=null;if(latest)update(latest);};
 document.fonts?.addEventListener('loadingdone',fonts);
 return {update,destroy(){destroyed=true;document.fonts?.removeEventListener('loadingdone',fonts);for(const record of nodes.values())record.node.remove();nodes.clear();latest=null;}};
}

/** A new camera request and direct user manipulation both invalidate older animation frames. */
export function createCameraController(get,set,options={}){
 const view=globalThis.window||globalThis;
 const request=options.requestFrame||view.requestAnimationFrame?.bind(view)||globalThis.requestAnimationFrame?.bind(globalThis)||((callback)=>setTimeout(()=>callback(now()),16));
 const cancelFrame=options.cancelFrame||view.cancelAnimationFrame?.bind(view)||globalThis.cancelAnimationFrame?.bind(globalThis)||clearTimeout;
 const now=options.now||(()=>view.performance?.now()??Date.now());
 let frame=null,generation=0;
 const cancel=()=>{generation++;if(frame!==null)cancelFrame(frame);frame=null;};
 const animateTo=(targetRotation,targetZoom,duration=650)=>{
  cancel();const current=generation,start=get(),rotation=[...start.rotation],zoom=start.zoom;
  const target=[wrapLon(targetRotation[0]),clampPhi(targetRotation[1])],endZoom=clamp(targetZoom,ZOOM_MIN,ZOOM_MAX);
  const reduced=typeof options.reducedMotion==='function'?options.reducedMotion():options.reducedMotion;
  if(reduced||!finite(duration)||duration<=0){set({rotation:target,zoom:endZoom});return;}
  const started=now(),longitude=wrapLon(target[0]-rotation[0]),latitude=target[1]-rotation[1];
  const step=time=>{
   if(current!==generation)return;
   frame=null;const t=clamp((time-started)/duration,0,1),ease=t<.5?2*t*t:1-Math.pow(-2*t+2,2)/2;
   set({rotation:t===1?target:[wrapLon(rotation[0]+longitude*ease),clampPhi(rotation[1]+latitude*ease)],zoom:zoom+(endZoom-zoom)*ease});
   if(t<1&&current===generation)frame=request(step);
  };
  frame=request(step);
 };
 return {animateTo,cancel};
}
