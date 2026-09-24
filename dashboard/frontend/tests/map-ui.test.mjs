import test from 'node:test';
import assert from 'node:assert/strict';
import {JSDOM} from './dom-test-support.mjs';
import {createMarkerLayer,createCameraController} from '../static/js/ui/map/interaction.js';
import {bindMapInteraction,mapPoint,project} from '../static/js/ui/map/globe.js';

function fixture({width=1000,height=460,aspect='xMidYMid meet'}={}){
 const dom=new JSDOM(`<style>.marker text{font-size:11px;letter-spacing:.2px}.region-marker-label{opacity:0;pointer-events:none}.marker.selected .region-marker-label,.marker:hover .region-marker-label,.marker:focus .region-marker-label{opacity:1}</style><svg tabindex="0" viewBox="0 0 1000 460" preserveAspectRatio="${aspect}"><g id="markers"></g></svg>`,{pretendToBeVisual:true});
 const {document}=dom.window,svg=document.querySelector('svg'),group=document.querySelector('g');
 svg.getBoundingClientRect=()=>({left:0,top:0,right:width,bottom:height,width,height});
 const captures=new Set();let captureCount=0;
 svg.setPointerCapture=id=>{captures.add(id);captureCount++;};
 svg.hasPointerCapture=id=>captures.has(id);svg.releasePointerCapture=id=>captures.delete(id);
 dom.window.SVGElement.prototype.getBBox=function(){
  const style=dom.window.getComputedStyle(this),size=parseFloat(style.fontSize)||11;
  const width=[...this.textContent].reduce((sum,char)=>sum+(char==='W'?10:char==='i'?2:6),0)*size/11*(style.fontWeight==='700'?1.1:1);
  return {x:(Number(this.getAttribute('x'))||0)-1.5*size/11,y:(Number(this.getAttribute('y'))||0)-8*size/11,width,height:size};
 };
 dom.window.SVGElement.prototype.getComputedTextLength=function(){return this.getBBox().width;};
 const pointer=(type,{target=svg,id=1,x=100,y=100,button=0,detail=1,isPrimary=true}={})=>{
  const event=new dom.window.MouseEvent(type,{bubbles:true,cancelable:true,clientX:x,clientY:y,button,detail});
  Object.defineProperties(event,{pointerId:{value:id},isPrimary:{value:isPrimary}});target.dispatchEvent(event);return event;
 };
 return {dom,document,svg,group,pointer,get captureCount(){return captureCount;}};
}
const region=(id,en,lon=0,lat=0)=>({id,name:en,en,lon,lat});
const options=regions=>({regions,events:[],selectedRegion:regions[0]?.id,rotation:[0,0],zoom:1});
const approximate=(actual,expected)=>assert.ok(Math.abs(actual-expected)<.02,`${actual} ~= ${expected}`);

test('marker label measures actual glyph bounds with equal padding, including side bearings',()=>{
 const {group}=fixture(),layer=createMarkerLayer(group);
 layer.update(options([region('wide','WWWW'),region('narrow','iiii',20)]));
 const markers=[...group.children];
 for(const marker of markers){
  const rect=marker.querySelector('rect'),text=marker.querySelector('text'),glyph=text.getBBox();
  approximate(glyph.x-Number(rect.getAttribute('x')),8);
  approximate(Number(rect.getAttribute('x'))+Number(rect.getAttribute('width'))-(glyph.x+glyph.width),8);
  approximate(glyph.y-Number(rect.getAttribute('y')),Number(rect.getAttribute('y'))+Number(rect.getAttribute('height'))-(glyph.y+glyph.height));
 }
 assert.ok(Number(markers[0].querySelector('rect').getAttribute('width'))>Number(markers[1].querySelector('rect').getAttribute('width')));
});

test('camera and count updates preserve focused marker and text nodes, including hidden hemisphere roundtrip',()=>{
 const {group,document}=fixture(),layer=createMarkerLayer(group),input=options([region('a','Seoul')]);
 layer.update(input);const marker=group.firstElementChild,text=marker.querySelector('text');marker.focus();
 layer.update({...input,events:[{region:'a'}],rotation:[5,0]});
 assert.equal(group.firstElementChild,marker);assert.equal(marker.querySelector('text'),text);assert.equal(document.activeElement,marker);
 assert.equal(text.textContent,'Seoul · 1');
 layer.update({...input,rotation:[180,0]});assert.equal(marker.style.display,'none');assert.equal(marker.getAttribute('tabindex'),'-1');
 layer.update(input);assert.equal(group.firstElementChild,marker);assert.equal(marker.style.display,'');assert.equal(marker.getAttribute('tabindex'),'0');
});

test('neighboring and edge labels always stay centered directly above their own markers',()=>{
 const {group}=fixture(),layer=createMarkerLayer(group);
 const input={...options([region('a','Northern Virginia',45,0),region('b','Washington State',45.1,0),region('c','US West California',45.2,0)]),zoom:1.7};
 const result=layer.update(input);
 assert.equal(result.length,3);
 for(const [index,box]of result.entries()){
  const [x,y]=project(input.regions[index].lon,input.regions[index].lat,input.rotation,input.zoom);
  approximate(box.x+box.width/2,x);assert.ok(box.y+box.height<y);
 }
 assert.deepEqual(layer.update({...input,selectedRegion:'c',obstacles:[{x:0,y:0,width:1000,height:460}]}),result,'Selection and overlays cannot move labels to alternate positions');
});

test('labels remeasure after typography changes without losing above-center alignment',()=>{
 const {group,document}=fixture(),layer=createMarkerLayer(group),input=options([region('a','WWWW')]);
 const [first]=layer.update(input);
 document.querySelector('style').textContent='.marker text{font-weight:700}';
 const [second]=layer.update(input);assert.ok(second.width>first.width);
 approximate(first.x+first.width/2,500);approximate(second.x+second.width/2,500);
 approximate(first.y+first.height,second.y+second.height);
});

test('mobile and desktop SVG scales keep labels at 11px type, .2px spacing, 8px padding and 22px height',()=>{
 const {group,svg}=fixture(),layer=createMarkerLayer(group),input=options([region('a','Seoul')]);
 let marker,previousWidth;
 for(const scale of [.337,.738,1.2]){
  svg.getBoundingClientRect=()=>({left:0,top:0,right:1000*scale,bottom:460*scale,width:1000*scale,height:460*scale});
  svg.getScreenCTM=()=>({a:scale,b:0,c:0,d:scale,inverse:()=>({a:1/scale,b:0,c:0,d:1/scale,e:0,f:0})});
  const [box]=layer.update(input);
  marker??=group.firstElementChild;assert.equal(group.firstElementChild,marker);
  const text=marker.querySelector('text'),rect=marker.querySelector('rect'),glyph=text.getBBox();
  approximate(parseFloat(text.style.fontSize)*scale,11);
  approximate(parseFloat(text.style.letterSpacing)*scale,.2);
  approximate((glyph.x-Number(rect.getAttribute('x')))*scale,8);
  approximate((Number(rect.getAttribute('x'))+Number(rect.getAttribute('width'))-(glyph.x+glyph.width))*scale,8);
  approximate(Number(rect.getAttribute('height'))*scale,22);
  if(previousWidth)approximate(box.width*scale,previousWidth);
  previousWidth=box.width*scale;
  assert.ok(box.x*scale>=7.99);assert.ok((box.x+box.width)*scale<=1000*scale-7.99);
 }
});

test('hidden SVGs with no usable screen transform retain finite default label dimensions',()=>{
 const {group,svg}=fixture(),layer=createMarkerLayer(group),input=options([region('a','Seoul')]);
 for(const matrix of [null,{a:0,b:0,c:0,d:0}]){
  svg.getScreenCTM=()=>matrix;layer.update(input);
  const text=group.querySelector('text'),rect=group.querySelector('rect');
  assert.equal(text.style.fontSize,'11px');assert.equal(text.style.letterSpacing,'0.2px');
  assert.ok(Number.isFinite(Number(rect.getAttribute('width'))));
 }
});

test('slice viewport hides offscreen markers without shifting visible marker labels inward',()=>{
 const {group}=fixture({width:400,height:460,aspect:'xMidYMid slice'}),layer=createMarkerLayer(group);
 const input=options([region('a','Long Western Region',-24),region('b','Long Eastern Region',24),region('outside','Offscreen',60)]);
 const boxes=layer.update(input);
 assert.equal(boxes.length,2);
 for(const [index,box]of boxes.entries())approximate(box.x+box.width/2,project(input.regions[index].lon,0,input.rotation,input.zoom)[0]);
 assert.equal(group.children[2].style.display,'none');
});

test('labels at the top edge remain above the marker instead of flipping below it',()=>{
 const {group}=fixture(),layer=createMarkerLayer(group),input=options([region('top','Near top edge',0,35)]);
 const [box]=layer.update(input),[,y]=project(0,35,input.rotation,input.zoom);
 assert.ok(y>0);assert.ok(box.y<0,'Natural viewport clipping is preferred over moving a label below its marker');
 assert.ok(box.y+box.height<y);approximate(box.x+box.width/2,500);
});

test('hundreds of hover and focus transitions never move, rewrite or hide stationary map labels',()=>{
 const {group,pointer,dom,document}=fixture(),layer=createMarkerLayer(group);
 const input=options([region('seoul','SEOUL'),region('tokyo','TOKYO',.5),region('osaka','OSAKA',1)]);
 const initial=layer.update(input),markers=[...group.children],osaka=markers[2];
 const geometry=()=>markers.map(marker=>({transform:marker.getAttribute('transform'),rect:[...marker.querySelector('rect').attributes].map(attr=>[attr.name,attr.value]),text:[...marker.querySelector('text').attributes].map(attr=>[attr.name,attr.value])}));
 const before=geometry(),observer=new dom.window.MutationObserver(()=>{});
 observer.observe(group,{subtree:true,attributes:true,childList:true,characterData:true});
 for(let index=0;index<300;index++){
  pointer('pointerover',{target:osaka.querySelector('.marker-hit-target')});
  osaka.focus();
  pointer('pointerout',{target:osaka.querySelector('.marker-hit-target')});
  markers[index%2].focus();
  assert.equal(osaka.style.display,'');
 }
 assert.deepEqual(observer.takeRecords(),[],'Hover/focus must not write SVG attributes or replace nodes');
 assert.deepEqual(geometry(),before);assert.deepEqual([...group.children],markers);
 osaka.focus();assert.equal(document.activeElement,osaka);
 // jsdom does not invalidate cached computed styles on :focus changes; assert the
 // pseudo-class and absence of a JS visibility override. Browser QA checks rendering.
 assert.equal(osaka.matches(':focus'),true);assert.equal(osaka.querySelector('text').style.opacity,'');
 assert.equal(dom.window.getComputedStyle(markers[0].querySelector('text')).opacity,'1','Selected label stays visible while another label is focused');
 assert.deepEqual(layer.update(input),initial,'Identical map input must ignore current focus');
 assert.deepEqual(geometry(),before);
 observer.disconnect();layer.destroy();assert.equal(group.children.length,0);assert.deepEqual(layer.update(input),[]);
});

test('only a fixed screen-size hit area participates in marker pointer targeting',()=>{
 const {group,svg}=fixture(),layer=createMarkerLayer(group),input=options([region('osaka','OSAKA')]),scale=.337;
 svg.getScreenCTM=()=>({a:scale,b:0,c:0,d:scale,inverse:()=>({a:1/scale,b:0,c:0,d:1/scale,e:0,f:0})});
 layer.update(input);const marker=group.firstElementChild,hit=marker.querySelector('.marker-hit-target');
 assert.equal(marker.style.pointerEvents,'none');assert.equal(hit.style.pointerEvents,'all');
 approximate(Number(hit.getAttribute('rx'))*scale,10);approximate(Number(hit.getAttribute('ry'))*scale,10);
 for(const decoration of marker.querySelectorAll('.halo,.pulse,.selected-ring,.core,.region-marker-label'))assert.equal(decoration.style.pointerEvents,'none');
 const radius=hit.getAttribute('rx');
 layer.update({...input,events:Array.from({length:20},()=>({region:'osaka'}))});
 assert.equal(hit.getAttribute('rx'),radius,'Event count/pulse radius cannot change hover hit area');
});

function clockCamera(extra={}){
 let state={rotation:[170,0],zoom:1},clock=0,nextId=1;const frames=new Map(),allFrames=new Map(),writes=[];
 const camera=createCameraController(()=>state,value=>{state=value;writes.push(value);},{now:()=>clock,requestFrame:callback=>{const id=nextId++;frames.set(id,callback);allFrames.set(id,callback);return id;},cancelFrame:id=>frames.delete(id),...extra});
 return {camera,frames,allFrames,writes,get state(){return state;},advance(time){clock=time;const pending=[...frames.values()];frames.clear();pending.forEach(callback=>callback(time));}};
}

test('new camera animation invalidates stale frames and finishes along the shortest longitude path',()=>{
 const clock=clockCamera();clock.camera.animateTo([-170,20],2,100);const stale=[...clock.allFrames.values()][0];
 clock.advance(50);approximate(clock.state.rotation[0],-180);approximate(clock.state.rotation[1],10);
 clock.camera.animateTo([30,10],1.5,100);const before=clock.writes.length;stale(90);assert.equal(clock.writes.length,before);
 clock.advance(150);assert.deepEqual(clock.state,{rotation:[30,10],zoom:1.5});assert.equal(clock.frames.size,0);
});

test('direct cancellation stops queued camera callbacks; reduced motion applies one bounded update',()=>{
 const clock=clockCamera();clock.camera.animateTo([10,10],2);const stale=[...clock.allFrames.values()][0];
 clock.camera.cancel();stale(650);assert.equal(clock.writes.length,0);assert.equal(clock.frames.size,0);
 const reduced=clockCamera({reducedMotion:()=>true});reduced.camera.animateTo([190,90],9);
 assert.deepEqual(reduced.state,{rotation:[-170,80],zoom:3.2});assert.equal(reduced.frames.size,0);assert.equal(reduced.writes.length,1);
});

test('responsive drag uses SVG coordinates and captures once, while foreign pointers cannot end the drag',()=>{
 const f=fixture({width:500,height:230});let state={rotation:[0,0],zoom:1},interactions=0;
 const binding=bindMapInteraction(f.svg,()=>state,value=>state=value,{onInteraction:()=>interactions++});
 f.pointer('pointerdown',{x:100,y:100});f.pointer('pointermove',{x:150,y:100});
 approximate(state.rotation[0],-100/380*180/Math.PI);assert.equal(f.captureCount,1);
 f.pointer('pointerup',{id:2});f.pointer('pointermove',{x:160,y:100});
 approximate(state.rotation[0],-120/380*180/Math.PI);assert.equal(f.captureCount,1);assert.equal(interactions,1);
 f.pointer('pointerup');assert.equal(f.svg.classList.contains('dragging'),false);binding.destroy();
});

test('a completed drag suppresses its delayed click but permits the next click and keyboard activation',async()=>{
 const f=fixture();let state={rotation:[0,0],zoom:1},clicks=0;
 const binding=bindMapInteraction(f.svg,()=>state,value=>state=value);f.svg.addEventListener('click',()=>clicks++);
 f.pointer('pointerdown');f.pointer('pointermove',{x:130});f.pointer('pointerup',{x:130});
 await new Promise(resolve=>setTimeout(resolve,5));assert.equal(f.pointer('click',{x:130}).defaultPrevented,true);assert.equal(clicks,0);
 f.pointer('pointerdown');f.pointer('pointerup');f.pointer('click');assert.equal(clicks,1);
 f.pointer('pointerdown');f.pointer('pointermove',{x:130});f.pointer('pointerup');f.pointer('click',{detail:0});assert.equal(clicks,2);binding.destroy();
});

test('ordinary marker clicks do not capture; wheel and arrow interactions cancel camera movement; destroy unbinds',()=>{
 const f=fixture();let state={rotation:[0,0],zoom:1},changes=0,interactions=0;
 const binding=bindMapInteraction(f.svg,()=>state,value=>{state=value;changes++;},{onInteraction:()=>interactions++});
 f.pointer('pointerdown');f.pointer('pointerup');assert.equal(f.captureCount,0);
 f.svg.dispatchEvent(new f.dom.window.WheelEvent('wheel',{deltaY:-100,bubbles:true,cancelable:true}));assert.ok(state.zoom>1);
 f.svg.dispatchEvent(new f.dom.window.KeyboardEvent('keydown',{key:'ArrowRight',bubbles:true,cancelable:true}));assert.ok(state.rotation[0]>0);assert.equal(interactions,3);
 binding.destroy();f.pointer('pointerdown');f.pointer('pointermove',{x:200});assert.equal(changes,2);
});

test('mapPoint handles screen transforms and centered letterboxing without a browser geometry API',()=>{
 const {svg}=fixture({width:500,height:500});
 assert.deepEqual(mapPoint(svg,250,250),[500,230]);
 svg.getScreenCTM=()=>({inverse:()=>({a:2,b:0,c:0,d:2,e:-20,f:-40})});
 assert.deepEqual(mapPoint(svg,100,100),[180,160]);
});
