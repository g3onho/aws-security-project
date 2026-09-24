import test from 'node:test';
import assert from 'node:assert/strict';
import {JSDOM} from './dom-test-support.mjs';
import {animateLayout} from '../static/js/ui/components/layout-motion.js';

function fixture(t,html='<section class="panel" data-height="100"><div class="content"><canvas></canvas></div></section>'){
 const dom=new JSDOM(`<style>.panel{box-sizing:border-box}</style><main>${html}</main>`,{pretendToBeVisual:true});
 const {document}=dom.window,calls=[],current=new Map(),root=document.querySelector('main');
 const install=node=>{
  node.getBoundingClientRect=()=>({x:0,y:0,left:0,top:0,right:200,bottom:current.get(node)?.height??(Number(node.dataset.height)||0),width:200,height:current.get(node)?.height??(Number(node.dataset.height)||0)});
  node.getClientRects=()=>node.isConnected&&!node.closest('[hidden]')&&node.style.display!=='none'?[node.getBoundingClientRect()]:[];
  node.animate=(frames,options)=>{
   const from=parseFloat(frames[0].height),to=parseFloat(frames[1].height),extra=Number(node.dataset.extra)||0;
   const animation={onfinish:null,oncancel:null,cancelled:false,
    progress(value){if(current.get(node)?.animation===animation)current.set(node,{animation,height:from+(to-from)*value+extra});},
    finish(){if(current.get(node)?.animation===animation)current.delete(node);animation.onfinish?.();},
    cancel(){animation.cancelled=true;if(current.get(node)?.animation===animation)current.delete(node);animation.oncancel?.();},
   };
   calls.push({node,frames,options,animation});current.set(node,{animation,height:from+extra});return animation;
  };
  return node;
 };
 [root,...root.querySelectorAll('*')].forEach(install);
 t.after(()=>{calls.forEach(call=>call.animation.finish());dom.window.close();});
 return {dom,document,root,calls,install,panel:root.querySelector('.panel')};
}

test('API content update animates the containing card height without replacing canvas, focus or scroll state',t=>{
 const f=fixture(t,'<section class="panel" data-height="100"><div class="content"><input><canvas></canvas></div></section>');
 const content=f.panel.querySelector('.content'),canvas=content.querySelector('canvas'),input=content.querySelector('input');
 input.focus();content.scrollTop=30;canvas.chartInstance={id:7};let resizeEvents=0;
 f.dom.window.addEventListener('resize',()=>resizeEvents++);
 const result=animateLayout(content,()=>{f.panel.dataset.height='180';return 'rendered';});
 assert.equal(result,'rendered');assert.equal(f.calls.length,1);assert.equal(f.calls[0].node,f.panel);
 assert.deepEqual(f.calls[0].frames,[{height:'100px'},{height:'180px'}]);
 assert.equal(f.calls[0].options.fill,'none');assert.equal(f.panel.style.height,'');assert.equal(f.panel.style.overflow,'clip');
 assert.equal(content.querySelector('canvas'),canvas);assert.equal(canvas.chartInstance.id,7);
 assert.equal(f.document.activeElement,input);assert.equal(content.scrollTop,30);assert.equal(resizeEvents,0);
 f.calls[0].animation.finish();assert.equal(f.panel.style.height,'');assert.equal(f.panel.style.overflow,'');
});

test('a wrapper animates only top-level panels and avoids nested parent/child height effects',t=>{
 const f=fixture(t,'<section class="panel outer" data-height="100"><section class="panel nested" data-height="40"></section></section><section class="panel sibling" data-height="70"></section>');
 const outer=f.root.querySelector('.outer'),nested=f.root.querySelector('.nested'),sibling=f.root.querySelector('.sibling');
 animateLayout(f.root,()=>{outer.dataset.height='150';nested.dataset.height='80';sibling.dataset.height='110';});
 assert.deepEqual(f.calls.map(call=>call.node),[outer,sibling]);
});

test('a wrapper without panels animates itself and subsequent child updates resume the same parent',t=>{
 const f=fixture(t,'<div class="wrapper" data-height="40"></div>'),wrapper=f.root.firstElementChild;
 let child;
 animateLayout(wrapper,()=>{child=f.install(f.document.createElement('section'));child.className='panel';child.dataset.height='100';wrapper.append(child);wrapper.dataset.height='120';});
 const first=f.calls[0];assert.equal(first.node,wrapper);first.animation.progress(.5);
 animateLayout(child,()=>{child.dataset.height='180';wrapper.dataset.height='200';});
 assert.equal(first.animation.cancelled,true);assert.equal(f.calls.length,2);assert.equal(f.calls[1].node,wrapper);
 assert.deepEqual(f.calls[1].frames,[{height:'80px'},{height:'200px'}]);
});

test('a parent update cancels an existing child animation before measuring the natural target',t=>{
 const f=fixture(t,'<section class="panel parent" data-height="160"><section class="panel child" data-height="80"></section></section>');
 const child=f.root.querySelector('.child');
 animateLayout(child,()=>{child.dataset.height='120';});const first=f.calls[0];first.animation.progress(.5);
 animateLayout(f.panel,()=>{f.panel.dataset.height='240';});
 assert.equal(first.animation.cancelled,true);assert.equal(f.calls[1].node,f.panel);assert.equal(child.style.overflow,'');
});

test('a rapid replacement response restarts at the presented height and ignores an old finish callback',t=>{
 const f=fixture(t),style=f.panel.style;
 // jsdom's CSSStyleDeclaration drops shorthand overflow priorities. Supply the
 // standard browser CSSOM behavior so this test also covers !important restoration.
 const set=style.setProperty.bind(style),get=style.getPropertyPriority.bind(style),remove=style.removeProperty.bind(style);
 let priority='';
 style.setProperty=(name,value,importance='')=>{if(name==='overflow')priority=importance;set(name,value,importance);};
 style.getPropertyPriority=name=>name==='overflow'?priority:get(name);
 style.removeProperty=name=>{if(name==='overflow')priority='';return remove(name);};
 style.setProperty('overflow','visible','important');
 animateLayout(f.panel,()=>{f.panel.dataset.height='200';});const first=f.calls[0],staleFinish=first.animation.onfinish;
 first.animation.progress(.6);
 animateLayout(f.panel,()=>{f.panel.dataset.height='80';});const second=f.calls[1];
 assert.equal(first.animation.cancelled,true);assert.deepEqual(second.frames,[{height:'160px'},{height:'80px'}]);
 staleFinish();assert.equal(f.panel.style.overflow,'clip');assert.equal(f.panel.style.getPropertyPriority('overflow'),'important');
 second.animation.finish();assert.equal(f.panel.style.overflow,'visible');assert.equal(f.panel.style.getPropertyPriority('overflow'),'important');
});

test('content-box heights account for border and padding while preserving inline height declarations',t=>{
 const f=fixture(t);f.panel.style.cssText='box-sizing:content-box;padding:10px;border:2px solid;height:auto';f.panel.dataset.extra='24';
 animateLayout(f.panel,()=>{f.panel.dataset.height='200';});
 assert.deepEqual(f.calls[0].frames,[{height:'76px'},{height:'176px'}]);
 f.calls[0].animation.finish();assert.equal(f.panel.style.height,'auto');assert.equal(f.panel.style.padding,'10px');
});

test('existing scroll/clipping styles and styles changed by the caller survive completion or external cancellation',t=>{
 const f=fixture(t);f.panel.style.overflow='auto';
 animateLayout(f.panel,()=>{f.panel.dataset.height='150';});assert.equal(f.panel.style.overflow,'auto');
 f.calls[0].animation.cancel();assert.equal(f.panel.style.overflow,'auto');
 f.panel.style.removeProperty('overflow');
 animateLayout(f.panel,()=>{f.panel.dataset.height='200';});assert.equal(f.panel.style.overflow,'clip');
 f.panel.style.overflow='hidden';f.calls[1].animation.finish();assert.equal(f.panel.style.overflow,'hidden');
});

test('reduced motion respects system preference and cancels a running effect before the next render',t=>{
 const f=fixture(t);animateLayout(f.panel,()=>{f.panel.dataset.height='180';});const first=f.calls[0];
 f.dom.window.matchMedia=()=>({matches:true});
 animateLayout(f.panel,()=>{f.panel.dataset.height='220';});
 assert.equal(first.animation.cancelled,true);assert.equal(f.calls.length,1);assert.equal(f.panel.style.overflow,'');
 animateLayout(f.panel,()=>{f.panel.dataset.height='240';},{reducedMotion:()=>true});assert.equal(f.calls.length,1);
});

test('unsupported, hidden, detached, equal-height and zero-duration updates still render without animation',t=>{
 const f=fixture(t);
 const cases=[
  {prepare:()=>{f.panel.animate=undefined;},options:{}},
  {prepare:()=>{f.install(f.panel);f.panel.hidden=true;},options:{}},
  {prepare:()=>{f.panel.hidden=false;f.panel.remove();},options:{}},
  {prepare:()=>{f.root.append(f.panel);},options:{duration:0}},
 ];
 for(const {prepare,options}of cases){prepare();const height=Number(f.panel.dataset.height)+20;assert.equal(animateLayout(f.panel,()=>{f.panel.dataset.height=String(height);return height;},options),height);}
 animateLayout(f.panel,()=>{});assert.equal(f.calls.length,0);
});

test('animation API failure and rendering exceptions restore temporary styles and propagate render errors',t=>{
 const f=fixture(t);f.panel.animate=()=>{throw new Error('unsupported keyframes');};
 assert.equal(animateLayout(f.panel,()=>{f.panel.dataset.height='150';return 7;}),7);assert.equal(f.panel.style.overflow,'');
 f.install(f.panel);animateLayout(f.panel,()=>{f.panel.dataset.height='200';});
 assert.throws(()=>animateLayout(f.panel,()=>{throw new Error('render failed');}),/render failed/);
 assert.equal(f.calls[0].animation.cancelled,true);assert.equal(f.panel.style.overflow,'');
});
