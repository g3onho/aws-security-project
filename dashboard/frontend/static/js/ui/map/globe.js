// v2.1: rotating orthographic globe projection — drag-to-rotate, wheel/button zoom, and
// great-circle (shortest-path) attack arcs rendered with a slight altitude lift so they read
// as arcs over the globe surface rather than flat lines. Replaces the v2.0 flat "2.5D overview"
// projection. This is a hand-rolled, dependency-free implementation (no D3/WebGL): country and
// attack-line paths are clipped to the front hemisphere per-point (not true spherical polygon
// clipping), which is a deliberate simplification for the dashboard — edges right at the
// horizon can show a minor straight-line seam.
const CX=500, CY=230, BASE_R=380, D2R=Math.PI/180, PHI_LIMIT=80;
export const ZOOM_MIN=1, ZOOM_MAX=3.2, DEFAULT_ZOOM=1, REGION_ZOOM=2.6; // v2.2.1: default view now 1.0x (user request) -- the globe rim is visible at this zoom, which is expected
export const DEFAULT_ROTATION=[126.978,37.566]; // v2.2.1: centered exactly on Seoul (ap-northeast-2), not just "Korea-ish" East Asia

export function wrapLon(lon){return((lon+180)%360+360)%360-180;}
export function clampPhi(phi){return Math.max(-PHI_LIMIT,Math.min(PHI_LIMIT,phi));}

// Orthographic projection of (lon,lat) given the current view rotation [lambda0,phi0] (degrees)
// and zoom. altScale (default 1) lifts a point slightly off the sphere's surface — used only for
// attack arcs. Returns [x, y, cosc]; cosc>0 means the point faces the viewer (front hemisphere).
export function project(lon,lat,rotation,zoom,altScale=1){
 const [lambda0,phi0]=rotation;
 const λ=(lon-lambda0)*D2R, φ=lat*D2R, φ0=phi0*D2R;
 const R=BASE_R*zoom*altScale;
 const cosc=Math.sin(φ0)*Math.sin(φ)+Math.cos(φ0)*Math.cos(φ)*Math.cos(λ);
 const x=CX+R*Math.cos(φ)*Math.sin(λ);
 const y=CY-R*(Math.cos(φ0)*Math.sin(φ)-Math.sin(φ0)*Math.cos(φ)*Math.cos(λ));
 return [x,y,cosc];
}

// Builds a (possibly multi-segment) SVG path from a lon/lat ring, breaking the path wherever it
// crosses to the far side of the globe (front-only clip, see file header).
export function ringPath(ring,rotation,zoom,close=true){
 let d='',open=false;
 for(const p of ring){
  const [x,y,vis]=project(p[0],p[1],rotation,zoom);
  if(vis>0){d+=(open?'L':'M')+x.toFixed(2)+','+y.toFixed(2);open=true;}else open=false;
 }
 return d?(close?d+'Z':d):'';
}
export function polygonPath(coords,rotation,zoom){
 return coords.map(ring=>ringPath(ring,rotation,zoom)).join('');
}

export function globeArtwork(rotation,zoom){
 const R=BASE_R*zoom;
 const lines=[];
 // Sample the graticule densely so each parallel and meridian follows the
 // orthographic sphere smoothly instead of looking like a faceted polygon.
 for(let lat=-75;lat<=75;lat+=15){const pts=[];for(let lon=-180;lon<=180;lon+=2)pts.push([lon,lat]);lines.push(ringPath(pts,rotation,zoom,false));}
 for(let lon=-165;lon<=165;lon+=15){const pts=[];for(let lat=-90;lat<=90;lat+=2)pts.push([lon,lat]);lines.push(ringPath(pts,rotation,zoom,false));}
 return {
  base:`<defs><radialGradient id="ocean-depth" cx="43%" cy="36%" r="68%"><stop offset="0" stop-color="#25332e"/><stop offset=".65" stop-color="#19251f"/><stop offset="1" stop-color="#0c1511"/></radialGradient><radialGradient id="surface-shade" cx="43%" cy="36%" r="66%"><stop offset=".25" stop-color="#7fb49a" stop-opacity=".03"/><stop offset=".75" stop-color="#020c07" stop-opacity=".02"/><stop offset="1" stop-color="#020c07" stop-opacity=".55"/></radialGradient><marker id="attack-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0 10 5 0 10Z" fill="#e7a064"/></marker><marker id="attack-arrow-sample" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0 0 10 5 0 10Z" fill="#8fb3ff"/></marker></defs><circle class="globe-rim" cx="${CX}" cy="${CY}" r="${R.toFixed(2)}" fill="url(#ocean-depth)"/><g class="graticule">${lines.filter(Boolean).map(d=>`<path d="${d}"/>`).join('')}</g>`,
  shade:`<circle cx="${CX}" cy="${CY}" r="${R.toFixed(2)}" fill="url(#surface-shade)" pointer-events="none"/>`
 };
}

// Use the SVG's screen transform: CSS pixels and viewBox units differ on smaller screens.
export function mapPoint(svg,clientX,clientY){
 try{
  const inverse=svg.getScreenCTM()?.inverse();
  if(inverse)return [inverse.a*clientX+inverse.c*clientY+inverse.e,inverse.b*clientX+inverse.d*clientY+inverse.f];
 }catch{/* Detached/hidden SVGs can have no invertible screen transform. */}
 const rect=svg.getBoundingClientRect(),box=svg.viewBox?.baseVal;
 const [x,y,width,height]=box?.width?[box.x,box.y,box.width,box.height]:(svg.getAttribute('viewBox')||'0 0 1000 460').split(/[\s,]+/).map(Number);
 if(!rect.width||!rect.height)return [clientX,clientY];
 const aspect=svg.getAttribute('preserveAspectRatio')||'xMidYMid meet';
 if(aspect.includes('none'))return [x+(clientX-rect.left)*width/rect.width,y+(clientY-rect.top)*height/rect.height];
 const scale=(aspect.includes('slice')?Math.max:Math.min)(rect.width/width,rect.height/height);
 const align=(axis)=>aspect.includes(`${axis}Min`)?0:aspect.includes(`${axis}Max`)?1:.5;
 return [x+(clientX-rect.left-(rect.width-width*scale)*align('x'))/scale,y+(clientY-rect.top-(rect.height-height*scale)*align('Y'))/scale];
}

export function bindMapInteraction(svg,get,set,{onInteraction=()=>{}}={}){
 let drag=null,suppress=null;
 const view=svg.ownerDocument.defaultView||svg;
 const listeners=[];
 const listen=(target,type,handler,options)=>{target.addEventListener(type,handler,options);listeners.push(()=>target.removeEventListener(type,handler,options));};
 const stop=e=>{
  if(!drag||(e&&e.pointerId!==undefined&&e.pointerId!==drag.id))return;
  const previous=drag;drag=null;svg.classList.remove('dragging');
  if(previous.moved)suppress={id:previous.id,until:Date.now()+750};
  if(svg.hasPointerCapture?.(previous.id))svg.releasePointerCapture(previous.id);
 };
 listen(svg,'pointerdown',e=>{
  if(e.button!==0||e.isPrimary===false||drag)return;
  suppress=null;onInteraction();
  drag={client:[e.clientX,e.clientY],point:mapPoint(svg,e.clientX,e.clientY),rotation:[...get().rotation],zoom:get().zoom,id:e.pointerId,moved:false};
 });
 // Window listeners retain a gesture when the cursor briefly leaves the SVG before capture.
 listen(view,'pointermove',e=>{
  if(!drag||e.pointerId!==drag.id)return;
  if(!drag.moved&&Math.hypot(e.clientX-drag.client[0],e.clientY-drag.client[1])>4){
   drag.moved=true;svg.classList.add('dragging');
   try{svg.setPointerCapture?.(e.pointerId);}catch{/* Pointer already ended. */}
  }
  if(!drag.moved)return;
  e.preventDefault();
  const point=mapPoint(svg,e.clientX,e.clientY),R=BASE_R*drag.zoom;
  const dx=point[0]-drag.point[0],dy=point[1]-drag.point[1];
  set({zoom:drag.zoom,rotation:[wrapLon(drag.rotation[0]-(dx/R)*(180/Math.PI)),clampPhi(drag.rotation[1]+(dy/R)*(180/Math.PI))]});
 },{passive:false});
 listen(view,'pointerup',stop);listen(view,'pointercancel',stop);
 listen(svg,'lostpointercapture',stop);
 listen(view,'blur',()=>stop());
 listen(svg,'click',e=>{
  // Keep suppression through the following click; clearing it in a zero-delay timer races
  // delayed synthesized clicks. A new pointerdown resets it, so a new click still works.
  if(suppress&&e.detail!==0&&Date.now()<=suppress.until&&(e.pointerId===undefined||e.pointerId===suppress.id)){
   e.preventDefault();e.stopImmediatePropagation();suppress=null;
  }
 },true);
 listen(svg,'wheel',e=>{
  e.preventDefault();stop();onInteraction();const s=get();
  const amount=e.deltaY*(e.deltaMode===1?16:e.deltaMode===2?svg.getBoundingClientRect().height||460:1);
  set({zoom:Math.max(ZOOM_MIN,Math.min(ZOOM_MAX,s.zoom*Math.exp(-amount*.0015))),rotation:[...s.rotation]});
 },{passive:false});
 listen(svg,'keydown',e=>{
  const arrows={ArrowLeft:[-1,0],ArrowRight:[1,0],ArrowUp:[0,-1],ArrowDown:[0,1]};
  if(arrows[e.key]){e.preventDefault();stop();onInteraction();const s=get(),d=arrows[e.key],step=6/s.zoom;
   set({zoom:s.zoom,rotation:[wrapLon(s.rotation[0]+d[0]*step),clampPhi(s.rotation[1]-d[1]*step)]});}
 });
 return {destroy(){stop();listeners.forEach(remove=>remove());suppress=null;}};
}

// v2.2: point-in-polygon lookup used to find and highlight the country a selected AWS region
// sits in ("국가 선택시 국가 밝게 표현"). Works directly in lon/lat space (not projected), with
// standard even-odd ray casting and hole support (rings[0] = outer ring, rings[1..] = holes).
// A country with more than one AWS region (e.g. the US, Japan) is not special-cased: whichever
// region is selected, the single country polygon it falls inside is the one highlighted.
function pointInRing(pt, ring) {
 const [x, y] = pt;
 let inside = false;
 for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
  const [xi, yi] = ring[i], [xj, yj] = ring[j];
  const intersect = ((yi > y) !== (yj > y)) && (x < (xj - xi) * (y - yi) / (yj - yi) + xi);
  if (intersect) inside = !inside;
 }
 return inside;
}
function pointInPolygon(pt, rings) {
 if (!rings.length || !pointInRing(pt, rings[0])) return false;
 for (let i = 1; i < rings.length; i++) if (pointInRing(pt, rings[i])) return false;
 return true;
}
function pointInFeatureGeometry(pt, geometry) {
 if (geometry.type === 'Polygon') return pointInPolygon(pt, geometry.coordinates);
 if (geometry.type === 'MultiPolygon') return geometry.coordinates.some(poly => pointInPolygon(pt, poly));
 return false;
}
export function findCountryIndex(lon, lat, features) {
 for (let i = 0; i < features.length; i++) {
  if (pointInFeatureGeometry([lon, lat], features[i].geometry)) return i;
 }
 return -1;
}

// Great-circle (shortest-path) interpolation between two lon/lat points, used for attack arcs.
function toVec(lon,lat){const λ=lon*D2R,φ=lat*D2R;return [Math.cos(φ)*Math.cos(λ),Math.cos(φ)*Math.sin(λ),Math.sin(φ)];}
function fromVec(v){return [Math.atan2(v[1],v[0])/D2R,Math.asin(Math.max(-1,Math.min(1,v[2])))/D2R];}
function greatCirclePoints(lon1,lat1,lon2,lat2,steps=40){
 const a=toVec(lon1,lat1),b=toVec(lon2,lat2);
 const dot=Math.max(-1,Math.min(1,a[0]*b[0]+a[1]*b[1]+a[2]*b[2]));
 const theta=Math.acos(dot);
 if(theta<1e-6)return [{p:[lon1,lat1],t:0},{p:[lon2,lat2],t:1}];
 const sinT=Math.sin(theta),pts=[];
 for(let i=0;i<=steps;i++){
  const t=i/steps,w1=Math.sin((1-t)*theta)/sinT,w2=Math.sin(t*theta)/sinT;
  pts.push({p:fromVec([a[0]*w1+b[0]*w2,a[1]*w1+b[1]*w2,a[2]*w1+b[2]*w2]),t});
 }
 return pts;
}

export function connectionMarkup(events,regions,escape,rotation,zoom){
 const rimR=BASE_R*zoom; // v2.2.1 fix: see note below
 return events.map(e=>{
  const r=regions.find(r=>r.id===e.region),o=e.sourceLocation;if(!o||!r||r.lon===undefined)return '';
  const pts=greatCirclePoints(o.lon,o.lat,r.lon,r.lat,40);
  let d='',open=false,visibleAny=false;
  for(const {p,t} of pts){
   const alt=1+Math.sin(t*Math.PI)*.08; // slight altitude lift, peaking mid-arc, for a 3D feel
   const [x,y,vis]=project(p[0],p[1],rotation,zoom,alt);
   // vis>0 (cosc>0) only guarantees the *surface* point is on the front hemisphere; the lifted
   // (altScale>1) point can still project OUTSIDE the drawn globe circle near the horizon, where
   // sin(angular distance)*altScale can exceed 1. Left unchecked this drew an arrow tip sticking
   // out past the globe's rim into empty space (v2.2.1 bug report). Require the point to also
   // stay within the globe's actual on-screen radius so arcs are clipped exactly at the visible
   // edge instead of poking past it.
   const withinRim=Math.hypot(x-CX,y-CY)<=rimR;
   if(vis>0&&withinRim){d+=(open?'L':'M')+x.toFixed(2)+','+y.toFixed(2);open=true;visibleAny=true;}else open=false;
  }
  if(!visibleAny)return '';
  const [ox,oy,ovis]=project(o.lon,o.lat,rotation,zoom);
  // GuardDuty 샘플 finding 은 색(파란 점선)과 라벨로 실제 공격과 구분한다.
  const sample=e.sourceSample===true,tag=sample?'샘플 · ':'';
  const label=ovis>0?`<circle class="attack-origin" cx="${ox.toFixed(2)}" cy="${oy.toFixed(2)}" r="4"/><text class="attack-ip" x="${(ox+8).toFixed(2)}" y="${(oy-10).toFixed(2)}">${tag}${o.country&&!sample?escape(o.country)+' · ':''}${escape(e.sourceIp)}</text>`:''; // 샘플 국가명은 GeneratedFindingCountryName 이라 뺀다
  return `<g class="attack-connection${sample?' sample':''}" data-event="${e.id}" role="button" tabindex="0" aria-label="${tag}${escape(e.sourceIp)} → ${escape(r.name)}, ${escape(e.id)} 상세"><title>${tag}${escape(e.sourceIp)} (${escape(o.city)}) → ${escape(r.name)} / ${escape(e.id)}</title><path class="attack-hit" d="${d}"/><path class="attack-line" d="${d}" marker-end="url(#attack-arrow${sample?'-sample':''})"/><path class="attack-motion" d="${d}"/>${label}</g>`;
 }).join('');
}
