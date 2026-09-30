// Chart.js 수명주기: 같은 캔버스면 갱신, 캔버스가 바뀌면 이전 차트 destroy, 화면에서 빠진 차트 정리(설계 2.1-6).
import {$} from '../context.js?v=v42';
const charts=new Map();
export function drawChart(id,type,data,options={}){
 const el=$(`#${id}`);if(!el)return;
 if(!window.Chart){el.replaceWith(Object.assign(document.createElement('p'),{className:'chart-fallback',textContent:'차트 라이브러리를 불러오지 못했습니다. 텍스트 수치를 확인해주세요.'}));return;}
 const chartOptions={responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false},tooltip:{backgroundColor:'#d8e6f3',titleColor:'#0f0f0f',bodyColor:'#0e1e2a',padding:10}},...options};
 const existing=charts.get(id);
 if(existing?.canvas===el){existing.data=data;existing.options=chartOptions;existing.update('none');return;}
 existing?.destroy();
 charts.set(id,new Chart(el,{type,data,options:chartOptions}));
}
export function cleanCharts(){
 for(const [id,chart] of charts){if(!chart.canvas.isConnected){chart.destroy();charts.delete(id);}}
}
