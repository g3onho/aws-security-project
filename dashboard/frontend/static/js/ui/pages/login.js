let csrf='';const error=document.querySelector('#login-error');const form=document.querySelector('#login-form');
async function init(){
 try{
  const r=await fetch('/api/auth/session');const m=await r.json();csrf=m.csrfToken;
  if(m.user){location.replace('/');return;}
  // 아이디·암호 칸에 값이 미리 채워져 있으면(데모 편의) 페이지 뜨자마자 자동 제출한다.
  const u=document.querySelector('#username'),p=document.querySelector('#password');
  if(u.value&&p.value)form.requestSubmit();
 }catch{error.textContent='서버에 연결할 수 없습니다. 새로고침해주세요.';}
}
form.addEventListener('submit',async e=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;error.textContent='';try{const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({username:document.querySelector('#username').value,password:document.querySelector('#password').value})});const m=await r.json();if(!r.ok)throw Error(m.title);location.replace('/');}catch(ex){error.textContent=ex.message;}finally{b.disabled=false;}});
init();
