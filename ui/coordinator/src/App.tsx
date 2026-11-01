import React, { useEffect, useMemo, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import { Activity, BrainCircuit, CircleDot, Compass, Database, Gauge, Orbit, Plus, ShieldCheck, Sparkles, Workflow } from 'lucide-react';

const API = '/v1/coordinator';
let CSRF = sessionStorage.getItem('patience_csrf') || '';
let CSRF_FROM_SESSION = sessionStorage.getItem('patience_csrf_src') === 'session';
// Dev-open mode has no login, so fetch a double-submit token (also sets the patience_coord_csrf cookie).
async function ensureCsrf(force=false){
  if (CSRF && !force) return;
  const r = await fetch(API+'/csrf',{credentials:'same-origin'});
  if (!r.ok) throw new Error(r.status===401?'auth':`HTTP ${r.status}`);
  CSRF=(await r.json()).csrf_token; CSRF_FROM_SESSION=false;
  sessionStorage.setItem('patience_csrf',CSRF); sessionStorage.setItem('patience_csrf_src','dev');
}
async function call(path:string, method='GET', body?:unknown, retried=false):Promise<any>{
  const headers:Record<string,string> = {};
  if (method !== 'GET') { await ensureCsrf(); headers['Content-Type']='application/json'; headers['X-CSRF-Token']=CSRF; }
  const r = await fetch(API+path,{method,headers,credentials:'same-origin',body:body===undefined?undefined:JSON.stringify(body)});
  if (r.status===403 && method!=='GET' && !retried && !CSRF_FROM_SESSION) { await ensureCsrf(true); return call(path,method,body,true); }
  if (r.status===401||r.status===403) throw new Error('auth');
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
async function login(user:string,password:string){
  const r = await fetch(API+'/session',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({user,password})});
  if(!r.ok) throw new Error('Login failed');
  CSRF=(await r.json()).csrf_token; CSRF_FROM_SESSION=true;
  sessionStorage.setItem('patience_csrf',CSRF); sessionStorage.setItem('patience_csrf_src','session');
}
type Project = {id:number; name:string; status:string; priority:string; next_step:string; created_at:string};
type Event = {id:number; kind:string; title:string; detail:string; source:string; created_at:string};
type Coord = {llm_suggestion:{text:string;model:string;unverified:boolean}|null; llm_error:string|null; recommendation:string; basis:string; confidence:number; mode:string; proposed_action:{status:string;description:string}; observed_projects:number; recent_events:number};

function Presence({mood}:{mood:string}) {
  const group = React.useRef<THREE.Group>(null);
  const core = React.useRef<THREE.Mesh>(null);
  useFrame((state, delta) => {
    if (group.current) { group.current.rotation.y += delta * (mood === 'coordinating' ? .20 : .10); group.current.rotation.x = Math.sin(state.clock.elapsedTime*.35)*.08; }
    if (core.current) { const s = 1 + Math.sin(state.clock.elapsedTime*1.5)*.035; core.current.scale.setScalar(s); }
  });
  const nodes = useMemo(() => Array.from({length:34},(_,i)=> {
    const a=i*2.399, r=1.15+(i%5)*.12, y=Math.sin(i*1.7)*.82;
    return [Math.cos(a)*r,y,Math.sin(a)*r] as [number,number,number];
  }),[]);
  return <group ref={group}>
    <mesh ref={core}><icosahedronGeometry args={[.68,3]}/><meshStandardMaterial color="#b9c6c9" metalness={.82} roughness={.22} emissive="#52676a" emissiveIntensity={.28} wireframe={false}/></mesh>
    <mesh><icosahedronGeometry args={[.91,1]}/><meshBasicMaterial color="#a5b8b8" wireframe transparent opacity={.25}/></mesh>
    {nodes.map((p,i)=><mesh key={i} position={p}><sphereGeometry args={[i%4===0?.045:.022,10,10]}/><meshBasicMaterial color={i%4===0?'#d7e2df':'#81999a'} transparent opacity={.8}/></mesh>)}
    {nodes.slice(0,17).map((p,i)=><mesh key={'line'+i} position={[(p[0])*.53,p[1]*.53,p[2]*.53]}><sphereGeometry args={[.012,6,6]}/><meshBasicMaterial color="#d2dddd"/></mesh>)}
  </group>;
}
function PresencePanel({mood}:{mood:string}) {
 return <div className="presence">
   <div className="presence-label"><span className="live-dot"/> PRESENCE / ADAPTIVE CORE</div>
   <Canvas camera={{position:[0,0,4.1],fov:42}} dpr={[1,1.5]}>
    <ambientLight intensity={1.4}/><pointLight position={[3,3,4]} intensity={35}/><pointLight position={[-3,-2,-3]} intensity={12} color="#7c9696"/>
    <Presence mood={mood}/><OrbitControlsShim/>
   </Canvas>
   <div className="presence-caption"><strong>PATIENCE</strong><span> {mood.toUpperCase()} · LOCAL SESSION</span></div>
 </div>;
}
function OrbitControlsShim(){ useFrame(({camera})=>camera.lookAt(0,0,0)); return null; }

export default function App(){
 const [projects,setProjects]=useState<Project[]>([]);
 const [events,setEvents]=useState<Event[]>([]);
 const [coord,setCoord]=useState<Coord|null>(null);
 const [health,setHealth]=useState<any>(null);
 const [newName,setNewName]=useState('');
 const [newStep,setNewStep]=useState('');
 const [note,setNote]=useState('');
 const [tab,setTab]=useState('command');
 const [busy,setBusy]=useState(false);
 const [error,setError]=useState('');
 const [authed,setAuthed]=useState(true);
 const [u,setU]=useState(''); const [pw,setPw]=useState('');
 async function load(){
   try{
    const [p,e,c,h]=await Promise.all([call('/projects'),call('/events'),call('/recommendation'),call('/health')]);
    setProjects(p);setEvents(e);setCoord(c);setHealth(h);setError('');setAuthed(true);
   }catch(err:any){ if(err?.message==='auth') setAuthed(false); else setError('Local service offline. Start the PATIENCE API on 127.0.0.1:8765.');}
 }
 useEffect(()=>{load();const t=setInterval(load,12000);return()=>clearInterval(t)},[]);
 async function createProject(e:React.FormEvent){e.preventDefault();if(!newName.trim())return;setBusy(true);try{await call('/projects','POST',{name:newName,priority:'high',next_step:newStep});setNewName('');setNewStep('');await load()}finally{setBusy(false)}}
 async function addNote(e:React.FormEvent){e.preventDefault();if(!note.trim())return;await call('/events','POST',{kind:'observation',title:note,detail:'User-entered observation'});setNote('');await load()}
 async function setStatus(id:number,status:string){await call(`/projects/${id}`,'PATCH',{status});await load()}
 const active=projects.filter(p=>p.status==='active').length;
 const mood=busy?'coordinating':coord?'observing':'idle';
 if(!authed) return <form className="panel input-panel" style={{maxWidth:360,margin:'15vh auto'}} onSubmit={async e=>{e.preventDefault();try{await login(u,pw);setPw('');await load()}catch{setError('Login failed')}}}>
   <b>PATIENCE coordinator: approver login</b>{error&&<div className="error-banner">{error}</div>}
   <input value={u} onChange={e=>setU(e.target.value)} placeholder="User" autoComplete="username" required/>
   <input type="password" value={pw} onChange={e=>setPw(e.target.value)} placeholder="Password" autoComplete="current-password" required/>
   <button type="submit">Log in</button></form>;
 return <div className="app-shell">
  <aside className="sidebar">
   <div className="brand"><div className="brand-mark">P*</div><div><b>PATIENCE</b><small>GOVERNANCE INTELLIGENCE</small></div></div>
   <div className="side-label">WORKSPACE</div>
   {[['command','Command center',Gauge],['oracle','Oracle intelligence',BrainCircuit],['projects','Project field',Orbit],['governance','Governance membrane',ShieldCheck],['signals','Observation stream',Activity]].map(([id,label,Icon]:any)=><button className={'nav-item '+(tab===id?'selected':'')} onClick={()=>setTab(id)} key={id}><Icon size={16}/>{label}</button>)}
   <div className="sidebar-bottom"><div className="side-label">SYSTEM</div><div className="system-line"><span className="live-dot"/>{health?.status==='online'?'LOCAL SERVICE ONLINE':'SERVICE UNAVAILABLE'}</div><div className="system-line muted"><Database size={13}/> SQLite / localhost</div><div className="system-line muted"><ShieldCheck size={13}/> Preview-only execution</div></div>
  </aside>
  <main className="main">
   <header className="topbar"><div><span className="eyebrow">HYPERION / PERSONAL WORKSTATION</span><h1>{({command:'Command center',oracle:'Oracle intelligence',projects:'Project field',governance:'Governance membrane',signals:'Observation stream'} as any)[tab]}</h1></div><div className="top-right"><span className="mode-chip"><span className="live-dot"/> COORDINATOR MODE</span><span className="clock">{new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'})}</span></div></header>
   {error&&<div className="error-banner">{error}</div>}
   {coord?.llm_error&&<div className="error-banner">Local model unavailable ({coord.llm_error}); showing deterministic ranking only.</div>}
   {coord?.llm_suggestion&&<div className="panel"><b>UNVERIFIED model suggestion ({coord.llm_suggestion.model})</b><p>{coord.llm_suggestion.text}</p><small>Not covered by the basis/confidence shown; no action has been taken.</small></div>}
   {tab==='command'&&<div className="dashboard">
    <section className="hero-grid"><PresencePanel mood={mood}/><div className="oracle-card"><div className="section-kicker"><Sparkles size={14}/> ORACLE / CURRENT ASSESSMENT</div><div className="oracle-status">READY TO COORDINATE</div><p className="recommendation">{coord?.recommendation||'Waiting for local workspace data.'}</p><div className="basis"><span>ASSESSMENT BASIS</span><p>{coord?.basis||'No assessment available.'}</p></div><div className="confidence"><div><span>CONFIDENCE</span><b>{Math.round((coord?.confidence||0)*100)}%</b></div><div className="meter"><i style={{width:`${(coord?.confidence||0)*100}%`}}/></div><div className="action-preview"><div><ShieldCheck size={15}/> ACTION GATE</div><span>PREVIEW ONLY</span><p>{coord?.proposed_action.description||'Human review required before action.'}</p></div></div></div></section>
    <section className="metrics"><Metric label="ACTIVE PROJECTS" value={active.toString().padStart(2,'0')} icon={<Workflow/>}/><Metric label="WORKSPACE EVENTS" value={events.length.toString().padStart(2,'0')} icon={<Activity/>}/><Metric label="OBSERVATION SOURCES" value="01" icon={<Database/>}/><Metric label="EXECUTION PERMISSIONS" value="00" icon={<ShieldCheck/>}/></section>
    <section className="lower-grid"><div className="panel"><PanelTitle icon={<Orbit/>} title="PROJECT FIELD" meta={`${projects.length} REGISTERED`}/><div className="project-list">{projects.slice(0,5).map(p=><div className="project-row" key={p.id}><div className="project-symbol"/><div className="project-info"><b>{p.name}</b><span>{p.next_step||'Next step not defined'}</span></div><span className={'priority '+p.priority}>{p.priority}</span><select value={p.status} onChange={e=>setStatus(p.id,e.target.value)}><option>active</option><option>planned</option><option>paused</option><option>complete</option></select></div>)}{!projects.length&&<Empty>No projects recorded.</Empty>}</div></div>
    <div className="panel"><PanelTitle icon={<Activity/>} title="OBSERVATION STREAM" meta="LATEST EVENTS"/><div className="event-list">{events.slice(0,5).map(ev=><div className="event-row" key={ev.id}><span className="event-dot"/><div><b>{ev.title}</b><p>{ev.detail||ev.source}</p><small>{new Date(ev.created_at).toLocaleString()}</small></div></div>)}</div></div></section>
    <section className="lower-grid forms-grid"><form className="panel input-panel" onSubmit={createProject}><PanelTitle icon={<Plus/>} title="REGISTER PROJECT" meta="USER-DEFINED"/><input value={newName} onChange={e=>setNewName(e.target.value)} placeholder="Project name" required/><input value={newStep} onChange={e=>setNewStep(e.target.value)} placeholder="Next measurable step"/><button className="primary" disabled={busy}>Add to project field</button></form><form className="panel input-panel" onSubmit={addNote}><PanelTitle icon={<CircleDot/>} title="ADD OBSERVATION" meta="EXPLICIT INPUT ONLY"/><textarea value={note} onChange={e=>setNote(e.target.value)} placeholder="Record a signal, decision, blocker, or thought…" required/><button className="secondary">Record observation</button></form></section>
   </div>}
   {tab==='oracle'&&<section className="single-panel"><div className="panel"><PanelTitle icon={<BrainCircuit/>} title="ORACLE INTELLIGENCE" meta="REASONING / EVIDENCE / UNCERTAINTY"/><h2 className="large-statement">{coord?.recommendation||'Oracle awaits workspace data.'}</h2><div className="three-cells"><div><label>MODE</label><b>{coord?.mode||'offline'}</b></div><div><label>CONFIDENCE</label><b>{Math.round((coord?.confidence||0)*100)}%</b></div><div><label>OBSERVED PROJECTS</label><b>{coord?.observed_projects??0}</b></div></div><p className="muted-copy">Oracle analysis is grounded only in records stored in this PATIENCE workspace. Model-generated text is advisory, not authoritative. Verify important recommendations against source records.</p></div></section>}
   {tab==='projects'&&<section className="single-panel"><div className="panel"><PanelTitle icon={<Orbit/>} title="PROJECT FIELD" meta="PROJECTS / DEPENDENCIES / NEXT STEPS"/>{projects.map(p=><div className="wide-project" key={p.id}><div><b>{p.name}</b><p>{p.next_step}</p></div><span className="priority">{p.priority}</span><select value={p.status} onChange={e=>setStatus(p.id,e.target.value)}><option>active</option><option>planned</option><option>paused</option><option>complete</option></select></div>)}</div></section>}
   {tab==='governance'&&<section className="single-panel"><div className="panel"><PanelTitle icon={<ShieldCheck/>} title="GOVERNANCE MEMBRANE" meta="PERMISSION BOUNDARIES"/><div className="policy-grid">{[['Observation','Only user-entered workspace records','ENABLED'],['Local reasoning','Ollama is optional and local','CONDITIONAL'],['External communication','No message-sending connector','BLOCKED'],['File-system access','No ambient file scanning','BLOCKED'],['Consequential execution','Preview only; human action required','BLOCKED'],['Audit trail','Workspace events stored in SQLite','ENABLED']].map(x=><div className="policy" key={x[0]}><div><b>{x[0]}</b><p>{x[1]}</p></div><span className={x[2]==='ENABLED'?'good':'locked'}>{x[2]}</span></div>)}</div></div></section>}
   {tab==='signals'&&<section className="single-panel"><div className="panel"><PanelTitle icon={<Activity/>} title="OBSERVATION STREAM" meta="LOCAL WORKSPACE EVENT LOG"/>{events.map(ev=><div className="wide-project" key={ev.id}><div><b>{ev.title}</b><p>{ev.detail||'No additional detail'}</p><small>{ev.source} · {new Date(ev.created_at).toLocaleString()}</small></div><span className="priority">{ev.kind}</span></div>)}</div></section>}
   <footer> PATIENCE * / EXPERIMENTAL BUILD 0.1 <span>LOCAL-FIRST · AUDITABLE · HUMAN-GOVERNED</span></footer>
  </main>
 </div>;
}
function Metric({label,value,icon}:any){return <div className="metric"><div className="metric-icon">{icon}</div><div><span>{label}</span><b>{value}</b></div></div>}
function PanelTitle({icon,title,meta}:any){return <div className="panel-title"><div>{icon}<b>{title}</b></div><span>{meta}</span></div>}
function Empty({children}:any){return <div className="empty">{children}</div>}
