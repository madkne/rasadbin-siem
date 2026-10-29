import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import Shell from "../components/Shell";
import { ws } from "../lib/ws";
import type { EventEntry, Integration } from "../lib/types";
export default function IntegrationWorkspace(){
 const {id=""}=useParams(); const [item,setItem]=useState<Integration|null>(null); const [events,setEvents]=useState<EventEntry[]>([]);
 useEffect(()=>{
   const offReady=ws.on("ready",()=>{ws.send("integrations.get");ws.send("integration.events",{id});ws.send("subscribe");});
   const offList=ws.on("integrations",all=>setItem(all.find(v=>v.id===id)??null));
   const offEvents=ws.on("integration.events",v=>{if(v.id===id)setEvents(v.events);});
   const offEvent=ws.on("event",e=>{if(e.source===id)setEvents(prev=>{if(prev.some(x=>x.time===e.time&&x.message===e.message))return prev;return [e,...prev].slice(0,50);});});
   const offSaved=ws.on("integration_saved",v=>{if(v.id===id)setItem(v);});
   const offStatus=ws.on("integration.status",v=>{if(v.id===id)setItem(prev=>prev?{...prev,status:v.status}:prev);});
   if(ws.isReady){ws.send("integrations.get");ws.send("integration.events",{id});ws.send("subscribe");}
   return ()=>{offReady();offList();offEvents();offEvent();offSaved();offStatus();if(ws.isReady)ws.send("unsubscribe");};
 },[id]);
 return <Shell><main className="integration-page"><Link to="/integrations" className="back-link">← All integrations</Link>
 {item?<><div className="page-heading"><div><p className="eyebrow">INTEGRATION WORKSPACE</p><h1>{item.name}</h1><p className="muted">{item.description}</p></div><span className={item.enabled?"state-enabled":"state-disabled"}>{item.enabled?"Enabled":"Disabled"}</span></div>
 <div className="workspace-grid"><section className="card"><h2>Collector</h2><p>{item.collector}</p><p className="muted">Collector lifecycle and health are isolated from the web UI.</p></section><section className="card"><h2>Event processor</h2><p>{item.processor}</p><p className="muted">Normalize, enrich and validate source events before detection.</p></section><section className="card"><h2>Detections & alerting</h2><ul>{item.detections.map(d=><li key={d}>{d}</li>)}</ul><p>Alerting: <strong>{item.alerting?"Enabled":"Disabled"}</strong></p><p>Status: <strong>{item.status}</strong></p></section></div>
 <section className="card workspace-events"><div className="events-heading"><div><h2>Recent events</h2><p className="muted">Events routed through this integration</p></div><button type="button" className="ghost" onClick={()=>ws.send("integration.events",{id})}>Refresh</button></div>{events.length===0?<p className="empty-state">No events for this integration yet. Enable the source and connect its collector adapter.</p>:<div className="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Event</th></tr></thead><tbody>{events.map((e,i)=><tr key={`${e.time}-${i}`}><td>{new Date(e.time).toLocaleString()}</td><td>{e.severity}</td><td>{e.message}</td></tr>)}</tbody></table></div>}</section></>:<p className="muted">Loading integration…</p>}
 </main></Shell>;
}