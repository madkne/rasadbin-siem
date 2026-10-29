import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import TopBar from "../components/TopBar";
import { ws } from "../lib/ws";

type Integration = {
  id: string; name: string; description: string; category: string;
  enabled: boolean; collector: string; processor: string;
  detections: string[]; alerting: boolean; status: string;
};
const statusText: Record<string,string> = {
  not_configured: "Not enabled",
  disabled: "Disabled",
  enabled_waiting_for_collector: "Enabled · collector adapter pending",
  running: "Running",
  failed: "Failed",
};
export default function Integrations() {
  const [items,setItems] = useState<Integration[]>([]);
  const [error,setError] = useState("");
  const [busy,setBusy] = useState<string|null>(null);
  useEffect(()=>{
    const offReady=ws.on("ready",()=>ws.send("integrations.get"));
    const offList=ws.on<Integration[]>("integrations",setItems);
    const offSaved=ws.on<Integration>("integration_saved",v=>{setItems(old=>old.map(i=>i.id===v.id?v:i));setBusy(null);});
    const offErr=ws.on<{for?:string;message:string}>("error",e=>{if(e.for==="integration.update"||e.for==="integrations.get"){setError(e.message);setBusy(null);}});
    if(ws.isReady) ws.send("integrations.get");
    return ()=>{offReady();offList();offSaved();offErr();};
  },[]);
  function update(item:Integration, enabled=item.enabled, alerting=item.alerting) {
    setBusy(item.id); setError("");
    ws.send("integration.update",{id:item.id,enabled,alerting});
  }
  return <><TopBar/><main className="integration-page">
    <div className="page-heading"><div><p className="eyebrow">DATA SOURCES</p><h1>Integrations</h1><p className="muted">Enable the telemetry sources Rasadbin should process. Each integration defines its own collector, processor, detections and alert policy.</p></div><span className="integration-count">{items.filter(i=>i.enabled).length} / {items.length} enabled</span></div>
    {error&&<p className="msg error" role="alert">{error}</p>}
    <div className="integration-grid">{items.map(item=><section className="integration-card" key={item.id}>
      <div className="integration-card-head"><div className="integration-icon">{item.category==="Network"?"↔":item.category==="Services"?"⌘":"≋"}</div><div className="integration-title"><span className="eyebrow">{item.category}</span><h2>{item.name}</h2></div><label className="switch-label"><input aria-label={`Enable ${item.name}`} type="checkbox" checked={item.enabled} disabled={busy===item.id} onChange={e=>update(item,e.target.checked)}/><span>{item.enabled?"On":"Off"}</span></label></div>
      <p>{item.description}</p><div className="integration-meta"><span>Collector</span><p>{item.collector}</p><span>Event processor</span><p>{item.processor}</p></div>
      <div className="detection-list"><strong>Detection packs</strong>{item.detections.map(d=><span key={d}>• {d}</span>)}</div>
      <div className="integration-footer"><label><input type="checkbox" checked={item.alerting} disabled={!item.enabled||busy===item.id} onChange={e=>update(item,item.enabled,e.target.checked)}/> Generate alerts</label><span className={item.enabled?"state-enabled":"state-disabled"}>{statusText[item.status]??item.status}</span></div>
      <Link className="integration-detail-link" to={`/integrations/${item.id}`}>Open integration workspace <span aria-hidden>→</span></Link>
    </section>)}</div>
    <p className="muted integration-note">Important: integration controls and configuration are persisted. A source is not considered operational until its collector adapter reports healthy; collector adapters are being introduced independently of this control plane.</p>
  </main></>;
}
