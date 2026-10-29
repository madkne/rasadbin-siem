"use strict";
(() => {
  const $ = (s) => document.querySelector(s);
  const MAX_POINTS = 60, MAX_EVENTS = 50;
  const heap = [];

  function renderStats(s) {
    $("#s-uptime").textContent = RB.fmtDuration(s.uptime_seconds);
    $("#s-events").textContent = s.events_total.toLocaleString();
    $("#s-clients").textContent = s.clients;
    $("#s-goroutines").textContent = s.goroutines;
    $("#s-heap").textContent = s.heap_mb.toFixed(1) + " MB";
    $("#s-version").textContent = s.version + " (" + s.commit + ")";

    heap.push(s.heap_mb);
    if (heap.length > MAX_POINTS) heap.shift();
    drawHeap();
  }

  function drawHeap() {
    const svg = $("#heap");
    const max = Math.max(...heap, 1) * 1.1;
    const pts = heap
      .map((v, i) => ((i / (MAX_POINTS - 1)) * 300).toFixed(1) + "," + (60 - (v / max) * 60).toFixed(1))
      .join(" ");
    let line = svg.querySelector("polyline");
    if (!line) {
      line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
      line.setAttribute("fill", "none");
      line.setAttribute("stroke", "currentColor");
      line.setAttribute("stroke-width", "1.5");
      line.setAttribute("vector-effect", "non-scaling-stroke");
      svg.appendChild(line);
    }
    line.setAttribute("points", pts);
  }

  function eventRow(e) {
    const tr = document.createElement("tr");
    const cells = [new Date(e.time).toLocaleTimeString(), e.source, null, e.message];
    cells.forEach((text, i) => {
      const td = document.createElement("td");
      if (i === 2) {
        const span = document.createElement("span");
        span.className = "sev sev-" + String(e.severity).replace(/[^a-z]/g, "");
        span.textContent = e.severity;
        td.appendChild(span);
      } else {
        td.textContent = text;
      }
      tr.appendChild(td);
    });
    return tr;
  }

  function renderEvents(list) {
    const body = $("#events");
    body.replaceChildren(...list.slice().reverse().map(eventRow));
    $("#empty").hidden = list.length > 0;
  }

  function addEvent(e) {
    const body = $("#events");
    body.prepend(eventRow(e));
    while (body.children.length > MAX_EVENTS) body.lastChild.remove();
    $("#empty").hidden = true;
  }

  RB.on("ready", () => RB.send("subscribe", { topic: "dashboard" }));
  RB.on("dashboard", (d) => { renderStats(d.stats); renderEvents(d.events || []); });
  RB.on("stats", renderStats);
  RB.on("event", addEvent);

  RB.connect({ auth: true });
})();
