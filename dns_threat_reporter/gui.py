"""
DNS Threat Reporter - Web GUI
Starts a local HTTP server and opens the dashboard in the default browser.
No extra dependencies -- uses Python's built-in http.server + webbrowser.
"""

import threading
import json
import time
import sys
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from pathlib import Path

from .sniffer import DNSSniffer
from .parser import DNSParser, DNSQuery
from .analyzer import DNSAnalyzer, ThreatLevel, AnalysisResult
from .reporter import DNSReporter

PORT = 8765

# ──────────────────────────────────────────────────────────────
# HTML / CSS / JS  (all in one string, using only double-quotes
# inside JS to avoid Python \' escaping bugs)
# ──────────────────────────────────────────────────────────────

_HTML = (
    '<!DOCTYPE html>'
    '<html lang="en">'
    '<head>'
    '<meta charset="UTF-8">'
    '<title>DNS Threat Reporter</title>'
    '<style>'
    '* { box-sizing: border-box; margin: 0; padding: 0; }'
    'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;'
    '       background: #f0f2f5; color: #222; }'

    '.toolbar { background: white; padding: 10px 16px; border-bottom: 1px solid #e0e0e0;'
    '           display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }'
    '.toolbar h1 { font-size: 16px; font-weight: 700; color: #1a1a2e; margin-right: 6px; }'
    'button { padding: 7px 16px; border: none; border-radius: 5px; cursor: pointer;'
    '         font-size: 13px; font-weight: 600; transition: opacity .15s; }'
    'button:hover:not(:disabled) { opacity: .85; }'
    'button:disabled { opacity: .4; cursor: default; }'
    '.btn-start     { background: #4caf50; color: white; }'
    '.btn-stop      { background: #ef5350; color: white; }'
    '.btn-demo      { background: #5c6bc0; color: white; }'
    '.btn-blacklist { background: #bf360c; color: white; }'
    '.btn-whitelist { background: #1565c0; color: white; }'
    '.toolbar-right { margin-left: auto; display: flex; gap: 8px; }'
    '.iface-group { display: flex; align-items: center; gap: 6px; font-size: 13px; }'
    'select { padding: 5px 8px; border: 1px solid #ccc; border-radius: 4px; font-size: 13px; }'

    '.statusbar { background: white; border-bottom: 1px solid #eee; padding: 6px 16px;'
    '             display: flex; align-items: center; gap: 12px; font-size: 13px; color: #555; }'
    '.dot { font-size: 11px; }'
    '.dot.idle    { color: #aaa; }'
    '.dot.active  { color: #4caf50; }'
    '.dot.demo    { color: #5c6bc0; }'
    '.dot.stopped { color: #ef5350; }'
    '#stats { margin-left: auto; font-weight: 600; }'

    '.content { padding: 12px 16px; display: flex; flex-direction: column;'
    '           gap: 10px; height: calc(100vh - 90px); }'
    '.section-label { font-size: 12px; color: #888; font-weight: 500; letter-spacing: .03em; }'

    '.table-wrap { background: white; border-radius: 8px;'
    '              box-shadow: 0 1px 3px rgba(0,0,0,.09); flex: 1; overflow: auto; }'
    'table { width: 100%; border-collapse: collapse; font-size: 13px; }'
    'th { background: #f8f8f8; padding: 9px 12px; text-align: left;'
    '     border-bottom: 2px solid #eee; font-size: 11px; color: #777;'
    '     text-transform: uppercase; letter-spacing: .05em; position: sticky; top: 0; }'
    'td { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; }'
    'tr:last-child td { border-bottom: none; }'
    'tr:hover { background: #f0f7ff !important; cursor: pointer; }'
    '.empty-state { text-align: center; padding: 52px 0; color: #bbb; font-size: 14px; }'
    '.badge { display: inline-block; padding: 2px 9px; border-radius: 20px;'
    '         font-size: 11px; font-weight: 700; white-space: nowrap; }'
    '.badge.MEDIUM   { background: #fff3cd; color: #856404; }'
    '.badge.HIGH     { background: #ffe0e0; color: #c62828; }'
    '.badge.CRITICAL { background: #ffd6dd; color: #b71c1c; }'
    'tr.MEDIUM   { background: #fffdf5; }'
    'tr.HIGH     { background: #fff8f8; }'
    'tr.CRITICAL { background: #fff5f7; }'
    '.wl { padding: 3px 8px; font-size: 11px; font-weight: 600;'
    '      background: #e8f4fd; color: #1565c0; border-radius: 4px;'
    '      border: 1px solid #bbdefb; cursor: pointer; }'
    '.wl:hover { background: #bbdefb; }'

    '.details-panel { background: white; border-radius: 8px; padding: 10px 14px;'
    '                 font-size: 13px; color: #444; min-height: 50px;'
    '                 box-shadow: 0 1px 3px rgba(0,0,0,.09); line-height: 1.6; }'

    '.overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.45);'
    '           z-index: 100; align-items: center; justify-content: center; }'
    '.overlay.open { display: flex; }'
    '.modal { background: white; border-radius: 10px; width: 520px; max-height: 80vh;'
    '         display: flex; flex-direction: column; box-shadow: 0 8px 32px rgba(0,0,0,.25); }'
    '.mhdr { padding: 16px 20px; border-bottom: 1px solid #eee;'
    '        display: flex; align-items: center; justify-content: space-between; }'
    '.mhdr h2 { font-size: 15px; font-weight: 700; }'
    '.mclose { background: none; border: none; font-size: 22px; cursor: pointer;'
    '          color: #999; padding: 0 4px; line-height: 1; }'
    '.mclose:hover { color: #333; opacity: 1; }'
    '.mbody { flex: 1; overflow-y: auto; padding: 12px 20px; }'
    '.mfoot { padding: 12px 20px; border-top: 1px solid #eee; display: flex; gap: 8px; }'
    '.mfoot input { flex: 1; padding: 7px 10px; border: 1px solid #ccc;'
    '               border-radius: 5px; font-size: 13px; }'
    '.mfoot input:focus { outline: none; border-color: #5c6bc0; }'
    '.madd { padding: 7px 16px; border-radius: 5px; border: none; cursor: pointer;'
    '        font-size: 13px; font-weight: 600; color: white; }'
    '.dlist { list-style: none; }'
    '.dlist li { display: flex; align-items: center; justify-content: space-between;'
    '            padding: 7px 4px; border-bottom: 1px solid #f5f5f5; font-size: 13px; }'
    '.dlist li:last-child { border-bottom: none; }'
    '.dlist .rm { background: none; border: 1px solid #ddd; border-radius: 4px;'
    '             padding: 2px 8px; font-size: 11px; color: #c62828; cursor: pointer; }'
    '.dlist .rm:hover { background: #ffeaea; opacity: 1; }'
    '.dname { font-family: monospace; }'
    '.lempty { text-align: center; padding: 32px 0; color: #bbb; font-size: 13px; }'
    '</style>'
    '</head>'
    '<body>'

    '<div class="toolbar">'
    '  <h1>&#128272; DNS Threat Reporter</h1>'
    '  <button class="btn-start" id="btnStart" onclick="apiStart()">&#9654; Start Monitoring</button>'
    '  <button class="btn-stop"  id="btnStop"  onclick="apiStop()" disabled>&#9646;&#9646; Stop</button>'
    '  <div class="iface-group">'
    '    Interface:'
    '    <select id="ifaceSelect"><option value="">All</option></select>'
    '  </div>'
    '  <div class="toolbar-right">'
    '    <button class="btn-blacklist" onclick="openList(\'blacklist\')">&#128683; Blacklist</button>'
    '    <button class="btn-whitelist" onclick="openList(\'whitelist\')">&#10003; Whitelist</button>'
    '    <button class="btn-demo" onclick="apiDemo()">&#9654; Run Demo</button>'
    '  </div>'
    '</div>'

    '<!-- Blacklist modal -->'
    '<div class="overlay" id="ovBlacklist">'
    '  <div class="modal">'
    '    <div class="mhdr">'
    '      <h2>&#128683; Blacklist &mdash; Known Malicious Domains</h2>'
    '      <button class="mclose" onclick="closeList(\'blacklist\')">&times;</button>'
    '    </div>'
    '    <div class="mbody"><ul class="dlist" id="listBlacklist"><li class="lempty">Loading&hellip;</li></ul></div>'
    '    <div class="mfoot">'
    '      <input id="inputBlacklist" type="text" placeholder="Add domain, e.g. evil.com">'
    '      <button class="madd" style="background:#bf360c" onclick="addDomain(\'blacklist\')">+ Add</button>'
    '    </div>'
    '  </div>'
    '</div>'

    '<!-- Whitelist modal -->'
    '<div class="overlay" id="ovWhitelist">'
    '  <div class="modal">'
    '    <div class="mhdr">'
    '      <h2>&#10003; Whitelist &mdash; Trusted Domains</h2>'
    '      <button class="mclose" onclick="closeList(\'whitelist\')">&times;</button>'
    '    </div>'
    '    <div class="mbody"><ul class="dlist" id="listWhitelist"><li class="lempty">Loading&hellip;</li></ul></div>'
    '    <div class="mfoot">'
    '      <input id="inputWhitelist" type="text" placeholder="Add domain, e.g. safe.com">'
    '      <button class="madd" style="background:#1565c0" onclick="addDomain(\'whitelist\')">+ Add</button>'
    '    </div>'
    '  </div>'
    '</div>'

    '<div class="statusbar">'
    '  <span class="dot idle" id="dot">&#9679;</span>'
    '  <span id="statusText">Idle &mdash; ready</span>'
    '  <span id="stats">Total: <b>0</b> &nbsp; Threats: <b>0</b> &nbsp; Safe: <b>0</b></span>'
    '</div>'

    '<div class="content">'
    '  <div class="section-label">Detected Threats &mdash; MEDIUM and above</div>'
    '  <div class="table-wrap">'
    '    <table>'
    '      <thead><tr>'
    '        <th>Time</th><th>Level</th><th>Domain</th>'
    '        <th>Type</th><th>Source IP</th><th>Alert</th><th>Whitelist</th>'
    '      </tr></thead>'
    '      <tbody id="tbody">'
    '        <tr><td colspan="7" class="empty-state">No threats yet &mdash; click <b>Run Demo</b> to try.</td></tr>'
    '      </tbody>'
    '    </table>'
    '  </div>'
    '  <div class="details-panel" id="details">Click a row for details.</div>'
    '</div>'

    '<script>'
    'var _res = [], _lastN = -1, _alertedN = 0;'

    'if (window.Notification && Notification.permission === "default") {'
    '  Notification.requestPermission();'
    '}'

    'function h(s) {'
    '  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");'
    '}'

    'function playBeep() {'
    '  try {'
    '    var ctx = new (window.AudioContext || window.webkitAudioContext)();'
    '    function tone(freq, start, dur) {'
    '      var o = ctx.createOscillator();'
    '      var g = ctx.createGain();'
    '      o.connect(g); g.connect(ctx.destination);'
    '      o.frequency.value = freq;'
    '      o.type = "square";'
    '      g.gain.setValueAtTime(0.3, ctx.currentTime + start);'
    '      g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + start + dur);'
    '      o.start(ctx.currentTime + start);'
    '      o.stop(ctx.currentTime + start + dur);'
    '    }'
    '    tone(880, 0.0, 0.18);'
    '    tone(660, 0.2, 0.18);'
    '    tone(880, 0.4, 0.28);'
    '  } catch(e) {}'
    '}'

    'function alertNewCriticals(results) {'
    '  for (var i = _alertedN; i < results.length; i++) {'
    '    if (results[i].level === "CRITICAL") {'
    '      playBeep();'
    '      if (window.Notification && Notification.permission === "granted") {'
    '        var n = new Notification("&#128683; CRITICAL Threat Detected", {'
    '          body: results[i].domain + "\\n" + results[i].alert,'
    '          icon: "",'
    '          tag: "dns-critical"'
    '        });'
    '        n.onclick = function() { window.focus(); };'
    '      }'
    '    }'
    '  }'
    '  _alertedN = results.length;'
    '}'

    'function poll() {'
    '  fetch("/api/state").then(function(r){ return r.json(); }).then(function(d){'
    '    document.getElementById("stats").innerHTML ='
    '      "Total: <b>"+d.total+"</b> &nbsp; "'
    '      +"Threats: <b style=\'color:#c62828\'>"+d.threats+"</b> &nbsp; "'
    '      +"Safe: <b style=\'color:#388e3c\'>"+d.safe+"</b>";'
    '    var dot = document.getElementById("dot");'
    '    var txt = document.getElementById("statusText");'
    '    txt.textContent = d.status;'
    '    if (d.monitoring) dot.className = "dot active";'
    '    else if (d.status.indexOf("demo") >= 0 || d.status.indexOf("Demo") >= 0) dot.className = "dot demo";'
    '    else if (d.status.indexOf("Stop") >= 0 || d.status.indexOf("stop") >= 0) dot.className = "dot stopped";'
    '    else dot.className = "dot idle";'
    '    document.getElementById("btnStart").disabled = d.monitoring;'
    '    document.getElementById("btnStop").disabled  = !d.monitoring;'
    '    if (d.results.length !== _lastN) {'
    '      alertNewCriticals(d.results);'
    '      _lastN = d.results.length;'
    '      _res   = d.results;'
    '      renderTable(d.results);'
    '    }'
    '  }).catch(function(){});'
    '  setTimeout(poll, 500);'
    '}'

    'function renderTable(results) {'
    '  var tbody = document.getElementById("tbody");'
    '  if (!results.length) {'
    '    tbody.innerHTML = "<tr><td colspan=\'7\' class=\'empty-state\'>No threats yet &mdash; click <b>Run Demo</b> to try.</td></tr>";'
    '    return;'
    '  }'
    '  var html = "";'
    '  for (var i = results.length - 1; i >= 0; i--) {'
    '    var r = results[i];'
    '    html += "<tr class=\'"+r.level+"\' onclick=\'showDetails("+i+")\'>"'
    '      +"<td>"+r.time+"</td>"'
    '      +"<td><span class=\'badge "+r.level+"\'>"+r.level+"</span></td>"'
    '      +"<td><b>"+h(r.domain)+"</b></td>"'
    '      +"<td>"+r.qtype+"</td>"'
    '      +"<td>"+r.source+"</td>"'
    '      +"<td>"+h(r.alert)+"</td>"'
    '      +"<td onclick=\'event.stopPropagation()\'>"'
    '        +"<button class=\'wl\' onclick=\'wlRow("+i+",false)\'>Exact</button> "'
    '        +"<button class=\'wl\' onclick=\'wlRow("+i+",true)\'>+Parent</button>"'
    '      +"</td>"'
    '      +"</tr>";'
    '  }'
    '  tbody.innerHTML = html;'
    '}'

    'function showDetails(i) {'
    '  var r = _res[i]; if (!r) return;'
    '  document.getElementById("details").innerHTML ='
    '    "<b>Domain:</b> "+h(r.domain)+" &nbsp; "'
    '    +"<b>Type:</b> "+r.qtype+" &nbsp; "'
    '    +"<b>Source:</b> "+r.source+"<br>"'
    '    +"<b>Alerts:</b> "+r.alerts.map(h).join(" &nbsp;|&nbsp; ");'
    '}'

    'function post(url, data) {'
    '  return fetch(url, {'
    '    method: "POST",'
    '    headers: {"Content-Type": "application/json"},'
    '    body: JSON.stringify(data || {})'
    '  });'
    '}'

    'function apiStart() {'
    '  var iface = document.getElementById("ifaceSelect").value;'
    '  post("/api/start", {interface: iface || null});'
    '}'
    'function apiStop()  { post("/api/stop"); }'
    'function apiDemo()  { _lastN = -1; post("/api/demo"); }'

    'function wlRow(i, parent) {'
    '  var domain = _res[i] && _res[i].domain; if (!domain) return;'
    '  post("/api/whitelist", {domain: domain, parent: parent}).then(function(){ _lastN = -1; });'
    '}'

    'function openList(which) {'
    '  document.getElementById("ov"+which.charAt(0).toUpperCase()+which.slice(1)).classList.add("open");'
    '  loadList(which);'
    '}'
    'function closeList(which) {'
    '  document.getElementById("ov"+which.charAt(0).toUpperCase()+which.slice(1)).classList.remove("open");'
    '}'
    'document.querySelectorAll(".overlay").forEach(function(el){'
    '  el.addEventListener("click", function(e){ if(e.target===el) el.classList.remove("open"); });'
    '});'

    'function loadList(which) {'
    '  var ul = document.getElementById("list"+which.charAt(0).toUpperCase()+which.slice(1));'
    '  ul.innerHTML = "<li class=\'lempty\'>Loading&hellip;</li>";'
    '  fetch("/api/list/"+which).then(function(r){ return r.json(); }).then(function(domains){'
    '    if (!domains.length) { ul.innerHTML = "<li class=\'lempty\'>No domains yet.</li>"; return; }'
    '    ul.innerHTML = domains.slice().sort().map(function(d){'
    '      return "<li><span class=\'dname\'>"+h(d)+"</span>"'
    '        +"<button class=\'rm\' data-which=\'"+which+"\' data-domain=\'"+h(d)+"\'>Remove</button></li>";'
    '    }).join("");'
    '    ul.querySelectorAll(".rm").forEach(function(btn){'
    '      btn.onclick = function(){ removeDomain(btn.dataset.which, btn.dataset.domain); };'
    '    });'
    '  }).catch(function(){ ul.innerHTML = "<li class=\'lempty\'>Failed to load.</li>"; });'
    '}'

    'function addDomain(which) {'
    '  var inp = document.getElementById("input"+which.charAt(0).toUpperCase()+which.slice(1));'
    '  var domain = inp.value.trim().toLowerCase();'
    '  if (!domain) return;'
    '  post("/api/list/"+which+"/add", {domain: domain}).then(function(){ loadList(which); });'
    '  inp.value = "";'
    '}'
    'document.getElementById("inputBlacklist").addEventListener("keydown",'
    '  function(e){ if(e.key==="Enter") addDomain("blacklist"); });'
    'document.getElementById("inputWhitelist").addEventListener("keydown",'
    '  function(e){ if(e.key==="Enter") addDomain("whitelist"); });'

    'function removeDomain(which, domain) {'
    '  post("/api/list/"+which+"/remove", {domain: domain}).then(function(){ loadList(which); });'
    '}'

    'fetch("/api/interfaces").then(function(r){ return r.json(); }).then(function(ifaces){'
    '  var sel = document.getElementById("ifaceSelect");'
    '  ifaces.forEach(function(name){'
    '    var opt = document.createElement("option");'
    '    opt.value = name; opt.textContent = name; sel.appendChild(opt);'
    '  });'
    '}).catch(function(){});'

    'poll();'
    '</script>'
    '</body></html>'
)


# ──────────────────────────────────────────────────────────────
# HTTP Server
# ──────────────────────────────────────────────────────────────

class _Server(HTTPServer):
    allow_reuse_address = True


class _Handler(BaseHTTPRequestHandler):
    gui = None

    def log_message(self, fmt, *args):
        pass  # suppress request logs

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", _HTML.encode())
        elif self.path == "/api/state":
            self._json(self.gui._get_state())
        elif self.path == "/api/interfaces":
            self._json(DNSThreatReporterGUI._get_interfaces())
        elif self.path == "/api/list/blacklist":
            self._json(sorted(self.gui.analyzer.blacklist))
        elif self.path == "/api/list/whitelist":
            self._json(sorted(self.gui.analyzer.user_whitelist))
        else:
            self._send(404, "text/plain", b"Not found")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n)) if n else {}

        if self.path == "/api/start":
            self.gui._start_monitoring(body.get("interface"))
            self._json({"ok": True})
        elif self.path == "/api/stop":
            self.gui._stop_monitoring()
            self._json({"ok": True})
        elif self.path == "/api/demo":
            threading.Thread(target=self.gui._run_demo, daemon=True).start()
            self._json({"ok": True})
        elif self.path == "/api/whitelist":
            # Whitelist a row from the main table
            domain = body.get("domain", "").lower().strip()
            if body.get("parent"):
                parts = domain.split(".")
                domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
            if domain:
                self.gui.analyzer.add_to_whitelist(domain)
                self.gui._remove_whitelisted(domain)
            self._json({"ok": True, "domain": domain})
        elif self.path == "/api/list/blacklist/add":
            domain = body.get("domain", "").lower().strip()
            if domain:
                self.gui.analyzer.add_to_blacklist(domain)
            self._json({"ok": True})
        elif self.path == "/api/list/blacklist/remove":
            domain = body.get("domain", "").lower().strip()
            if domain:
                self.gui.analyzer.remove_from_blacklist(domain)
            self._json({"ok": True})
        elif self.path == "/api/list/whitelist/add":
            domain = body.get("domain", "").lower().strip()
            if domain:
                self.gui.analyzer.add_to_whitelist(domain)
            self._json({"ok": True})
        elif self.path == "/api/list/whitelist/remove":
            domain = body.get("domain", "").lower().strip()
            if domain:
                self.gui.analyzer.remove_from_whitelist(domain)
            self._json({"ok": True})
        else:
            self._send(404, "text/plain", b"Not found")

    def _send(self, code, ct, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data):
        self._send(200, "application/json", json.dumps(data).encode())


# ──────────────────────────────────────────────────────────────
# Application
# ──────────────────────────────────────────────────────────────

class DNSThreatReporterGUI:
    def __init__(self):
        project_root = Path(__file__).parent.parent
        self.parser = DNSParser()
        self.analyzer = DNSAnalyzer(
            blacklist_path=str(project_root / "data" / "blacklist.txt"),
            whitelist_path=str(project_root / "data" / "whitelist.txt"),
        )
        self.reporter = DNSReporter(
            log_dir=str(project_root / "logs"),
            analyzer=self.analyzer,
        )
        self.sniffer = DNSSniffer()
        self._monitoring = False
        self._status = "Idle \u2014 ready"
        self._results = []
        self._stats = {"total": 0, "safe": 0, "threats": 0}
        self._lock = threading.Lock()

    def _get_state(self):
        with self._lock:
            return {
                "monitoring": self._monitoring,
                "status":  self._status,
                "total":   self._stats["total"],
                "threats": self._stats["threats"],
                "safe":    self._stats["safe"],
                "results": list(self._results),
            }

    def _add_result(self, result: AnalysisResult):
        with self._lock:
            self._stats["total"] += 1
            if result.threat_level in (ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                self._stats["threats"] += 1
            else:
                self._stats["safe"] += 1
                return
            self._results.append({
                "time":   result.query.timestamp.strftime("%H:%M:%S"),
                "level":  result.threat_level.value,
                "domain": result.query.domain,
                "qtype":  result.query.query_type,
                "source": result.query.source_ip,
                "alert":  result.alerts[0] if result.alerts else "",
                "alerts": result.alerts,
            })

    def _remove_whitelisted(self, domain: str):
        with self._lock:
            before = len(self._results)
            self._results = [
                r for r in self._results
                if r["domain"].lower() != domain
                and not r["domain"].lower().endswith("." + domain)
            ]
            self._stats["threats"] -= before - len(self._results)

    def _start_monitoring(self, interface=None):
        if self._monitoring:
            return
        self.sniffer = DNSSniffer(interface=interface)
        self._monitoring = True
        self._status = "Monitoring..."
        threading.Thread(target=self._sniff_loop, daemon=True).start()

    def _stop_monitoring(self):
        self._monitoring = False
        self._status = "Stopped"
        self.sniffer.stop()

    def _sniff_loop(self):
        try:
            self.sniffer.start(self._handle_packet)
        except Exception as e:
            self._status = f"Error: {e}"
            self._monitoring = False

    def _handle_packet(self, packet):
        if not DNSSniffer.is_dns_query(packet):
            return
        query = self.parser.parse(packet)
        if query is None:
            return
        result = self.analyzer.analyze(query)
        self.reporter._write_to_log(result)
        self.reporter._write_to_json(result)
        if result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            self.reporter._write_alert(result)
        self._add_result(result)

    def _run_demo(self):
        self._status = "Running demo..."
        test_domains = [
            ("ynet.co.il",                                             "A"),
            ("www.google.com",                                         "A"),
            ("mail.walla.co.il",                                       "AAAA"),
            ("malware-site.com",                                       "A"),
            ("sub.evil-server.net",                                    "A"),
            ("password1234.hacker-server.com",                         "A"),
            ("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.data-steal.com",   "TXT"),
            ("x7k9m2p4q8w1.xyz",                                      "A"),
            ("a1b2c3d4e5f6g7h8i9j0.tk",                               "A"),
            ("4a6f686e20446f6520736563726574.tunnel.evil.com",         "TXT"),
            ("some-website.tk",                                        "A"),
            ("another-site.ml",                                        "A"),
            ("cdn.github.com",                                         "A"),
            ("api.microsoft.com",                                      "A"),
        ]
        for domain, qtype in test_domains:
            query = DNSQuery(
                domain=domain,
                query_type=qtype,
                source_ip="192.168.1.100",
                timestamp=datetime.now(),
            )
            self._add_result(self.analyzer.analyze(query))
            time.sleep(0.4)
        self._status = "Demo complete"

    @staticmethod
    def _get_interfaces():
        try:
            out = subprocess.run(
                ["ifconfig", "-l"], capture_output=True, text=True, timeout=5
            )
            return out.stdout.strip().split()
        except Exception:
            return ["en0", "en1", "eth0"]

    def run(self):
        _Handler.gui = self
        server = _Server(("127.0.0.1", PORT), _Handler)
        url = f"http://127.0.0.1:{PORT}"

        def open_browser():
            time.sleep(0.6)
            if sys.platform == "darwin":
                subprocess.Popen(["open", url])
            else:
                import webbrowser
                webbrowser.open(url)

        threading.Thread(target=open_browser, daemon=True).start()
        print(f"[GUI] Dashboard: {url}")
        print("[GUI] Press Ctrl+C to stop.\n")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.shutdown()
            self.reporter.close()
