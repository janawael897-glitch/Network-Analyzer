#!/usr/bin/env python3
"""
patch_incidents.py
==================
Injects the incident detail slide-in panel into web_dashboard.py.

Usage (run from your project root):
    python patch_incidents.py

It will:
  1. Read web_dashboard.py
  2. Inject the panel CSS into the existing <style> block
  3. Inject the panel HTML just before </main>
  4. Replace loadIncidents() with a version that has onclick on each row
  5. Add the Claude AI "Investigate" handler
  6. Write web_dashboard.py back (a .bak backup is created first)
"""

import re, shutil, sys
from pathlib import Path

TARGET = Path("web_dashboard.py")

if not TARGET.exists():
    sys.exit("ERROR: web_dashboard.py not found. Run this script from your project root.")

# ── Backup ────────────────────────────────────────────────────────
shutil.copy(TARGET, TARGET.with_suffix(".py.bak"))
print(f"[OK] Backup created: {TARGET.with_suffix('.py.bak')}")

src = TARGET.read_text(encoding="utf-8")

# ══════════════════════════════════════════════════════════════════
# 1. CSS  — inject before the closing </style> of the main HTML
# ══════════════════════════════════════════════════════════════════
PANEL_CSS = r"""
/* ── Incident Detail Slide-In Panel ─────────────────────────────── */
.inc-overlay{
  position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:900;
  opacity:0;pointer-events:none;transition:opacity .25s;
  backdrop-filter:blur(3px);
}
.inc-overlay.open{opacity:1;pointer-events:all;}

.inc-drawer{
  position:fixed;top:0;right:-520px;width:520px;height:100vh;
  background:#060e18;border-left:1px solid rgba(0,200,255,.18);
  z-index:901;display:flex;flex-direction:column;
  transition:right .28s cubic-bezier(.4,0,.2,1);
  box-shadow:-20px 0 60px rgba(0,0,0,.7);
}
.inc-drawer.open{right:0;}

.inc-drawer-header{
  padding:18px 22px;border-bottom:1px solid rgba(255,255,255,.06);
  display:flex;align-items:center;gap:14px;flex-shrink:0;
  background:linear-gradient(135deg,rgba(255,45,85,.04),rgba(0,0,0,0));
}
.inc-drawer-title{
  font-family:var(--font-mono);font-size:11px;font-weight:700;
  letter-spacing:3px;text-transform:uppercase;color:#ff2d55;flex:1;
}
.inc-drawer-close{
  width:30px;height:30px;border-radius:6px;background:rgba(255,255,255,.04);
  border:1px solid rgba(255,255,255,.08);color:#3a5570;cursor:pointer;
  font-size:16px;display:flex;align-items:center;justify-content:center;
  transition:all .2s;
}
.inc-drawer-close:hover{color:#ff2d55;border-color:rgba(255,45,85,.3);}

.inc-drawer-body{flex:1;overflow-y:auto;padding:22px;}
.inc-drawer-body::-webkit-scrollbar{width:4px;}
.inc-drawer-body::-webkit-scrollbar-thumb{background:rgba(255,255,255,.1);border-radius:2px;}

.inc-field{margin-bottom:16px;}
.inc-field-label{
  font-family:var(--font-mono);font-size:9px;letter-spacing:2.5px;
  text-transform:uppercase;color:#3a5570;margin-bottom:5px;
}
.inc-field-value{
  font-family:var(--font-mono);font-size:12px;color:#c0d4ee;
  background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);
  border-radius:6px;padding:9px 12px;word-break:break-all;
}
.inc-field-value.ip{color:#00c8ff;}
.inc-field-value.sev-HIGH{color:#ff6400;border-color:rgba(255,100,0,.2);}
.inc-field-value.sev-CRITICAL{color:#ff2d55;border-color:rgba(255,45,85,.2);}
.inc-field-value.sev-MEDIUM{color:#ffb800;border-color:rgba(255,184,0,.2);}
.inc-field-value.sev-LOW{color:#00ff88;border-color:rgba(0,255,136,.2);}

.inc-stats-row{
  display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:18px;
}
.inc-stat-box{
  background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);
  border-radius:8px;padding:12px 10px;text-align:center;
}
.inc-stat-val{
  font-family:var(--font-mono);font-size:18px;font-weight:700;
  color:#00c8ff;line-height:1;margin-bottom:4px;
}
.inc-stat-lbl{
  font-family:var(--font-mono);font-size:9px;letter-spacing:1.5px;
  text-transform:uppercase;color:#3a5570;
}

.inc-action-row{display:flex;gap:8px;margin-top:20px;padding-top:16px;border-top:1px solid rgba(255,255,255,.05);}
.inc-btn{
  flex:1;padding:10px;border-radius:7px;font-family:var(--font-mono);
  font-size:10px;font-weight:700;letter-spacing:1.5px;cursor:pointer;
  text-transform:uppercase;border:1px solid;transition:all .2s;
}
.inc-btn-investigate{
  background:rgba(0,200,255,.08);border-color:rgba(0,200,255,.3);color:#00c8ff;
}
.inc-btn-investigate:hover{background:rgba(0,200,255,.18);box-shadow:0 0 16px rgba(0,200,255,.2);}
.inc-btn-investigate:disabled{opacity:.4;cursor:not-allowed;}
.inc-btn-close{
  background:rgba(0,255,136,.06);border-color:rgba(0,255,136,.2);color:#00ff88;
}
.inc-btn-close:hover{background:rgba(0,255,136,.14);}
.inc-btn-danger{
  background:rgba(255,45,85,.07);border-color:rgba(255,45,85,.25);color:#ff2d55;
}
.inc-btn-danger:hover{background:rgba(255,45,85,.18);}

.inc-ai-output{
  margin-top:16px;padding:14px;background:rgba(0,200,255,.03);
  border:1px solid rgba(0,200,255,.1);border-radius:8px;
  font-family:var(--font-mono);font-size:11px;color:#b4b2a9;
  line-height:1.7;display:none;max-height:280px;overflow-y:auto;
  white-space:pre-wrap;
}
.inc-ai-output.visible{display:block;}
.inc-ai-spinner{
  display:inline-block;width:10px;height:10px;border:1.5px solid rgba(0,200,255,.2);
  border-top-color:#00c8ff;border-radius:50%;animation:spin .8s linear infinite;
  margin-right:8px;vertical-align:middle;
}
@keyframes spin{to{transform:rotate(360deg)}}

.ent-table tbody tr.inc-row-selected td{background:rgba(255,45,85,.06)!important;}
.ent-table tbody tr.inc-row{cursor:pointer;}
.ent-table tbody tr.inc-row:hover td{background:rgba(255,45,85,.04)!important;}
"""

# Find the LAST </style> before the closing </head> in the HTML string
# The big HTML block is inside a Python triple-quoted string.
# We inject our CSS just before the very last </style> that appears before the dashboard JS.
# Strategy: insert before the first `/* ── Notification system` comment in the style block.
# Actually simpler: find a unique anchor near the end of the CSS in HTML var.

CSS_ANCHOR = "/* ── Notifications ──────────────────────────────────────────────── */"
if CSS_ANCHOR not in src:
    # fallback anchor
    CSS_ANCHOR = "::-webkit-scrollbar { width: 5px; }"

if CSS_ANCHOR in src:
    src = src.replace(CSS_ANCHOR, PANEL_CSS + "\n" + CSS_ANCHOR, 1)
    print("[OK] CSS injected.")
else:
    print("[WARN] CSS anchor not found — CSS not injected. Add it manually.")

# ══════════════════════════════════════════════════════════════════
# 2. HTML  — inject panel overlay+drawer just before </main>
# ══════════════════════════════════════════════════════════════════
PANEL_HTML = r"""
<!-- ── Incident Detail Slide-In Panel ─────────────────────────── -->
<div class="inc-overlay" id="inc-overlay" onclick="closeIncidentPanel()"></div>
<aside class="inc-drawer" id="inc-drawer">
  <div class="inc-drawer-header">
    <div style="width:28px;height:28px;border-radius:6px;background:rgba(255,45,85,.12);
      border:1px solid rgba(255,45,85,.3);display:flex;align-items:center;
      justify-content:center;font-size:13px;">⚠</div>
    <div class="inc-drawer-title">Incident Detail</div>
    <button class="inc-drawer-close" onclick="closeIncidentPanel()">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
      </svg>
    </button>
  </div>

  <div class="inc-drawer-body">
    <!-- ID & timestamp -->
    <div style="margin-bottom:18px;">
      <div style="font-family:var(--font-mono);font-size:14px;font-weight:700;
        color:#ff2d55;margin-bottom:4px;" id="inc-d-id">—</div>
      <div style="font-family:var(--font-mono);font-size:10px;color:#3a5570;"
        id="inc-d-time">—</div>
    </div>

    <!-- Fields -->
    <div class="inc-field">
      <div class="inc-field-label">Source IP</div>
      <div class="inc-field-value ip" id="inc-d-ip">—</div>
    </div>
    <div class="inc-field">
      <div class="inc-field-label">Severity</div>
      <div class="inc-field-value" id="inc-d-sev">—</div>
    </div>
    <div class="inc-field">
      <div class="inc-field-label">Attack Vector</div>
      <div class="inc-field-value" id="inc-d-vec">—</div>
    </div>
    <div class="inc-field">
      <div class="inc-field-label">TTP / Chain</div>
      <div class="inc-field-value" id="inc-d-ttp">—</div>
    </div>
    <div class="inc-field">
      <div class="inc-field-label">Status</div>
      <div class="inc-field-value" style="color:#00ff88;">● Active / Unresolved</div>
    </div>

    <!-- Mini stats -->
    <div class="inc-stats-row">
      <div class="inc-stat-box">
        <div class="inc-stat-val" id="inc-d-alert-count">—</div>
        <div class="inc-stat-lbl">Alert Count</div>
      </div>
      <div class="inc-stat-box">
        <div class="inc-stat-val" id="inc-d-score" style="color:#ffb800;">—</div>
        <div class="inc-stat-lbl">Threat Score</div>
      </div>
    </div>

    <!-- AI analysis output -->
    <div class="inc-ai-output" id="inc-ai-output"></div>

    <!-- Action buttons -->
    <div class="inc-action-row">
      <button class="inc-btn inc-btn-investigate" id="inc-btn-investigate"
        onclick="investigateIncident()">
        🔍 Investigate
      </button>
      <button class="inc-btn inc-btn-close"
        onclick="closeIncidentFromPanel()">
        ✓ Close
      </button>
      <button class="inc-btn inc-btn-danger"
        onclick="closeIncidentPanel()">
        ✕ Dismiss
      </button>
    </div>
  </div>
</aside>
"""

# Anchor: inject just before the closing </main> tag
MAIN_ANCHOR = "</main>"
if MAIN_ANCHOR in src:
    # Insert before the LAST </main> occurrence
    idx = src.rfind(MAIN_ANCHOR)
    src = src[:idx] + PANEL_HTML + "\n" + src[idx:]
    print("[OK] Panel HTML injected before </main>.")
else:
    print("[WARN] </main> not found — HTML not injected.")

# ══════════════════════════════════════════════════════════════════
# 3. JS — replace loadIncidents() with click-enabled version
#         and add panel open/close/investigate functions
# ══════════════════════════════════════════════════════════════════

NEW_LOAD_INCIDENTS = r"""
async function loadIncidents(){
  const tb=document.getElementById('incidents-tbody');
  if(!tb)return;
  try{
    const r=await fetch('/api/v1/enterprise/incidents?status=open&limit=10',{credentials:'include'});
    const rows=await r.json();
    if(!rows.length){ tb.innerHTML='<tr><td colspan="7" class="ent-table-empty">No active incidents detected</td></tr>'; return; }
    const canAct=window._userRole==='admin'||window._userRole==='analyst';
    const vectorFrom=(chain)=>{
      if(!chain)return'—';
      const lc=chain.toLowerCase();
      if(lc.includes('lateral'))return'Lateral Movement';
      if(lc.includes('ddos')||lc.includes('flood'))return'DDoS / Flood';
      if(lc.includes('scan'))return'Port Scan';
      if(lc.includes('brute'))return'Brute Force';
      if(lc.includes('exfil'))return'Data Exfiltration';
      return chain.split(':')[0]||chain;
    };
    // Store rows globally so the panel can access them
    window._incidentRows = rows;
    tb.innerHTML=rows.map((i,idx)=>{
      const sev=i.severity||'LOW';
      return `<tr class="inc-row" onclick="openIncidentPanel(${idx})" data-idx="${idx}">
        <td style="color:rgba(255,255,255,.3);font-size:9px;letter-spacing:.5px">${i.incident_id.slice(0,8).toUpperCase()}…</td>
        <td style="color:#00c8ff">${i.source_ip}</td>
        <td><span class="ent-sev ent-sev-${sev}">${sev}</span></td>
        <td style="color:var(--text);opacity:.7">${vectorFrom(i.attack_chain)}</td>
        <td style="color:var(--dim);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${i.attack_chain||''}">${i.attack_chain||'—'}</td>
        <td style="color:rgba(255,255,255,.25)">${i.last_seen?i.last_seen.replace('T',' ').slice(0,16):'—'}</td>
        <td onclick="event.stopPropagation()">${canAct?`<button class="ent-close-btn" onclick="closeIncident('${i.incident_id}')">CLOSE</button>`:'<span style="color:var(--dim);font-size:9px">—</span>'}</td>
      </tr>`;
    }).join('');
  }catch(e){ tb.innerHTML=`<tr><td colspan="7" class="ent-table-empty">Error loading incidents</td></tr>`; }
}

// ── Incident panel helpers ──────────────────────────────────────
let _currentIncidentIdx = null;

function openIncidentPanel(idx) {
  const rows = window._incidentRows;
  if (!rows || !rows[idx]) return;
  const i = rows[idx];
  _currentIncidentIdx = idx;

  // Highlight selected row
  document.querySelectorAll('.inc-row').forEach(r => r.classList.remove('inc-row-selected'));
  const selRow = document.querySelector(`.inc-row[data-idx="${idx}"]`);
  if (selRow) selRow.classList.add('inc-row-selected');

  // Populate fields
  document.getElementById('inc-d-id').textContent   = i.incident_id || '—';
  document.getElementById('inc-d-time').textContent = i.last_seen
    ? 'Last seen: ' + i.last_seen.replace('T', ' ').slice(0, 16)
    : '—';
  document.getElementById('inc-d-ip').textContent   = i.source_ip  || '—';

  const sev = i.severity || 'LOW';
  const sevEl = document.getElementById('inc-d-sev');
  sevEl.textContent = '● ' + sev;
  sevEl.className = 'inc-field-value sev-' + sev;

  document.getElementById('inc-d-vec').textContent = (() => {
    const chain = i.attack_chain || '';
    const lc = chain.toLowerCase();
    if (lc.includes('lateral'))  return 'Lateral Movement';
    if (lc.includes('ddos') || lc.includes('flood')) return 'DDoS / Flood';
    if (lc.includes('scan'))     return 'Port Scan';
    if (lc.includes('brute'))    return 'Brute Force';
    if (lc.includes('exfil'))    return 'Data Exfiltration';
    if (lc.includes('recon'))    return 'Reconnaissance';
    return chain.split(':')[0] || chain || '—';
  })();

  document.getElementById('inc-d-ttp').textContent         = i.attack_chain || '—';
  document.getElementById('inc-d-alert-count').textContent = i.alert_count ?? '—';
  document.getElementById('inc-d-score').textContent       = i.threat_score != null
    ? Math.round(i.threat_score) : '—';

  // Reset AI output
  const aiOut = document.getElementById('inc-ai-output');
  aiOut.textContent = '';
  aiOut.classList.remove('visible');
  document.getElementById('inc-btn-investigate').disabled = false;
  document.getElementById('inc-btn-investigate').innerHTML = '🔍 Investigate';

  // Open panel
  document.getElementById('inc-overlay').classList.add('open');
  document.getElementById('inc-drawer').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeIncidentPanel() {
  document.getElementById('inc-overlay').classList.remove('open');
  document.getElementById('inc-drawer').classList.remove('open');
  document.body.style.overflow = '';
  document.querySelectorAll('.inc-row').forEach(r => r.classList.remove('inc-row-selected'));
  _currentIncidentIdx = null;
}

async function closeIncidentFromPanel() {
  const rows = window._incidentRows;
  if (_currentIncidentIdx === null || !rows) return;
  const i = rows[_currentIncidentIdx];
  closeIncidentPanel();
  await closeIncident(i.incident_id);
}

// ── AI-powered Investigate (calls Anthropic API) ────────────────
async function investigateIncident() {
  const rows = window._incidentRows;
  if (_currentIncidentIdx === null || !rows) return;
  const i = rows[_currentIncidentIdx];

  const btn   = document.getElementById('inc-btn-investigate');
  const aiOut = document.getElementById('inc-ai-output');

  btn.disabled = true;
  btn.innerHTML = '<span class="inc-ai-spinner"></span> Analyzing…';
  aiOut.textContent = '';
  aiOut.classList.add('visible');

  const prompt = `You are a SOC analyst. Analyze this network security incident and provide a concise threat assessment:

Incident ID: ${i.incident_id}
Source IP: ${i.source_ip}
Severity: ${i.severity || 'UNKNOWN'}
Attack Chain / TTP: ${i.attack_chain || 'Unknown'}
Last Seen: ${i.last_seen || 'Unknown'}
Alert Count: ${i.alert_count ?? 'Unknown'}
Threat Score: ${i.threat_score ?? 'Unknown'}

Provide:
1. THREAT SUMMARY (2-3 sentences)
2. LIKELY INTENT (what the attacker is probably doing)
3. RECOMMENDED ACTIONS (3 bullet points)
4. RISK LEVEL: Low / Medium / High / Critical

Be concise and actionable. Use plain text, no markdown.`;

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 512,
        messages: [{ role: "user", content: prompt }]
      })
    });
    const data = await response.json();

    if (data.content && data.content[0] && data.content[0].text) {
      aiOut.textContent = data.content[0].text.trim();
    } else if (data.error) {
      aiOut.textContent = "API Error: " + (data.error.message || JSON.stringify(data.error));
    } else {
      aiOut.textContent = "No analysis returned.";
    }
  } catch (err) {
    aiOut.textContent = "Network error reaching Anthropic API: " + err.message;
  }

  btn.disabled = false;
  btn.innerHTML = '🔍 Re-analyze';
}
"""

# Replace the existing loadIncidents function
OLD_FUNC_START = "async function loadIncidents(){"
OLD_FUNC_END   = "async function closeIncident(id){"

if OLD_FUNC_START in src and OLD_FUNC_END in src:
    start_idx = src.index(OLD_FUNC_START)
    end_idx   = src.index(OLD_FUNC_END)
    src = src[:start_idx] + NEW_LOAD_INCIDENTS + "\n" + src[end_idx:]
    print("[OK] loadIncidents() replaced and panel JS injected.")
else:
    print("[WARN] Could not find loadIncidents() boundaries — JS not replaced.")
    print(f"  OLD_FUNC_START found: {OLD_FUNC_START in src}")
    print(f"  OLD_FUNC_END found:   {OLD_FUNC_END in src}")

# Also add ESC key close for the incident panel (after the existing ESC handler)
ESC_ANCHOR = "document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeSettings(); });"
ESC_EXTRA  = "\ndocument.addEventListener('keydown', e=>{ if(e.key==='Escape') closeIncidentPanel(); });"
if ESC_ANCHOR in src and ESC_EXTRA not in src:
    src = src.replace(ESC_ANCHOR, ESC_ANCHOR + ESC_EXTRA, 1)
    print("[OK] ESC key handler added for incident panel.")

# ── Write result ──────────────────────────────────────────────────
TARGET.write_text(src, encoding="utf-8")
print(f"\n✅  Done! web_dashboard.py patched successfully.")
print("   Restart Flask: python web_dashboard.py")
print("   Then open your dashboard and click any incident row.")
