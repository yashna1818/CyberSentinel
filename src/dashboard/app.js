// State
let ws = null;
let attackCounts = {};
let throughputHistory = [];
const MAX_HISTORY = 40;

function initWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/stream`;
  
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    document.getElementById('wsConnectionStatus').innerText = 'STREAM ONLINE';
    document.getElementById('wsConnectionStatus').style.color = 'var(--accent-emerald)';
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'TELEMETRY_UPDATE') {
        renderTelemetry(data);
      }
    } catch (err) {
      console.error("Error parsing WebSocket message:", err);
    }
  };

  ws.onclose = () => {
    document.getElementById('wsConnectionStatus').innerText = 'RECONNECTING...';
    document.getElementById('wsConnectionStatus').style.color = 'var(--accent-amber)';
    setTimeout(initWebSocket, 2000);
  };

  ws.onerror = () => {
    ws.close();
  };
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active'));
  
  const targetPane = document.getElementById(tabId);
  if (targetPane) targetPane.classList.add('active');

  const tabs = Array.from(document.querySelectorAll('.nav-tab'));
  const activeTab = tabs.find(t => t.getAttribute('onclick')?.includes(tabId));
  if (activeTab) activeTab.classList.add('active');
}

function renderTelemetry(data) {
  const m = data.metrics || {};
  
  // Update KPIs
  document.getElementById('kpiTotalEvents').innerText = Number(m.total_events_consumed || 0).toLocaleString();
  document.getElementById('kpiProducerEps').innerText = m.producer_eps || 0;
  document.getElementById('kpiTotalThreats').innerText = Number(m.total_threats_detected || 0).toLocaleString();
  document.getElementById('kpiActiveIncidents').innerText = Number(m.total_alerts_generated || 0).toLocaleString();
  document.getElementById('kpiProcessingLatency').innerText = `${m.event_processing_latency_ms || 0} ms`;
  document.getElementById('kpiPendingApprovals').innerText = (data.pending_approvals || []).filter(a => a.status === 'PENDING_APPROVAL').length;

  // SPA Performance Tab Stats
  document.getElementById('perfProducerEps').innerText = `${m.producer_eps || 0} EPS`;
  document.getElementById('perfConsumerEps').innerText = `${m.consumer_eps || 0} EPS`;
  document.getElementById('perfConsumerLag').innerText = `${m.consumer_lag || 0} msgs`;
  document.getElementById('perfActivePartitions').innerText = `${m.active_partitions || 3}`;
  document.getElementById('perfEventProcLat').innerText = `${m.event_processing_latency_ms || 0} ms`;
  document.getElementById('perfWindowLat').innerText = `${m.window_processing_time_ms || 0} ms`;
  document.getElementById('perfDetLat').innerText = `${m.detection_latency_ms || 0} ms`;
  document.getElementById('perfAgentLat').innerText = `${m.agent_investigation_latency_ms || 0} ms`;
  document.getElementById('perfDroppedEvents').innerText = `${m.total_dropped_events || 0}`;
  document.getElementById('perfDuplicateEvents').innerText = `${m.total_duplicate_events || 0}`;

  // Update Throughput History
  throughputHistory.push(m.consumer_eps || 0);
  if (throughputHistory.length > MAX_HISTORY) throughputHistory.shift();
  renderThroughputChart();

  // Render Live Events Table
  if (data.events && data.events.length > 0) {
    renderLiveEvents(data.events);
  }

  // Render Threat Alerts Table
  if (data.threats && data.threats.length > 0) {
    renderThreatAlerts(data.threats);
  }

  // Render Multi-Agent Investigation
  if (data.investigations && data.investigations.length > 0) {
    renderAgentInvestigations(data.investigations);
  }

  // Render HITL Approvals
  renderHitlApprovals(data.pending_approvals || []);
}

function renderLiveEvents(events) {
  const tbody = document.getElementById('liveEventsTableBody');
  tbody.innerHTML = '';
  
  // Show most recent at top
  const reversed = [...events].reverse();
  reversed.forEach(ev => {
    const tr = document.createElement('tr');
    const isAtk = ev.is_attack;
    const cat = ev.category || 'Benign';
    
    // Update attack breakdown count
    attackCounts[cat] = (attackCounts[cat] || 0) + 1;
    
    const badgeClass = isAtk ? 'badge-high' : 'badge-benign';
    const ts = ev.timestamp ? ev.timestamp.substring(11, 19) : '--:--:--';
    const durMs = ev['Flow Duration'] ? (ev['Flow Duration'] / 1000).toFixed(1) : 0;
    
    tr.innerHTML = `
      <td>${ts}</td>
      <td style="color:${isAtk ? 'var(--accent-crimson)' : 'var(--primary-cyan)'}">${ev.src_ip}</td>
      <td>${ev.dst_ip}</td>
      <td>${ev.dst_port}</td>
      <td>${ev.protocol === 6 ? 'TCP' : ev.protocol === 17 ? 'UDP' : ev.protocol}</td>
      <td>${ev['Total Fwd Packets'] || 1}</td>
      <td>${durMs} ms</td>
      <td><span class="badge ${badgeClass}">${cat}</span></td>
    `;
    tbody.appendChild(tr);
  });

  renderAttackDistribution();
}

function renderAttackDistribution() {
  const container = document.getElementById('attackDistributionList');
  container.innerHTML = '';
  
  const total = Object.values(attackCounts).reduce((a, b) => a + b, 0);
  if (total === 0) return;

  const entries = Object.entries(attackCounts).sort((a, b) => b[1] - a[1]);
  entries.forEach(([cat, count]) => {
    const pct = ((count / total) * 100).toFixed(1);
    const div = document.createElement('div');
    div.innerHTML = `
      <div style="display:flex; justify-content:space-between; font-size:0.75rem; margin-bottom:0.2rem;">
        <span>${cat}</span>
        <span style="font-family:var(--font-mono); color:var(--text-dim);">${count} (${pct}%)</span>
      </div>
      <div style="background:rgba(255,255,255,0.05); border-radius:4px; height:6px; overflow:hidden;">
        <div style="background:${cat === 'Benign' ? 'var(--text-dim)' : 'var(--primary-cyan)'}; width:${pct}%; height:100%;"></div>
      </div>
    `;
    container.appendChild(div);
  });
}

function renderThreatAlerts(threats) {
  const tbody = document.getElementById('threatAlertsTableBody');
  tbody.innerHTML = '';
  
  const reversed = [...threats].reverse();
  reversed.forEach(t => {
    const tr = document.createElement('tr');
    const sev = (t.severity || 'MEDIUM').toLowerCase();
    const badgeClass = `badge-${sev}`;
    const ts = t.timestamp ? t.timestamp.substring(11, 19) : '--:--:--';
    const evidenceStr = (t.supporting_evidence || []).join('; ');
    
    tr.innerHTML = `
      <td style="color:var(--primary-cyan); font-weight:600;">${t.threat_id}</td>
      <td>${ts}</td>
      <td><span class="badge ${badgeClass}">${t.severity}</span></td>
      <td><strong>${t.attack_category}</strong></td>
      <td style="color:var(--accent-crimson); font-weight:600;">${t.src_ip}</td>
      <td>${t.dst_ip}</td>
      <td>${(t.confidence_score * 100).toFixed(1)}%</td>
      <td style="max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${evidenceStr}">${evidenceStr}</td>
      <td style="font-size:0.7rem; color:var(--text-muted);">${t.detection_method}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderAgentInvestigations(investigations) {
  const latest = investigations[investigations.length - 1];
  if (!latest) return;

  document.getElementById('activeAgentBadge').innerText = latest.status || 'COMPLETED';
  document.getElementById('activeAgentBadge').className = `badge ${latest.status === 'RESOLVED' ? 'badge-low' : 'badge-high'}`;

  // Steps
  const container = document.getElementById('agentStepContainer');
  container.innerHTML = '';
  
  const steps = latest.workflow_audit_trail || [];
  steps.forEach(st => {
    const item = document.createElement('div');
    item.className = 'agent-step-item';
    const dateStr = new Date(st.timestamp * 1000).toLocaleTimeString();
    
    item.innerHTML = `
      <div class="step-meta">
        <span class="step-agent-name">${st.agent}</span>
        <span class="step-time">${dateStr}</span>
      </div>
      <div class="step-action">${st.action}</div>
      <div class="step-detail">${st.details}</div>
    `;
    container.appendChild(item);
  });

  // Latest Report Panel
  const repPanel = document.getElementById('latestInvestigationReport');
  const mitre = latest.mitre_attack || {};
  const mit = latest.recommended_mitigations || [];
  
  repPanel.innerHTML = `
    <div style="margin-bottom:1rem; border-bottom:1px solid var(--border-subtle); padding-bottom:0.8rem;">
      <h3 style="font-size:1.1rem; color:var(--text-main); margin-bottom:0.3rem;">Incident Report: ${latest.incident_id}</h3>
      <span class="badge ${latest.threat_summary?.severity === 'CRITICAL' ? 'badge-critical' : 'badge-high'}">${latest.threat_summary?.severity}</span>
      <span style="font-size:0.8rem; color:var(--text-muted); margin-left:0.5rem;">Target: ${latest.threat_summary?.destination_ip}</span>
    </div>

    <div style="background:rgba(0,242,254,0.05); border:1px solid rgba(0,242,254,0.2); border-radius:var(--radius-md); padding:0.9rem; margin-bottom:1rem;">
      <div style="font-size:0.75rem; color:var(--primary-cyan); font-weight:700; text-transform:uppercase; margin-bottom:0.3rem;">
        MITRE ATT&CK Knowledge Base Mapping (Local RAG)
      </div>
      <div style="font-size:0.95rem; font-weight:700; color:#ffffff;">
        ${mitre.technique_id}: ${mitre.technique_name}
      </div>
      <div style="font-size:0.8rem; color:var(--text-muted); margin-top:0.2rem;">
        <strong>Tactic:</strong> ${mitre.tactic} | <strong>Objective:</strong> ${mitre.adversary_objective}
      </div>
    </div>

    <div>
      <h4 style="font-size:0.85rem; color:var(--text-muted); margin-bottom:0.5rem;">Recommended Defensive Countermeasures:</h4>
      <ul style="list-style:none; padding:0; display:flex; flex-direction:column; gap:0.4rem;">
        ${mit.map(m => `
          <li style="font-size:0.8rem; background:rgba(15,23,42,0.6); padding:0.5rem 0.8rem; border-radius:4px; border-left:3px solid ${m.automated_safe ? 'var(--accent-emerald)' : 'var(--accent-crimson)'};">
            <strong>${m.action}</strong> [${m.type}]
            <div style="color:var(--text-dim); font-size:0.75rem;">${m.rationale}</div>
          </li>
        `).join('')}
      </ul>
    </div>
  `;
}

function renderHitlApprovals(approvals) {
  const container = document.getElementById('hitlApprovalsContainer');
  if (!approvals || approvals.length === 0) {
    container.innerHTML = '<p style="color:var(--text-dim);">No pending defensive actions requiring human sign-off.</p>';
    return;
  }

  container.innerHTML = '';
  approvals.forEach(appr => {
    const card = document.createElement('div');
    card.style = "background:rgba(15,23,42,0.8); border:1px solid var(--border-subtle); border-radius:var(--radius-md); padding:1rem; margin-bottom:0.8rem;";
    
    const isPending = appr.status === 'PENDING_APPROVAL';
    
    card.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
        <span style="font-weight:700; color:var(--accent-crimson); font-size:0.85rem;">[${appr.risk_level} RISK ACTION]</span>
        <span class="badge ${isPending ? 'badge-high' : appr.status === 'APPROVED' ? 'badge-low' : 'badge-critical'}">${appr.status}</span>
      </div>
      <div style="font-size:0.9rem; font-weight:600; color:var(--text-main); margin-bottom:0.3rem;">
        ${appr.action_name}
      </div>
      <div style="font-size:0.78rem; color:var(--text-muted); margin-bottom:0.6rem;">
        Target: <code>${appr.target_entity}</code> | Rationale: ${appr.rationale}
      </div>
      ${isPending ? `
        <div>
          <button class="btn-approve" onclick="handleHitlAction('${appr.approval_id}', 'APPROVE')">✓ Authorize Action</button>
          <button class="btn-reject" onclick="handleHitlAction('${appr.approval_id}', 'REJECT')">✕ Dismiss / Reject</button>
        </div>
      ` : `
        <div style="font-size:0.75rem; color:var(--text-dim);">Signed-off by SOC Analyst</div>
      `}
    `;
    container.appendChild(card);
  });
}

async function handleHitlAction(approvalId, action) {
  try {
    const res = await fetch(`/api/approvals/${approvalId}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: action, analyst_notes: `Analyst decision: ${action}` })
    });
    if (res.ok) {
      console.log(`Action ${action} submitted for ${approvalId}`);
    }
  } catch (err) {
    console.error("Error executing HITL action:", err);
  }
}

function renderThroughputChart() {
  const poly = document.getElementById('throughputPolyline');
  if (!poly || throughputHistory.length === 0) return;

  const maxVal = Math.max(100, ...throughputHistory) * 1.2;
  const w = 500;
  const h = 200;
  
  const points = throughputHistory.map((val, idx) => {
    const x = (idx / (MAX_HISTORY - 1)) * w;
    const y = h - ((val / maxVal) * h);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');

  poly.setAttribute('points', points);
}

// Stream Control handlers
async function toggleStreamPause() {
  await fetch('/api/stream/pause', { method: 'POST' });
  document.getElementById('btnPauseStream').style.display = 'none';
  document.getElementById('btnResumeStream').style.display = 'inline-block';
}

async function resumeStream() {
  await fetch('/api/stream/resume', { method: 'POST' });
  document.getElementById('btnPauseStream').style.display = 'inline-block';
  document.getElementById('btnResumeStream').style.display = 'none';
}

async function changeSpeed(eps) {
  await fetch('/api/stream/speed', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ eps: parseFloat(eps) })
  });
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initWebSocket();
});
