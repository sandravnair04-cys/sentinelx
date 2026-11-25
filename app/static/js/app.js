/* SENTINELX single-page SOC console */
(function () {
  'use strict';
  const S = window.SentinelX;
  const page = document.getElementById('page');
  const PAGE_TITLES = {
    overview: ['Overview Dashboard', 'Overview'],
    monitoring: ['Live Security Monitoring', 'Monitoring'],
    detection: ['Threat Detection', 'Detection'],
    investigation: ['AI Investigation Centre', 'Investigation'],
    incidents: ['Incident Management', 'Incidents'],
    response: ['Incident Response Centre', 'Response'],
    agents: ['AI Agent Monitoring', 'Agents'],
    intel: ['Threat Intelligence', 'Intelligence'],
    reports: ['Security Reports', 'Reports'],
    settings: ['System Settings', 'Settings']
  };
  let charts = [];
  let timers = [];
  let currentPage = 'overview';

  function clearTimers() { timers.forEach(clearInterval); timers = []; }
  function destroyCharts() { charts.forEach(function (c) { try { c.destroy(); } catch (e) {} }); charts = []; }
  function setHtml(html) { page.innerHTML = html; }
  function loading() { setHtml('<div class="card loading-box"><span class="spinner"></span> Loading live data…</div>'); }
  function fail(err) { setHtml('<div class="card"><div class="empty">Unable to load data: ' + S.esc(err.message) + '</div></div>'); S.toast(err.message, 'err'); }

  function chart(id, config) {
    const el = document.getElementById(id);
    if (!el || typeof Chart === 'undefined') return;
    charts.push(new Chart(el.getContext('2d'), config));
  }
  const CHART_COLORS = { blue: '#00b4ff', green: '#24e0a1', orange: '#ffb02e', red: '#ff4d6d', purple: '#a06bff' };

  function pageHead(title, subtitle, actions) {
    return '<div class="page-head"><div><h2>' + S.esc(title) + '</h2><p>' + S.esc(subtitle) + '</p></div>' +
      (actions ? '<div class="head-actions">' + actions + '</div>' : '') + '</div>';
  }

  /* ===================== 1. OVERVIEW ===================== */
  async function overview() {
    loading();
    try {
      const [stats, activity, recent, agents] = await Promise.all([
        S.api('/dashboard/stats'), S.api('/dashboard/activity?hours=24'),
        S.api('/dashboard/recent?limit=10'), S.api('/dashboard/agent-status')
      ]);
      const sd = stats.severity_distribution || {};
      const kpis = [
        ['Total events collected', stats.total_events, 'blue', '◉', 'Lab + collector sources'],
        ['Total security alerts', stats.total_alerts, 'purple', '◈', 'Rule & Sigma matches'],
        ['Critical threats', stats.critical_threats, 'red', '⚠', 'Critical incidents'],
        ['High-risk incidents', stats.high_risk_incidents, 'orange', '▣', 'Risk score ≥ 60'],
        ['Active investigations', stats.active_investigations, 'blue', '✦', 'Running / awaiting approval'],
        ['Resolved incidents', stats.resolved_incidents, 'green', '✓', 'Closed as resolved']
      ];
      setHtml(
        pageHead('Security Operations Overview', 'Real database-backed metrics · simulated lab data unless stated otherwise',
          '<span class="badge b-info">MODE: ' + S.esc(String(stats.llm_mode).toUpperCase()) + '</span>') +
        '<div class="grid kpis">' + kpis.map(function (k) {
          return '<div class="card kpi accent-' + k[2] + '"><div class="kpi-icon">' + k[3] + '</div>' +
            '<div class="kpi-label">' + S.esc(k[0]) + '</div><div class="kpi-value">' + S.esc(k[1]) + '</div>' +
            '<div class="kpi-foot">' + S.esc(k[4]) + '</div></div>';
        }).join('') + '</div>' +
        '<div class="grid cols-32" style="margin-top:16px">' +
          '<div class="card"><div class="card-head"><div class="card-title">Event Activity Over Time</div>' +
            '<div class="right card-sub">Last 24 hours · UTC</div></div><div class="chart-box lg"><canvas id="ch-activity"></canvas></div></div>' +
          '<div class="card"><div class="card-head"><div class="card-title">Alert Severity Distribution</div></div>' +
            '<div class="chart-box lg"><canvas id="ch-severity"></canvas></div></div>' +
        '</div>' +
        '<div class="grid cols-2" style="margin-top:16px">' +
          '<div class="card"><div class="card-head"><div class="card-title">Recent Security Events</div>' +
            '<a class="btn btn-ghost btn-sm right" href="#/monitoring">View all →</a></div>' +
            eventTable(recent.events, true) + '</div>' +
          '<div class="card"><div class="card-head"><div class="card-title">Latest Incident Summaries</div>' +
            '<a class="btn btn-ghost btn-sm right" href="#/incidents">Manage →</a></div>' +
            incidentTable(recent.incidents) + '</div>' +
        '</div>' +
        '<div class="card" style="margin-top:16px"><div class="card-head"><div class="card-title">AI Agent Status</div>' +
          '<div class="right card-sub">Execution statistics are read from the database</div></div>' +
          '<div class="grid cols-3">' + (agents.agents || []).map(function (a) {
            return '<div class="flex" style="justify-content:space-between;border:1px solid var(--line);border-radius:9px;padding:10px">' +
              '<div><div class="small" style="font-weight:700">' + S.esc(a.agent_key) + '</div>' +
              '<div class="tiny muted">' + a.executions + ' executions · ' + a.successes + ' successful</div></div>' +
              '<span class="badge ' + (a.last_run ? 'b-low' : 'b-muted') + '">' + (a.last_run ? 'Active' : 'Idle') + '</span></div>';
          }).join('') + '</div></div>'
      );
      const labels = (activity.series || []).map(function (p) { return p.timestamp.slice(11, 16); });
      chart('ch-activity', {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            { label: 'Events', data: activity.series.map(function (p) { return p.events; }), borderColor: CHART_COLORS.blue, backgroundColor: 'rgba(0,180,255,.12)', fill: true, tension: .35, borderWidth: 2, pointRadius: 0 },
            { label: 'Failures', data: activity.series.map(function (p) { return p.failures; }), borderColor: CHART_COLORS.red, backgroundColor: 'transparent', tension: .35, borderWidth: 2, pointRadius: 0 },
            { label: 'Successes', data: activity.series.map(function (p) { return p.successes; }), borderColor: CHART_COLORS.green, backgroundColor: 'transparent', tension: .35, borderWidth: 2, pointRadius: 0 }
          ]
        },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#8fa3c4', boxWidth: 12 } } }, scales: { x: { ticks: { color: '#62779c', maxTicksLimit: 12 }, grid: { color: '#15223a' } }, y: { beginAtZero: true, ticks: { color: '#62779c' }, grid: { color: '#15223a' } } } }
      });
      chart('ch-severity', {
        type: 'doughnut',
        data: { labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], datasets: [{ data: [sd.LOW || 0, sd.MEDIUM || 0, sd.HIGH || 0, sd.CRITICAL || 0], backgroundColor: [CHART_COLORS.green, CHART_COLORS.orange, '#ff8a3d', CHART_COLORS.red], borderColor: '#0c1528', borderWidth: 3 }] },
        options: { responsive: true, maintainAspectRatio: false, cutout: '66%', plugins: { legend: { position: 'bottom', labels: { color: '#8fa3c4', boxWidth: 12 } } } }
      });
    } catch (e) { fail(e); }
  }

  function eventTable(events, compact) {
    if (!events || !events.length) return '<div class="empty">No events collected yet.</div>';
    return '<div class="table-wrap"><table class="tbl"><thead><tr><th>Time (UTC)</th><th>Event</th><th>Action</th><th>User</th><th>Source IP</th><th>Host</th></tr></thead><tbody>' +
      events.map(function (e) {
        return '<tr><td class="nowrap tiny">' + S.esc(S.fmtDate(e.timestamp)) + '</td>' +
          '<td class="mono">' + S.esc(e.event_code) + '</td>' +
          '<td>' + actionBadge(e.action) + '</td>' +
          '<td>' + S.esc(e.username || '—') + '</td><td class="mono">' + S.esc(e.source_ip || '—') + '</td>' +
          '<td class="truncate">' + S.esc(e.host || '—') + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }
  function actionBadge(action) {
    const a = String(action || 'unknown');
    const cls = a === 'failure' ? 'b-critical' : a === 'success' ? 'b-info' : a === 'privilege' ? 'b-purple' : a === 'network' ? 'b-high' : a === 'process' ? 'b-high' : 'b-muted';
    return '<span class="badge ' + cls + '">' + S.esc(a) + '</span>';
  }
  function incidentTable(items) {
    if (!items || !items.length) return '<div class="empty">No incidents recorded yet.</div>';
    return '<div class="table-wrap"><table class="tbl"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Score</th><th>Status</th></tr></thead><tbody>' +
      items.map(function (i) {
        return '<tr><td class="mono">' + S.esc(i.incident_id) + '</td><td class="truncate">' + S.esc(i.title) + '</td>' +
          '<td>' + S.sevBadge(i.severity) + '</td><td class="mono">' + S.esc(i.risk_score) + '</td>' +
          '<td>' + S.statusBadge(i.status) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  /* ===================== 2. LIVE MONITORING ===================== */
  async function monitoring() {
    setHtml(
      pageHead('Live Security Monitoring', 'Auto-refreshing event feed · polls the database every 6 seconds',
        '<button class="btn btn-primary btn-sm" id="run-detection">▶ Run Detection</button>' +
        '<button class="btn btn-sm" id="run-correlate">◇ Correlate Events</button>') +
      '<div class="card"><div class="card-head"><div class="card-title">Event Stream</div>' +
        '<div class="right card-sub"><span class="pulse"></span> <span id="event-count">—</span> events</div></div>' +
        '<div class="filters"><input class="input" id="f-search" placeholder="Search message / event code…">' +
        '<select class="input" id="f-action"><option value="">All actions</option><option>failure</option><option>success</option><option>privilege</option><option>process</option><option>network</option><option>unknown</option></select>' +
        '<select class="input" id="f-source"><option value="">All sources</option><option>windows</option><option>linux</option><option>wazuh</option><option>simulation</option><option>manual</option></select>' +
        '<button class="btn btn-sm" id="f-apply">Apply</button></div>' +
        '<div id="monitor-table"><div class="loading-box"><span class="spinner"></span></div></div></div>'
    );
    async function load() {
      const q = new URLSearchParams({ limit: '100' });
      const search = document.getElementById('f-search').value.trim();
      const action = document.getElementById('f-action').value;
      const source = document.getElementById('f-source').value;
      if (search) q.set('search', search);
      if (action) q.set('action', action);
      if (source) q.set('source_type', source);
      try {
        const data = await S.api('/events?' + q.toString());
        document.getElementById('event-count').textContent = data.total;
        document.getElementById('monitor-table').innerHTML = eventTable(data.items);
      } catch (e) { S.toast(e.message, 'err'); }
    }
    document.getElementById('f-apply').onclick = load;
    document.getElementById('run-detection').onclick = async function () {
      const btn = this; btn.disabled = true;
      try { const r = await S.api('/detection/run', { method: 'POST' }); S.toast('Detection complete: ' + r.created + ' new alert(s)', 'ok'); load(); }
      catch (e) { S.toast(e.message, 'err'); } finally { btn.disabled = false; }
    };
    document.getElementById('run-correlate').onclick = async function () {
      try { const r = await S.api('/incidents/correlate', { method: 'POST' }); S.toast('Correlation complete: ' + r.incidents_created + ' new incident(s)', 'ok'); }
      catch (e) { S.toast(e.message, 'err'); }
    };
    await load();
    timers.push(setInterval(function () { if (document.getElementById('monitor-table')) load(); }, 6000));
  }

  /* ===================== 3. THREAT DETECTION ===================== */
  async function detection() {
    loading();
    try {
      const [rules, alerts] = await Promise.all([S.api('/detection/rules'), S.api('/alerts?limit=100')]);
      setHtml(
        pageHead('Threat Detection', 'Configurable rule-based engine with Sigma-compatible rules and explainable evidence',
          '<button class="btn btn-primary btn-sm" id="run-det">▶ Run Detection</button>' +
          '<button class="btn btn-sm" id="sigma-reload">↻ Reload Sigma Rules</button>') +
        '<div class="grid cols-2">' +
          '<div class="card"><div class="card-head"><div class="card-title">Detection Rules</div><div class="right card-sub">' + rules.items.length + ' rules</div></div>' +
            '<div class="table-wrap"><table class="tbl"><thead><tr><th>Rule</th><th>Category</th><th>Severity</th><th>Enabled</th></tr></thead><tbody>' +
            rules.items.map(function (r) {
              return '<tr><td class="truncate" title="' + S.esc(r.description) + '">' + S.esc(r.name) +
                '<div class="tiny muted">' + S.esc(r.source) + '</div></td><td>' + S.esc(r.category) + '</td>' +
                '<td>' + S.sevBadge(r.severity) + '</td><td><button class="btn btn-sm ' + (r.enabled ? 'btn-success' : 'btn-warn') + '" data-rule="' + r.id + '" data-enabled="' + (!r.enabled) + '">' + (r.enabled ? 'ON' : 'OFF') + '</button></td></tr>';
            }).join('') + '</tbody></table></div></div>' +
          '<div class="card"><div class="card-head"><div class="card-title">Generated Alerts</div><div class="right card-sub">' + alerts.total + ' total</div></div>' +
            '<div class="table-wrap"><table class="tbl"><thead><tr><th>Time</th><th>Rule</th><th>Severity</th><th>Source IP</th><th>Conf.</th></tr></thead><tbody>' +
            (alerts.items.length ? alerts.items.map(function (a) {
              return '<tr><td class="tiny nowrap">' + S.esc(S.fmtDate(a.created_at)) + '</td>' +
                '<td class="truncate"><b>' + S.esc(a.title) + '</b><div class="tiny muted">' + S.esc(a.category) + '</div></td>' +
                '<td>' + S.sevBadge(a.severity) + '</td><td class="mono">' + S.esc(a.source_ip || '—') + '</td><td class="mono">' + S.esc(a.confidence) + '</td></tr>';
            }).join('') : '<tr><td colspan="5" class="empty">No alerts yet. Run detection.</td></tr>') + '</tbody></table></div></div>' +
        '</div>'
      );
      document.querySelectorAll('[data-rule]').forEach(function (b) {
        b.onclick = async function () {
          try {
            await S.api('/detection/rules/' + b.dataset.rule, { method: 'PATCH', body: { enabled: b.dataset.enabled === 'true' } });
            S.toast('Rule updated', 'ok'); detection();
          } catch (e) { S.toast(e.message, 'err'); }
        };
      });
      document.getElementById('run-det').onclick = async function () {
        try { const r = await S.api('/detection/run', { method: 'POST' }); S.toast('Created ' + r.created + ' new alert(s)', 'ok'); detection(); }
        catch (e) { S.toast(e.message, 'err'); }
      };
      document.getElementById('sigma-reload').onclick = async function () {
        try { const r = await S.api('/detection/sigma/reload', { method: 'POST' }); S.toast('Sigma rules loaded: ' + r.loaded, 'ok'); }
        catch (e) { S.toast(e.message, 'err'); }
      };
    } catch (e) { fail(e); }
  }

  /* ===================== 4. AI INVESTIGATION CENTRE ===================== */
  async function investigation() {
    loading();
    try {
      const incidents = await S.api('/incidents?limit=100');
      setHtml(
        pageHead('AI Investigation Centre', 'Multi-agent LangGraph workflow · evidence-based, human-approved',
          '<button class="btn btn-primary btn-sm" id="start-inv">✦ Start AI Investigation</button>') +
        '<div class="card"><div class="card-head"><div class="card-title">Investigation Workflow</div>' +
          '<div class="right card-sub">Log Analysis → Threat Detection → Investigation → Risk → Response → Report</div></div>' +
          '<div id="wf-area" class="empty">Start an investigation to visualise agent execution.</div></div>' +
        '<div class="card" style="margin-top:16px"><div class="card-head"><div class="card-title">Select Incident</div></div>' +
          '<div class="filters"><select class="input" id="inv-incident" style="min-width:420px">' +
          (incidents.items.length ? incidents.items.map(function (i) {
            return '<option value="' + S.esc(i.incident_id) + '">' + S.esc(i.incident_id) + ' · ' + S.esc(i.title) + ' (' + S.esc(i.severity) + ')</option>';
          }).join('') : '<option value="">No incidents available</option>') + '</select>' +
          '<span class="small muted" id="inv-status"></span></div></div>' +
        '<div id="inv-results"></div>'
      );
      document.getElementById('start-inv').onclick = async function () {
        const id = document.getElementById('inv-incident').value;
        if (!id) { S.toast('No incident selected', 'err'); return; }
        const btn = this; btn.disabled = true;
        document.getElementById('inv-status').innerHTML = '<span class="spinner"></span> Agents investigating…';
        try {
          const r = await S.api('/investigations/start', { method: 'POST', body: { incident_id: id, started_by: S.getUser().username } });
          S.toast('Investigation ' + r.status + ' · session ' + r.session_uid.slice(0, 8), 'ok');
          await loadSession(r.session_uid);
        } catch (e) { S.toast(e.message, 'err'); }
        finally { btn.disabled = false; document.getElementById('inv-status').textContent = ''; }
      };
      const sessions = await S.api('/investigations?limit=10');
      if (sessions.items.length) await loadSession(sessions.items[0].session_uid, true);
    } catch (e) { fail(e); }
  }

  async function loadSession(uid, silent) {
    try {
      const s = await S.api('/investigations/' + uid);
      const st = s.state || {};
      const steps = [
        ['Log Analysis', st.log_analysis, 'log_analysis'],
        ['Threat Detection', st.detection_analysis, 'threat_detection'],
        ['Investigation', st.investigation_findings, 'investigation'],
        ['Risk Assessment', st.risk_assessment, 'risk_assessment'],
        ['Incident Response', st.requires_approval ? { summary: (st.response_recommendations || []).length + ' action(s) queued for approval' } : null, 'incident_response'],
        ['Report Generation', st.report, 'report_generation']
      ];
      const execMap = {};
      (s.executions || []).forEach(function (e) { execMap[e.agent_key] = e; });
      const wf = steps.map(function (step, i) {
        const exec = execMap[step[2]];
        let status = 'Idle', cls = '';
        if (exec) { status = exec.status === 'completed' ? 'Completed' : exec.status === 'failed' ? 'Failed' : exec.status; cls = exec.status === 'completed' ? 'done' : exec.status === 'failed' ? 'failed' : ''; }
        if (step[2] === 'incident_response' && s.status === 'waiting_approval') { status = 'Waiting for Approval'; cls = 'waiting'; }
        return '<div class="wf-step ' + cls + '"><div class="wf-num">STEP ' + (i + 1) + '</div>' +
          '<div class="wf-name">' + S.esc(step[0]) + '</div><div class="wf-status">' + S.esc(status) + '</div>' +
          '<div class="wf-time">' + (exec && exec.duration_ms !== undefined ? exec.duration_ms + ' ms' : '—') + '</div></div>';
      }).join('');
      document.getElementById('wf-area').innerHTML = '<div class="workflow">' + wf + '</div>' +
        '<div class="tiny muted">Session: <span class="code-chip">' + S.esc(s.session_uid) + '</span> · Mode: <b>' + S.esc(s.llm_mode) + '</b> · Status: ' + S.statusBadge(s.status) + '</div>';
      const findings = steps.filter(function (x) { return x[1]; }).map(function (x) {
        const v = x[1];
        const text = v.summary || v.explanation || v.narrative || v.executive_summary || v.correlation_explanation || JSON.stringify(v).slice(0, 400);
        return '<div class="card"><div class="card-head"><div class="card-title">' + S.esc(x[0]) + '</div>' +
          '<div class="right">' + (v.confidence !== undefined ? '<span class="badge b-info">confidence ' + S.esc(v.confidence) + '</span>' : '') + '</div></div>' +
          '<div class="prose">' + S.esc(text) + '</div>' +
          (v.factors ? '<div class="divider"></div><div class="tiny muted"><b>Risk factors:</b><br>' + v.factors.map(function (f) { return '• ' + S.esc(typeof f === 'string' ? f : f.factor + ' +' + f.points); }).join('<br>') + '</div>' : '') +
          (v.evidence_basis && v.evidence_basis.length ? '<div class="divider"></div><div class="tiny muted"><b>Evidence basis:</b> ' + v.evidence_basis.slice(0, 6).map(function (e) { return '<span class="code-chip">' + S.esc(e) + '</span>'; }).join(' ') + '</div>' : '') +
          '</div>';
      }).join('');
      let approvalHtml = '';
      if (s.status === 'waiting_approval') {
        approvalHtml = '<div class="card" style="border-color:rgba(255,176,46,.5)"><div class="card-head"><div class="card-title">⚠ Human Approval Checkpoint</div></div>' +
          '<div class="prose">The response agent queued <b>' + (st.response_recommendations || []).length + '</b> recommendation(s). No action will be executed until an analyst decides. Execution is simulated only.</div>' +
          '<div class="filters" style="margin-top:12px"><input class="input" id="ap-analyst" placeholder="Analyst username" value="' + S.esc(S.getUser().username) + '">' +
          '<input class="input" id="ap-reason" placeholder="Reason (optional)">' +
          '<select class="input" id="ap-decision"><option value="approved">Approve</option><option value="rejected">Reject</option></select>' +
          '<button class="btn btn-primary btn-sm" id="ap-submit">Submit Decision</button></div></div>';
      }
      const timeline = (st.investigation_findings && st.investigation_findings.timeline_summary) ? '' : '';
      document.getElementById('inv-results').innerHTML = '<div class="grid cols-2" style="margin-top:16px">' + (findings || '<div class="card empty">No agent findings yet.</div>') + '</div>' +
        (approvalHtml ? '<div style="margin-top:16px">' + approvalHtml + '</div>' : '');
      const btn = document.getElementById('ap-submit');
      if (btn) btn.onclick = async function () {
        try {
          await S.api('/investigations/' + uid + '/resume', {
            method: 'POST',
            body: { decision: document.getElementById('ap-decision').value, analyst: document.getElementById('ap-analyst').value, reason: document.getElementById('ap-reason').value, role: S.getUser().role }
          });
          S.toast('Decision recorded', 'ok'); await loadSession(uid, true);
        } catch (e) { S.toast(e.message, 'err'); }
      };
      if (!silent) S.toast('Investigation loaded', 'ok');
    } catch (e) { S.toast(e.message, 'err'); }
  }

  /* ===================== 5. INCIDENTS ===================== */
  async function incidents() {
    loading();
    try {
      const data = await S.api('/incidents?limit=200');
      setHtml(
        pageHead('Incident Management', 'Complete incident lifecycle with evidence, risk scoring and audit trail',
          '<button class="btn btn-sm" id="inc-correlate">◇ Run Correlation</button>') +
        '<div class="card"><div class="card-head"><div class="card-title">Incidents</div><div class="right card-sub">' + data.total + ' total</div></div>' +
        '<div class="filters"><input class="input" id="i-search" placeholder="Search ID, title, username…">' +
        '<select class="input" id="i-status"><option value="">All statuses</option>' +
        ['New', 'Investigating', 'Pending Approval', 'Contained', 'Resolved', 'False Positive'].map(function (s) { return '<option>' + s + '</option>'; }).join('') +
        '</select><select class="input" id="i-sev"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>' +
        '<button class="btn btn-sm" id="i-apply">Filter</button></div>' +
        '<div id="inc-table">' + incidentFullTable(data.items) + '</div></div>'
      );
      document.getElementById('i-apply').onclick = async function () {
        const q = new URLSearchParams({ limit: '200' });
        const s = document.getElementById('i-search').value.trim();
        const st = document.getElementById('i-status').value, sv = document.getElementById('i-sev').value;
        if (s) q.set('search', s); if (st) q.set('status', st); if (sv) q.set('severity', sv);
        try { const d = await S.api('/incidents?' + q); document.getElementById('inc-table').innerHTML = incidentFullTable(d.items); }
        catch (e) { S.toast(e.message, 'err'); }
      };
      document.getElementById('inc-correlate').onclick = async function () {
        try { const r = await S.api('/incidents/correlate', { method: 'POST' }); S.toast('Created ' + r.incidents_created + ' incident(s)', 'ok'); incidents(); }
        catch (e) { S.toast(e.message, 'err'); }
      };
      bindIncidentRows(data.items);
    } catch (e) { fail(e); }
  }

  function incidentFullTable(items) {
    if (!items.length) return '<div class="empty">No incidents found.</div>';
    return '<div class="table-wrap"><table class="tbl"><thead><tr><th>Incident ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Risk</th><th>Status</th><th>Detected</th><th></th></tr></thead><tbody>' +
      items.map(function (i) {
        return '<tr><td class="mono">' + S.esc(i.incident_id) + '</td><td class="truncate" title="' + S.esc(i.title) + '">' + S.esc(i.title) + '</td>' +
          '<td class="small">' + S.esc(i.category) + '</td><td>' + S.sevBadge(i.severity) + '</td>' +
          '<td><b class="mono">' + S.esc(i.risk_score) + '</b></td><td>' + S.statusBadge(i.status) + '</td>' +
          '<td class="tiny nowrap">' + S.esc(S.fmtDate(i.detection_time)) + '</td>' +
          '<td><button class="btn btn-sm" data-inc="' + S.esc(i.incident_id) + '">Open</button></td></tr>';
      }).join('') + '</tbody></table></div>';
  }
  function bindIncidentRows(items) {
    document.querySelectorAll('[data-inc]').forEach(function (b) {
      b.onclick = function () { openIncident(b.dataset.inc); };
    });
  }
  async function openIncident(id) {
    S.modal('Incident ' + id, '<div class="loading-box"><span class="spinner"></span></div>',
      '<button class="btn btn-ghost" data-close>Close</button>');
    try {
      const i = await S.api('/incidents/' + id);
      const body =
        '<div class="detail-grid">' +
          detail('Title', i.title) + detail('Severity', i.severity) + detail('Risk score', i.risk_score + ' / 100') +
          detail('Status', i.status) + detail('Source IP', i.source_ip) + detail('Username', i.username) +
          detail('Host', i.host) + detail('Detection time', S.fmtDate(i.detection_time)) + detail('Category', i.category) +
        '</div>' +
        '<div class="divider"></div><div class="card-title">Investigation Findings</div><div class="prose">' + S.esc(i.finding_summary || 'No summary recorded.') + '</div>' +
        (i.mitre && i.mitre.length ? '<div class="flex" style="margin-top:10px">' + i.mitre.map(function (m) { return '<span class="code-chip">' + S.esc(m.name || m) + '</span>'; }).join('') + '</div>' : '') +
        '<div class="divider"></div><div class="card-title">Risk Factors</div>' +
        (i.risk_assessments && i.risk_assessments[0] ? i.risk_assessments[0].factors.map(function (f) {
          return '<div class="small">' + S.esc(f.factor) + ' <span class="badge b-info">+' + S.esc(f.points) + '</span> <span class="muted">' + S.esc(f.reason) + '</span></div>';
        }).join('') : '<div class="muted small">No factors recorded.</div>') +
        '<div class="divider"></div><div class="card-title">Timeline (' + (i.timeline || []).length + ' events)</div>' +
        '<div class="timeline">' + (i.timeline || []).slice(0, 25).map(function (t) {
          return '<div class="tl-item"><div class="tl-time">' + S.esc(S.fmtDate(t.timestamp)) + ' · ' + S.esc(t.code) + '</div>' +
            '<div class="tl-text">' + S.esc(t.description) + ' — ' + S.esc(t.source_ip || 'n/a') + '</div></div>';
        }).join('') + '</div>' +
        '<div class="divider"></div><div class="card-title">Evidence (' + i.evidence.length + ')</div>' +
        i.evidence.slice(0, 10).map(function (e) {
          return '<div class="small mono">' + S.esc(e.kind) + ' · ' + S.esc(e.event_uid || '') + ' · sha256:' + S.esc(e.hash_sha256.slice(0, 20)) + '… ' + S.esc(e.description) + '</div>';
        }).join('') +
        '<div class="divider"></div><div class="card-title">Audit Trail</div>' +
        i.audit.slice(0, 12).map(function (a) { return '<div class="tiny muted">' + S.esc(S.fmtDate(a.created_at)) + ' · ' + S.esc(a.actor) + ' · ' + S.esc(a.action) + '</div>'; }).join('');
      const foot =
        '<select class="input" id="upd-status" style="width:auto">' +
        ['New', 'Investigating', 'Pending Approval', 'Contained', 'Resolved', 'False Positive'].map(function (s) { return '<option ' + (s === i.status ? 'selected' : '') + '>' + s + '</option>'; }).join('') +
        '</select><input class="input" id="upd-note" placeholder="Resolution notes" style="width:220px">' +
        '<button class="btn btn-primary btn-sm" id="upd-save">Update Status</button>' +
        '<button class="btn btn-ghost" data-close>Close</button>';
      S.modal('Incident ' + id, body, foot);
      document.querySelectorAll('#modal-root [data-close]').forEach(function (b) { b.onclick = S.closeModal; });
      document.getElementById('upd-save').onclick = async function () {
        try {
          await S.api('/incidents/' + id, { method: 'PATCH', body: { status: document.getElementById('upd-status').value, resolution_notes: document.getElementById('upd-note').value } });
          S.toast('Incident updated', 'ok'); S.closeModal(); incidents();
        } catch (e) { S.toast(e.message, 'err'); }
      };
    } catch (e) { S.toast(e.message, 'err'); }
  }
  function detail(label, value) {
    return '<div class="detail-item"><label>' + S.esc(label) + '</label><div>' + S.esc(value === null || value === undefined || value === '' ? '—' : value) + '</div></div>';
  }

  /* ===================== 6. RESPONSE CENTRE ===================== */
  async function response() {
    loading();
    try {
      const [recs, history] = await Promise.all([S.api('/response/recommendations'), S.api('/response/history')]);
      const pending = recs.items.filter(function (r) { return r.status === 'pending'; });
      const decided = recs.items.filter(function (r) { return r.status !== 'pending'; });
      setHtml(
        pageHead('Incident Response Centre', 'Human approval required · simulated execution only · no real actions performed') +
        '<div class="grid cols-2">' +
          '<div class="card"><div class="card-head"><div class="card-title">Pending Approval (' + pending.length + ')</div></div>' +
            (pending.length ? pending.map(recCard).join('') : '<div class="empty">No actions awaiting approval.</div>') + '</div>' +
          '<div class="card"><div class="card-head"><div class="card-title">Decision History (' + decided.length + ')</div></div>' +
            (decided.length ? decided.map(recCard).join('') : '<div class="empty">No decisions recorded.</div>') + '</div>' +
        '</div>' +
        '<div class="card" style="margin-top:16px"><div class="card-head"><div class="card-title">Approval Records</div></div>' +
          (history.items.length ? '<div class="table-wrap"><table class="tbl"><thead><tr><th>Time</th><th>Recommendation</th><th>Decision</th><th>Analyst</th><th>Role</th><th>Reason</th></tr></thead><tbody>' +
            history.items.map(function (h) { return '<tr><td class="tiny">' + S.esc(S.fmtDate(h.created_at)) + '</td><td>#' + S.esc(h.recommendation_id) + '</td><td>' + S.statusBadge(h.action) + '</td><td>' + S.esc(h.analyst) + '</td><td>' + S.esc(h.analyst_role) + '</td><td class="truncate">' + S.esc(h.reason || '—') + '</td></tr>'; }).join('') + '</tbody></table></div>' : '<div class="empty">No approval records.</div>') + '</div>'
      );
      document.querySelectorAll('[data-decide]').forEach(function (b) {
        b.onclick = function () { decideModal(b.dataset.decide, b.dataset.action); };
      });
    } catch (e) { fail(e); }
  }
  function recCard(r) {
    const impact = ['block_ip', 'disable_account', 'isolate_endpoint'].includes(r.action_type);
    return '<div style="border:1px solid var(--line);border-radius:10px;padding:13px;margin-bottom:10px;background:#0a1427">' +
      '<div class="flex"><b class="small">' + S.esc(r.title) + '</b>' + S.statusBadge(r.status) + '</div>' +
      '<div class="tiny muted" style="margin:6px 0">' + S.esc(r.description) + '</div>' +
      '<div class="tiny"><b>Purpose:</b> ' + S.esc(r.purpose) + '</div>' +
      '<div class="tiny"><b>Risk if ignored:</b> ' + S.esc(r.risk_if_ignored) + '</div>' +
      '<div class="tiny muted" style="margin-top:6px">Target: <span class="code-chip">' + S.esc(r.target) + '</span> · Incident: ' + S.esc(r.incident_id || '—') +
      ' · Mode: ' + S.esc(r.execution_mode) + (impact ? ' · <span class="badge b-high">ADMIN REQUIRED</span>' : '') + '</div>' +
      (r.status === 'pending' ? '<div class="flex" style="margin-top:10px">' +
        '<button class="btn btn-success btn-sm" data-decide="' + r.id + '" data-action="approved">✓ Approve</button>' +
        '<button class="btn btn-danger btn-sm" data-decide="' + r.id + '" data-action="rejected">✕ Reject</button></div>' :
        '<div class="tiny muted" style="margin-top:8px">Decided by ' + S.esc(r.analyst) + ' · ' + S.esc(S.fmtDate(r.decided_at)) + '</div>') +
      '</div>';
  }
  function decideModal(id, decision) {
    S.modal('Confirm ' + (decision === 'approved' ? 'Approval' : 'Rejection'),
      '<div class="prose">You are recording a <b>' + S.esc(decision) + '</b> decision for recommendation #' + S.esc(id) + '.</div>' +
      '<div class="prose muted small" style="margin-top:8px">Execution is simulated. No real IP blocking, account disabling or host isolation will occur.</div>' +
      '<label class="field-label">Analyst identity (must match signed-in user)</label>' +
      '<input class="input" id="dec-user" value="' + S.esc(S.getUser().username) + '">' +
      '<label class="field-label">Reason</label><input class="input" id="dec-reason" placeholder="Document your decision">',
      '<button class="btn btn-ghost" data-close>Cancel</button><button class="btn btn-primary btn-sm" id="dec-confirm">Confirm Decision</button>');
    document.querySelectorAll('#modal-root [data-close]').forEach(function (b) { b.onclick = S.closeModal; });
    document.getElementById('dec-confirm').onclick = async function () {
      try {
        await S.api('/response/recommendations/' + id + '/' + (decision === 'approved' ? 'approve' : 'reject'), {
          method: 'POST',
          body: { decision: decision, analyst: document.getElementById('dec-user').value, reason: document.getElementById('dec-reason').value, role: S.getUser().role }
        });
        S.toast('Decision recorded', 'ok'); S.closeModal(); response();
      } catch (e) { S.toast(e.message, 'err'); }
    };
  }

  /* ===================== 7. AGENTS ===================== */
  async function agents() {
    loading();
    try {
      const data = await S.api('/agents');
      setHtml(
        pageHead('AI Agent Monitoring', 'Real execution statistics from the agent execution log · mode: ' + data.llm_mode) +
        '<div class="grid cols-3">' + data.agents.map(function (a) {
          return '<div class="agent-card"><div class="agent-card-head"><div class="agent-avatar">' + S.esc(a.name.charAt(0)) + '</div>' +
            '<div><div class="agent-name">' + S.esc(a.name) + '</div><div class="agent-role">' + S.esc(a.role) + '</div></div>' +
            '<span class="badge ' + (a.status === 'Completed' ? 'b-low' : a.status === 'Failed' ? 'b-critical' : a.status.includes('Approval') ? 'b-high' : 'b-muted') + '" style="margin-left:auto">' + S.esc(a.status) + '</span></div>' +
            '<div class="agent-stats"><div class="agent-stat"><b>' + a.total_executions + '</b><span>Runs</span></div>' +
            '<div class="agent-stat"><b>' + a.successes + '</b><span>Success</span></div>' +
            '<div class="agent-stat"><b>' + a.failures + '</b><span>Failed</span></div>' +
            '<div class="agent-stat"><b>' + (a.avg_duration_ms || 0) + '</b><span>Avg ms</span></div></div>' +
            '<div class="tiny muted" style="margin-top:10px">Last execution: ' + S.esc(S.fmtDate(a.last_execution)) + '</div>' +
            (a.recent_history && a.recent_history.length ? '<div class="tiny muted" style="margin-top:6px">Recent: ' + a.recent_history.slice(0, 4).map(function (h) { return S.esc(h.status); }).join(' · ') + '</div>' : '') +
            '</div>';
        }).join('') + '</div>'
      );
    } catch (e) { fail(e); }
  }

  /* ===================== 8. THREAT INTELLIGENCE ===================== */
  async function intel() {
    loading();
    try {
      const [status, results] = await Promise.all([S.api('/threat-intel/status'), S.api('/threat-intel/results')]);
      setHtml(
        pageHead('Threat Intelligence', 'Optional API integrations with caching · unknown ≠ clean',
          '<span class="badge ' + (status.enabled ? 'b-low' : 'b-muted') + '">' + (status.enabled ? 'PROVIDERS CONFIGURED' : 'LOCAL / FALLBACK MODE') + '</span>') +
        '<div class="grid cols-2">' +
          '<div class="card"><div class="card-head"><div class="card-title">Indicator Lookup</div></div>' +
            '<div class="filters"><input class="input" id="ti-value" placeholder="IP, domain, MD5, SHA-1 or SHA-256">' +
            '<select class="input" id="ti-type"><option value="">Auto-detect</option><option value="ip">IP</option><option value="domain">Domain</option><option value="md5">MD5</option><option value="sha1">SHA-1</option><option value="sha256">SHA-256</option></select>' +
            '<button class="btn btn-primary btn-sm" id="ti-submit">Lookup</button></div>' +
            '<div id="ti-result" class="muted small">No lookup performed.</div>' +
            '<div class="divider"></div><div class="tiny muted">VirusTotal: <b>' + status.virustotal_configured + '</b> · AbuseIPDB: <b>' + status.abuseipdb_configured + '</b> · Cache TTL: ' + status.cache_ttl_seconds + 's</div>' +
            '<div class="tiny muted">No files are uploaded to third parties. API keys are read from environment variables.</div>' +
          '</div>' +
          '<div class="card"><div class="card-head"><div class="card-title">Cached Results</div></div>' +
            (results.items.length ? '<div class="table-wrap"><table class="tbl"><thead><tr><th>Indicator</th><th>Type</th><th>Verdict</th><th>Score</th><th>Provider</th></tr></thead><tbody>' +
              results.items.map(function (r) { return '<tr><td class="mono">' + S.esc(r.indicator) + '</td><td>' + S.esc(r.indicator_type) + '</td><td>' + S.statusBadge(r.verdict) + '</td><td>' + S.esc(r.score) + '</td><td class="small">' + S.esc(r.provider) + '</td></tr>'; }).join('') + '</tbody></table></div>' : '<div class="empty">No cached results.</div>') +
          '</div></div>'
      );
      document.getElementById('ti-submit').onclick = async function () {
        const v = document.getElementById('ti-value').value.trim();
        if (!v) { S.toast('Enter an indicator', 'err'); return; }
        const t = document.getElementById('ti-type').value;
        try {
          const r = await S.api('/threat-intel/lookup', { method: 'POST', body: { indicator: v, indicator_type: t || null } });
          document.getElementById('ti-result').innerHTML = '<div class="detail-grid" style="margin-top:12px">' +
            detail('Indicator', r.indicator) + detail('Type', r.indicator_type) + detail('Verdict', r.verdict) +
            detail('Score', r.score) + detail('Provider', r.provider) + detail('Cached', r.cached) + '</div>' +
            '<div class="tiny muted" style="margin-top:10px">' + S.esc(JSON.stringify(r.details)) + '</div>';
        } catch (e) { S.toast(e.message, 'err'); }
      };
    } catch (e) { fail(e); }
  }

  /* ===================== 9. REPORTS ===================== */
  async function reports() {
    loading();
    try {
      const [incidents, reportsData] = await Promise.all([S.api('/incidents?limit=200'), S.api('/reports')]);
      setHtml(
        pageHead('Security Reports', 'Professional PDF incident reports with evidence hashes and approval history') +
        '<div class="grid cols-2">' +
          '<div class="card"><div class="card-head"><div class="card-title">Generate Report</div></div>' +
            '<div class="filters"><select class="input" id="rep-incident" style="min-width:380px">' +
            (incidents.items.length ? incidents.items.map(function (i) { return '<option value="' + S.esc(i.incident_id) + '">' + S.esc(i.incident_id) + ' · ' + S.esc(i.title) + '</option>'; }).join('') : '<option value="">No incidents</option>') +
            '</select><button class="btn btn-primary btn-sm" id="rep-gen">Generate PDF</button></div>' +
            '<div id="rep-status" class="small muted"></div>' +
            '<div class="divider"></div><div class="tiny muted">Reports include: branding, incident summary, risk score, timeline, evidence hashes, agent findings, remediation and approval history.</div>' +
          '</div>' +
          '<div class="card"><div class="card-head"><div class="card-title">Generated Reports</div></div>' +
            (reportsData.items.length ? reportsData.items.map(function (r) {
              return '<div class="flex" style="justify-content:space-between;border:1px solid var(--line);border-radius:9px;padding:10px;margin-bottom:8px">' +
                '<div><div class="small" style="font-weight:700">' + S.esc(r.file_name) + '</div>' +
                '<div class="tiny muted">' + S.esc(r.incident_id) + ' · ' + S.esc(r.generated_by) + ' · ' + S.esc(S.fmtDate(r.created_at)) + '</div>' +
                '<div class="tiny mono">' + S.esc(r.sha256.slice(0, 28)) + '…</div></div>' +
                '<button class="btn btn-sm btn-primary" data-dl="' + S.esc(r.download_url) + '" data-name="' + S.esc(r.file_name) + '">Download</button></div>';
            }).join('') : '<div class="empty">No reports generated yet.</div>') + '</div>' +
        '</div>'
      );
      document.getElementById('rep-gen').onclick = async function () {
        const id = document.getElementById('rep-incident').value;
        if (!id) { S.toast('No incident selected', 'err'); return; }
        document.getElementById('rep-status').innerHTML = '<span class="spinner"></span> Generating…';
        try {
          const r = await S.api('/reports/generate/' + id, { method: 'POST' });
          document.getElementById('rep-status').textContent = 'Generated: ' + r.file_name + ' (' + r.size_bytes + ' bytes)';
          S.toast('Report generated', 'ok'); reports();
        } catch (e) { document.getElementById('rep-status').textContent = e.message; S.toast(e.message, 'err'); }
      };
      document.querySelectorAll('[data-dl]').forEach(function (b) {
        b.onclick = function () { S.download(b.dataset.dl, b.dataset.name); };
      });
    } catch (e) { fail(e); }
  }

  /* ===================== 10. SETTINGS ===================== */
  async function settings() {
    loading();
    try {
      const [cfg, scenarios, audit] = await Promise.all([
        S.api('/settings'), S.api('/simulation/scenarios'), S.api('/audit?limit=25')
      ]);
      let usersHtml = '';
      if (S.getUser().role === 'admin') {
        try {
          const users = await S.api('/users');
          usersHtml = '<div class="card"><div class="card-head"><div class="card-title">User Accounts</div><div class="right card-sub">' + users.items.length + ' users</div></div>' +
            '<div class="table-wrap"><table class="tbl"><thead><tr><th>Username</th><th>Email</th><th>Role</th><th>Active</th><th>Last login</th></tr></thead><tbody>' +
            users.items.map(function (u) { return '<tr><td>' + S.esc(u.username) + '</td><td>' + S.esc(u.email) + '</td><td>' + S.statusBadge(u.role) + '</td><td>' + (u.is_active ? 'Yes' : 'No') + '</td><td class="tiny">' + S.esc(S.fmtDate(u.last_login_at)) + '</td></tr>'; }).join('') +
            '</tbody></table></div></div>';
        } catch (e) { usersHtml = '<div class="card muted small">User list unavailable: ' + S.esc(e.message) + '</div>'; }
      }
      setHtml(
        pageHead('System Settings', 'Configuration, integrations, safe simulation and audit trail') +
        '<div class="grid cols-2">' +
          '<div class="card"><div class="card-head"><div class="card-title">Runtime Configuration</div></div>' +
            '<div class="detail-grid">' +
              detail('Application', cfg.app_name) + detail('Environment', cfg.app_env) + detail('Database', cfg.database) +
              detail('LLM mode', cfg.llm_mode) + detail('LLM model', cfg.llm_model || 'none (fallback)') + detail('Simulation mode', cfg.simulation_mode) +
              detail('Wazuh', cfg.wazuh_enabled) + detail('Elasticsearch', cfg.elasticsearch_enabled) + detail('Threat intel', cfg.threat_intel_enabled) +
              detail('Response execution', cfg.response_execution_enabled) + detail('Brute-force threshold', cfg.brute_force_threshold) + detail('Detection window (s)', cfg.brute_force_window_seconds) +
            '</div><div class="divider"></div><div class="tiny muted">Secrets are never returned by the API. Configure them in <span class="code-chip">.env</span>.</div></div>' +
          '<div class="card"><div class="card-head"><div class="card-title">Safe Lab Simulation</div></div>' +
            '<div class="tiny muted" style="margin-bottom:12px">Generates synthetic events only. No external systems contacted.</div>' +
            Object.keys(scenarios.scenarios).map(function (k) {
              return '<div class="flex" style="justify-content:space-between;border:1px solid var(--line);border-radius:8px;padding:9px;margin-bottom:7px">' +
                '<div><b class="small">' + S.esc(k) + '</b><div class="tiny muted">' + S.esc(scenarios.scenarios[k]) + '</div></div>' +
                '<button class="btn btn-sm" data-sim="' + S.esc(k) + '">Run</button></div>';
            }).join('') + '</div>' +
        '</div>' +
        '<div class="grid cols-2" style="margin-top:16px">' + usersHtml +
          '<div class="card"><div class="card-head"><div class="card-title">Audit Log</div><div class="right card-sub">Latest 25 actions</div></div>' +
            (audit.items.length ? audit.items.map(function (a) {
              return '<div class="tiny" style="padding:5px 0;border-bottom:1px solid var(--line-soft)">' + S.esc(S.fmtDate(a.created_at)) + ' · <b>' + S.esc(a.actor) + '</b> (' + S.esc(a.actor_role) + ') · ' + S.esc(a.action) + ' · ' + S.esc(a.target_id || '') + '</div>';
            }).join('') : '<div class="empty">No audit entries.</div>') + '</div>' +
        '</div>'
      );
      document.querySelectorAll('[data-sim]').forEach(function (b) {
        b.onclick = async function () {
          try {
            const r = await S.api('/simulation/run', { method: 'POST', body: { scenario: b.dataset.sim, count: 12 } });
            S.toast('Simulation complete: ' + r.events.inserted + ' event(s), ' + r.correlation.incidents_created + ' incident(s)', 'ok');
          } catch (e) { S.toast(e.message, 'err'); }
        };
      });
    } catch (e) { fail(e); }
  }

  /* ===================== ROUTER / AUTH ===================== */
  const pages = { overview: overview, monitoring: monitoring, detection: detection, investigation: investigation,
    incidents: incidents, response: response, agents: agents, intel: intel, reports: reports, settings: settings };

  function route() {
    const hash = (location.hash || '#/overview').replace(/^#\//, '');
    const name = pages[hash] ? hash : 'overview';
    currentPage = name;
    clearTimers(); destroyCharts();
    document.querySelectorAll('.nav-item').forEach(function (a) { a.classList.toggle('active', a.dataset.page === name); });
    document.getElementById('page-title').textContent = PAGE_TITLES[name][0];
    document.getElementById('page-crumb').textContent = PAGE_TITLES[name][1];
    pages[name]();
  }

  function showApp() {
    document.getElementById('login-screen').hidden = true;
    document.getElementById('app-shell').hidden = false;
    const user = S.getUser() || { username: 'analyst', role: 'analyst' };
    document.getElementById('user-name').textContent = user.username;
    document.getElementById('user-role').textContent = String(user.role).toUpperCase();
    document.getElementById('user-avatar').textContent = String(user.username).charAt(0).toUpperCase();
    S.api('/settings').then(function (cfg) {
      document.getElementById('mode-label').textContent = cfg.llm_mode === 'api' ? 'LLM API mode' : 'Deterministic fallback mode';
      document.getElementById('db-label').textContent = cfg.database.toUpperCase() + ' · Simulated data';
    }).catch(function () {});
    route();
  }

  S.showLogin = function (message) {
    clearTimers(); destroyCharts(); S.clearSession();
    document.getElementById('app-shell').hidden = true;
    document.getElementById('login-screen').hidden = false;
    if (message) { const e = document.getElementById('login-error'); e.hidden = false; e.textContent = message; }
  };

  document.getElementById('login-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    const err = document.getElementById('login-error'); err.hidden = true;
    const btn = this.querySelector('button[type=submit]'); btn.disabled = true;
    try {
      const data = await S.api('/auth/login', { method: 'POST', body: {
        username: document.getElementById('login-user').value.trim(),
        password: document.getElementById('login-pass').value
      } });
      S.setToken(data.access_token);
      S.setUser({ username: data.username, role: data.role });
      showApp();
    } catch (ex) { err.hidden = false; err.textContent = ex.message; }
    finally { btn.disabled = false; }
  });

  document.getElementById('logout-btn').onclick = async function () {
    try { await S.api('/auth/logout', { method: 'POST' }); } catch (e) {}
    S.showLogin();
  };

  document.getElementById('menu-toggle').onclick = function () { document.getElementById('sidebar').classList.toggle('open'); };
  document.querySelectorAll('.nav-item').forEach(function (a) {
    a.addEventListener('click', function () { document.getElementById('sidebar').classList.remove('open'); });
  });
  window.addEventListener('hashchange', function () { if (!document.getElementById('app-shell').hidden) route(); });

  setInterval(function () {
    document.getElementById('clock').textContent = new Date().toISOString().slice(11, 19) + ' UTC';
  }, 1000);

  if (S.getToken()) showApp(); else S.showLogin();
})();
