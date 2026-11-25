/* SENTINELX API client and shared UI helpers */
(function () {
  'use strict';

  const TOKEN_KEY = 'sentinelx.access_token';
  const USER_KEY = 'sentinelx.user';

  function getToken() { return localStorage.getItem(TOKEN_KEY); }
  function setToken(token) { localStorage.setItem(TOKEN_KEY, token); }
  function getUser() { try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null'); } catch (e) { return null; } }
  function setUser(user) { localStorage.setItem(USER_KEY, JSON.stringify(user)); }
  function clearSession() { localStorage.removeItem(TOKEN_KEY); localStorage.removeItem(USER_KEY); }

  async function api(path, options) {
    options = options || {};
    const headers = Object.assign({}, options.headers || {});
    const token = getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    let body = options.body;
    if (body && typeof body !== 'string' && !(body instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }
    let response;
    try {
      response = await fetch('/api' + path, Object.assign({}, options, { headers: headers, body: body }));
    } catch (err) {
      throw new Error('Network error: ' + err.message);
    }
    if (response.status === 401) {
      clearSession();
      if (window.SentinelX && window.SentinelX.showLogin) window.SentinelX.showLogin('Session expired. Please sign in again.');
    }
    const contentType = response.headers.get('content-type') || '';
    if (!response.ok) {
      let detail = 'Request failed (' + response.status + ')';
      if (contentType.includes('json')) {
        try { const data = await response.json(); detail = data.detail || detail; } catch (e) { /* ignore */ }
      }
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    }
    if (contentType.includes('json')) return response.json();
    return response;
  }

  function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fmtDate(value, withTime) {
    if (!value) return '—';
    const d = new Date(value);
    if (isNaN(d.getTime())) return esc(value);
    const date = d.toISOString().slice(0, 10);
    return withTime === false ? date : date + ' ' + d.toISOString().slice(11, 19) + 'Z';
  }

  function sevBadge(severity) {
    const s = String(severity || 'LOW').toUpperCase();
    const cls = s === 'CRITICAL' ? 'b-critical' : s === 'HIGH' ? 'b-high' : s === 'MEDIUM' ? 'b-medium' : 'b-low';
    return '<span class="badge ' + cls + '">' + esc(s) + '</span>';
  }

  function statusBadge(status) {
    const s = String(status || '').toLowerCase();
    let cls = 'b-muted';
    if (s.includes('critical') || s === 'rejected') cls = 'b-critical';
    else if (s.includes('high') || s.includes('waiting')) cls = 'b-high';
    else if (s.includes('medium') || s === 'new' || s === 'pending' || s === 'running') cls = 'b-info';
    else if (s.includes('approv') || s === 'contained' || s === 'completed' || s === 'resolved') cls = 'b-low';
    else if (s.includes('investigat')) cls = 'b-purple';
    return '<span class="badge ' + cls + '">' + esc(status) + '</span>';
  }

  function toast(message, type) {
    const box = document.getElementById('toast-container');
    if (!box) return;
    const el = document.createElement('div');
    el.className = 'toast ' + (type || '');
    el.innerHTML = esc(message);
    box.appendChild(el);
    setTimeout(function () { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(function () { el.remove(); }, 300); }, 4200);
  }

  function modal(title, bodyHtml, footHtml) {
    const root = document.getElementById('modal-root');
    root.innerHTML =
      '<div class="modal-backdrop">' +
        '<div class="modal" role="dialog" aria-modal="true">' +
          '<div class="modal-head"><h3>' + esc(title) + '</h3><button class="x" data-close>&times;</button></div>' +
          '<div class="modal-body">' + bodyHtml + '</div>' +
          (footHtml ? '<div class="modal-foot">' + footHtml + '</div>' : '') +
        '</div></div>';
    root.querySelectorAll('[data-close]').forEach(function (b) { b.onclick = closeModal; });
    root.querySelector('.modal-backdrop').onclick = function (e) { if (e.target === this) closeModal(); };
  }

  function closeModal() { const root = document.getElementById('modal-root'); if (root) root.innerHTML = ''; }

  function download(url, filename) {
    const token = getToken();
    fetch(url, { headers: token ? { Authorization: 'Bearer ' + token } : {} })
      .then(function (r) { if (!r.ok) throw new Error('Download failed'); return r.blob(); })
      .then(function (blob) {
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = filename || 'report.pdf';
        document.body.appendChild(a); a.click(); a.remove();
        URL.revokeObjectURL(a.href);
      })
      .catch(function (e) { toast(e.message, 'err'); });
  }

  window.SentinelX = {
    api: api, esc: esc, fmtDate: fmtDate, sevBadge: sevBadge, statusBadge: statusBadge,
    toast: toast, modal: modal, closeModal: closeModal, download: download,
    getToken: getToken, setToken: setToken, getUser: getUser, setUser: setUser, clearSession: clearSession
  };
})();
