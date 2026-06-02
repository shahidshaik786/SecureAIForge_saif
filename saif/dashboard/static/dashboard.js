async function postAction(url) {
  if (/\/stop\b/.test(url) && !confirm('Stop this scan?')) return;
  const response = await fetch(url, { method: 'POST' });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    alert(data.detail || data.error || data.message || 'Action failed');
    return;
  }
  location.reload();
}

function inferScanAction(url) {
  if (!url) return null;
  if (url.includes('/pause')) return 'pause';
  if (url.includes('/resume')) return 'resume';
  if (url.includes('/stop-force')) return 'force_stop';
  if (url.includes('/stop')) return 'stop';
  if (url.includes('/continue') || url.includes('/run-phase')) return 'continue_phase';
  if (url.includes('/report')) return 'generate_report';
  if (url.includes('/auth/validate')) return 'validate_auth';
  if (url.includes('/auth/relogin')) return 'relogin';
  if (url.includes('/auth/create-accounts')) return 'create_accounts';
  return null;
}

async function applyActionStates() {
  const byScan = new Map();
  document.querySelectorAll('button[data-action]').forEach(button => {
    const match = button.dataset.action.match(/\/api\/scans\/(\d+)\//);
    if (!match) return;
    const scanId = match[1];
    if (!byScan.has(scanId)) byScan.set(scanId, []);
    byScan.get(scanId).push(button);
  });
  for (const [scanId, buttons] of byScan.entries()) {
    try {
      const response = await fetch(`/api/scans/${scanId}/actions`);
      if (!response.ok) continue;
      const payload = await response.json();
      const states = payload.actions || {};
      buttons.forEach(button => {
        const action = inferScanAction(button.dataset.action);
        const state = states[action];
        if (!state) return;
        button.disabled = !state.enabled;
        button.title = state.enabled ? '' : (state.reason || 'Action is not available.');
        button.classList.toggle('btn-disabled', !state.enabled);
        if (state.css_class) button.classList.add(state.css_class);
      });
    } catch {
      continue;
    }
  }
}

function renderTable(container, rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    container.innerHTML = '<div class="empty-state">No records.</div>';
    return;
  }
  const keys = preferredKeys(rows[0]);
  container.innerHTML = `<table class="data-table"><thead><tr>${keys.map(k => `<th>${escapeHtml(label(k))}</th>`).join('')}</tr></thead><tbody>${rows.slice(0, 100).map((row, index) => `<tr class="${index === 0 ? 'latest-row' : ''}">${keys.map(k => `<td>${formatValue(row[k])}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
}

function preferredKeys(row) {
  const priority = ['id', 'scan_id', 'timestamp', 'level', 'status', 'severity', 'title', 'event_type', 'phase', 'agent_name', 'tool_name', 'message', 'target', 'endpoint', 'method', 'duration_ms', 'evidence_path', 'path', 'error_message'];
  const keys = Object.keys(row || {});
  return [...priority.filter(k => keys.includes(k)), ...keys.filter(k => !priority.includes(k))].slice(0, 12);
}

function label(key) {
  return String(key).replaceAll('_', ' ');
}

function formatValue(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') return `<code>${escapeHtml(JSON.stringify(value).slice(0, 300))}</code>`;
  const text = String(value);
  if (/^(critical|high|medium|low|info|running|completed|failed|not_ready|manual_review_required|missing_prerequisite|finding_created|closed|fixed)$/i.test(text)) {
    return `<span class="badge badge-${escapeHtml(text.toLowerCase().replaceAll('_', '-'))}">${escapeHtml(text)}</span>`;
  }
  return escapeHtml(text.slice(0, 500));
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, ch => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'}[ch]));
}

document.querySelectorAll('[data-toggle-sidebar]').forEach(button => {
  button.addEventListener('click', () => document.getElementById('sidebar')?.classList.toggle('open'));
});

document.querySelectorAll('button[data-action]').forEach(button => {
  button.addEventListener('click', () => postAction(button.dataset.action));
});
applyActionStates();

document.querySelectorAll('[data-json]').forEach(async container => {
  const response = await fetch(container.dataset.json);
  const data = await response.json();
  renderTable(container, Array.isArray(data) ? data : [data]);
});

document.querySelectorAll('[data-rows]').forEach(container => {
  try {
    renderTable(container, JSON.parse(container.dataset.rows || '[]'));
  } catch {
    container.innerHTML = '<div class="empty-state">Unable to render records.</div>';
  }
});

document.querySelectorAll('[data-table-filter]').forEach(input => {
  input.addEventListener('input', () => {
    const table = input.closest('.panel')?.querySelector('table');
    if (!table) return;
    const needle = input.value.toLowerCase();
    table.querySelectorAll('tbody tr').forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(needle) ? '' : 'none';
    });
  });
});

document.querySelectorAll('[data-start-scan]').forEach(form => {
  const submit = form.querySelector('button[type="submit"]');
  const message = form.querySelector('[data-form-message]');
  const updateStartState = () => {
    updateEffectiveConfig(form);
    const data = new FormData(form);
    let reason = '';
    if (!data.get('target')) reason = 'Target URL is required.';
    else if (!data.get('confirm')) reason = 'Authorization confirmation is required before starting a scan.';
    else if (data.get('enable_destructive_tests') && !data.get('confirm_destructive_testing')) reason = 'Confirm destructive testing acknowledgement before enabling destructive test cases.';
    if (submit) {
      submit.disabled = Boolean(reason);
      submit.title = reason;
      submit.classList.toggle('btn-disabled', Boolean(reason));
    }
    if (message && reason) message.textContent = reason;
  };
  form.addEventListener('input', updateStartState);
  form.addEventListener('change', updateStartState);
  updateStartState();
  form.addEventListener('submit', async event => {
    event.preventDefault();
    const message = form.querySelector('[data-form-message]');
    const data = new FormData(form);
    if (!data.get('confirm')) {
      message.textContent = 'Confirm scope and approval before starting.';
      return;
    }
    const payload = {
      target: data.get('target'),
      profile: data.get('profile') || 'auto',
      engagement_mode: data.get('mode') || 'black-box',
      full: Boolean(data.get('full')),
      enumeration_only: Boolean(data.get('enumeration_only')),
      debug: Boolean(data.get('debug')),
      confirm_authorized: Boolean(data.get('confirm')),
      auth_mode: data.get('auth_mode') || 'auto',
      credentials_path: data.get('credentials_path') || null,
      source_path: data.get('source_path') || null,
      allow_account_generation: Boolean(data.get('allow_account_generation')),
      allow_authenticated_testing: Boolean(data.get('allow_authenticated_testing')),
      allow_authorization_testing: Boolean(data.get('allow_authorization_testing')),
      allow_payload_testing: Boolean(data.get('allow_payload_testing')),
      allow_rate_limit_testing: Boolean(data.get('allow_rate_limit_testing')),
      execution_profile: data.get('execution_profile') || data.get('destructive_test_policy') || 'detect_only',
      destructive_method_policy: data.get('destructive_method_policy') || 'no_destructive_methods',
      destructive_test_policy: data.get('destructive_test_policy') || 'detect_only',
      enable_destructive_tests: Boolean(data.get('enable_destructive_tests')),
      allow_test_owned_object_creation: Boolean(data.get('allow_test_owned_object_creation')),
      confirm_destructive_testing: Boolean(data.get('confirm_destructive_testing')),
      selected_test_categories: data.getAll('selected_test_categories'),
    };
    if (payload.enable_destructive_tests && !payload.confirm_destructive_testing) {
      message.textContent = 'Confirm destructive testing acknowledgement before enabling destructive test cases.';
      return;
    }
    message.textContent = 'Starting scan...';
    const response = await fetch('/api/scans/start', {
      method: 'POST',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (response.ok && result.live_url) {
      message.textContent = `Started scan #${result.scan_id}. Opening live monitor...`;
      window.location.href = result.live_url;
      return;
    }
    message.textContent = response.ok ? `Started: ${result.command || 'scan command queued'}` : (result.message || result.detail || 'Unable to start scan');
  });
});

document.querySelectorAll('[data-preset]').forEach(button => {
  button.addEventListener('click', () => {
    const form = document.querySelector('[data-start-scan]');
    if (!form) return;
    const preset = button.dataset.preset;
    const isFullAuthorized = preset === 'full-authorized';
    if (preset === 'crapi-app') form.elements.profile.value = 'crapi';
    if (preset === 'default' || preset === 'enumeration-only' || preset === 'gray-box' || isFullAuthorized) form.elements.profile.value = 'auto';
    form.elements.mode.value = preset === 'gray-box' || isFullAuthorized ? 'gray-box' : 'black-box';
    form.elements.auth_mode.value = 'auto';
    form.elements.execution_profile.value = isFullAuthorized ? 'destructive-full-scan' : (preset === 'gray-box' ? 'test-owned-validation' : 'discovery_only');
    form.elements.full.checked = preset === 'full-authorized' || preset === 'gray-box';
    form.elements.enumeration_only.checked = preset === 'enumeration-only';
    form.elements.destructive_method_policy.value = isFullAuthorized ? 'lab_full_allowed' : (preset === 'default' || preset === 'enumeration-only' ? 'detect_only' : 'test_owned_only');
    form.elements.destructive_test_policy.value = isFullAuthorized ? 'lab_full_allowed' : (preset === 'gray-box' ? 'test_owned_only' : 'detect_only');
    form.elements.enable_destructive_tests.checked = isFullAuthorized;
    form.elements.allow_test_owned_object_creation.checked = isFullAuthorized;
    form.elements.confirm_destructive_testing.checked = false;
    form.elements.allow_account_generation.checked = isFullAuthorized;
    form.elements.allow_authenticated_testing.checked = isFullAuthorized || preset === 'gray-box';
    form.elements.allow_authorization_testing.checked = form.elements.allow_authenticated_testing.checked;
    form.elements.allow_payload_testing.checked = isFullAuthorized || preset === 'gray-box';
    form.elements.allow_rate_limit_testing.checked = isFullAuthorized;
    selectCategories(
      isFullAuthorized ? allCategories(form) : (preset === 'enumeration-only' ? ['recon','api_discovery','method_discovery','security_headers','error_handling'] : recommendedCategories()),
      form,
    );
    form.dispatchEvent(new Event('change', { bubbles: true }));
  });
});

document.querySelectorAll('[data-select-categories]').forEach(button => {
  button.addEventListener('click', () => {
    const form = button.closest('form') || document;
    const mode = button.dataset.selectCategories;
    if (mode === 'clear') selectCategories([], form);
    if (mode === 'all') selectCategories(allCategories(form), form);
    if (mode === 'recommended') selectCategories(recommendedCategories(), form);
    if (form.dispatchEvent) form.dispatchEvent(new Event('change', { bubbles: true }));
  });
});

function recommendedCategories() {
  return ['recon','api_discovery','method_discovery','security_headers','error_handling','auth_testing','session_management','jwt_testing','authorization_matrix','bola_idor','bfla','mass_assignment','xss','sqli','ssrf','business_logic'];
}

function allCategories(root = document) {
  return [...root.querySelectorAll('input[name="selected_test_categories"]')].map(item => item.value);
}

function selectCategories(values, root = document) {
  const selected = new Set(values);
  root.querySelectorAll('input[name="selected_test_categories"]').forEach(input => {
    input.checked = selected.has(input.value);
  });
}

function updateEffectiveConfig(form) {
  const root = form.querySelector('[data-effective-config]');
  if (!root) return;
  const selectedCount = form.querySelectorAll('input[name="selected_test_categories"]:checked').length;
  const totalCount = form.querySelectorAll('input[name="selected_test_categories"]').length;
  const set = (key, value) => {
    const node = root.querySelector(`[data-effective="${key}"]`);
    if (node) node.textContent = value;
  };
  set('execution_profile', selectLabel(form.elements.destructive_test_policy));
  set('application_profile', selectLabel(form.elements.profile));
  set('engagement_mode', form.elements.mode?.value || 'black-box');
  set('destructive_policy', selectLabel(form.elements.destructive_method_policy));
  set('full_workflow', boolText(form.elements.full?.checked));
  set('select_all_applicable', boolText(totalCount > 0 && selectedCount === totalCount));
  set('selected_test_categories_count', String(selectedCount));
  set('allow_authenticated_testing', boolText(form.elements.allow_authenticated_testing?.checked));
  set('allow_authorization_testing', boolText(form.elements.allow_authorization_testing?.checked));
  set('allow_payload_testing', boolText(form.elements.allow_payload_testing?.checked));
  set('allow_rate_limit_testing', boolText(form.elements.allow_rate_limit_testing?.checked));
  set('enable_destructive_tests', boolText(form.elements.enable_destructive_tests?.checked));
}

function boolText(value) {
  return value ? 'true' : 'false';
}

function selectLabel(select) {
  return select?.selectedOptions?.[0]?.textContent?.trim() || select?.value || '';
}

const livePanel = document.querySelector('.live-panel');
if (livePanel && location.pathname.includes('/live')) {
  const scanId = location.pathname.startsWith('/scans/') ? location.pathname.split('/')[2] : document.querySelector('[data-json^="/api/scans/"]')?.dataset.json.split('/')[3];
  if (scanId) {
    setInterval(async () => {
      for (const container of document.querySelectorAll('.live-panel [data-json]')) {
        const response = await fetch(container.dataset.json);
        const data = await response.json();
        renderTable(container, Array.isArray(data) ? data : [data]);
      }
    }, 2000);
  }
}
