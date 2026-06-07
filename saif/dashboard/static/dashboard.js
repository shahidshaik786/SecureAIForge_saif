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
  if (url.includes('/resolve-prerequisites')) return 'resolve_prerequisites';
  if (url.includes('/restart-worker')) return 'restart_worker';
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

function badgeHtml(value) {
  const text = value || '-';
  return `<span class="badge badge-${escapeHtml(String(text).toLowerCase().replaceAll('_', '-'))}">${escapeHtml(text)}</span>`;
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
    syncExecutionProfileFlags(form);
    syncExecutionProfile(form);
    syncExecutionDescription(form);
    updateEffectiveConfig(form);
    const data = new FormData(form);
    let reason = '';
    const isDestructiveFull = data.get('destructive_test_policy') === 'lab_full_allowed';
    const accountSource = data.get('account_source') || 'auto';
    const authProfile = ['authenticated_full', 'lab_full_allowed'].includes(String(data.get('destructive_test_policy') || '')) || data.get('execution_profile') === 'auth-authorization-debug';
    if (!data.get('target')) reason = 'Target URL is required.';
    else if (!data.get('confirm')) reason = 'Authorization confirmation is required before starting a scan.';
    else if (accountSource === 'credentials_file' && !data.get('credentials_path')) reason = 'Credentials file selected, but no credentials path was provided.';
    else if (authProfile && !['auto', 'credentials_file', 'generated_test_accounts', 'existing_session'].includes(String(accountSource))) reason = 'Select an account source for authenticated testing.';
    else if (isDestructiveFull && !['lab_full_allowed', 'test_owned_only', 'manual_confirmation'].includes(String(data.get('destructive_method_policy') || ''))) reason = 'Select an allowed destructive policy for Destructive Test Cases - Full Authorized Scan.';
    else if (isDestructiveFull && !data.get('confirm_destructive_testing')) reason = 'Confirm destructive testing acknowledgement before enabling destructive test cases.';
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
      account_source: data.get('account_source') || 'auto',
      auth_mode: data.get('account_source') || data.get('auth_mode') || 'auto',
      credentials_path: data.get('credentials_path') || null,
      required_user_count: 2,
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
      known_protected_endpoints: String(data.get('known_protected_endpoints') || '').split(/\r?\n|,/).map((line) => {
        const trimmed = line.trim();
        const match = trimmed.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$/i);
        return match ? {method: match[1].toUpperCase(), path: match[2].trim()} : trimmed ? {method: 'GET', path: trimmed} : null;
      }).filter(Boolean),
      har_file: data.get('har_file') || null,
      known_authenticated_requests: String(data.get('known_authenticated_request') || '').trim() ? [String(data.get('known_authenticated_request') || '')] : [],
      login_workflow_hints: Object.fromEntries(String(data.get('login_workflow_hints') || '').split(/\r?\n/).map((line) => line.split('=')).filter((pair) => pair.length === 2).map(([key, value]) => [key.trim(), value.trim()])),
    };
    if (payload.destructive_test_policy === 'lab_full_allowed' && !payload.confirm_destructive_testing) {
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
    const isAuthDebug = preset === 'auth-debug';
    if (preset === 'crapi-app') form.elements.profile.value = 'crapi';
    if (preset === 'default' || preset === 'enumeration-only' || preset === 'gray-box' || isFullAuthorized || isAuthDebug) form.elements.profile.value = isAuthDebug ? 'crapi' : 'auto';
    form.elements.mode.value = preset === 'gray-box' || isFullAuthorized || isAuthDebug ? 'gray-box' : 'black-box';
    form.elements.account_source.value = isAuthDebug || isFullAuthorized || preset === 'gray-box' ? 'generated_test_accounts' : 'auto';
    form.elements.auth_mode.value = form.elements.account_source.value;
    form.elements.execution_profile.value = isAuthDebug ? 'auth-authorization-debug' : isFullAuthorized ? 'destructive-full-scan' : (preset === 'gray-box' ? 'authenticated-full-scan' : 'discovery_only');
    form.elements.full.checked = preset === 'full-authorized' || preset === 'gray-box' || isAuthDebug;
    form.elements.enumeration_only.checked = preset === 'enumeration-only';
    form.elements.destructive_method_policy.value = isFullAuthorized ? 'lab_full_allowed' : (preset === 'default' || preset === 'enumeration-only' ? 'detect_only' : 'test_owned_only');
    form.elements.destructive_test_policy.value = isFullAuthorized ? 'lab_full_allowed' : (preset === 'gray-box' || isAuthDebug ? 'authenticated_full' : 'detect_only');
    form.elements.enable_destructive_tests.checked = isFullAuthorized;
    form.elements.allow_test_owned_object_creation.checked = isFullAuthorized || isAuthDebug || preset === 'gray-box';
    form.elements.confirm_destructive_testing.checked = false;
    form.elements.allow_account_generation.checked = isFullAuthorized || isAuthDebug || preset === 'gray-box';
    form.elements.allow_authenticated_testing.checked = isFullAuthorized || preset === 'gray-box' || isAuthDebug;
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
  set('target_url', form.elements.target?.value || '-');
  set('execution_profile', selectLabel(form.elements.destructive_test_policy));
  set('application_profile', selectLabel(form.elements.profile));
  set('engagement_mode', form.elements.mode?.value || 'black-box');
  set('auth_mode', form.elements.auth_mode?.value || 'auto');
  set('account_source', form.elements.account_source?.value || 'auto');
  set('credentials_path', form.elements.credentials_path?.value || '-');
  set('required_user_count', '2');
  set('destructive_policy', selectLabel(form.elements.destructive_method_policy));
  set('full_workflow', boolText(form.elements.full?.checked));
  set('select_all_applicable', boolText(totalCount > 0 && selectedCount === totalCount));
  set('selected_test_categories_count', String(selectedCount));
  set('allow_authenticated_testing', boolText(form.elements.allow_authenticated_testing?.checked));
  set('allow_authorization_testing', boolText(form.elements.allow_authorization_testing?.checked));
  set('allow_payload_testing', boolText(form.elements.allow_payload_testing?.checked));
  set('allow_rate_limit_testing', boolText(form.elements.allow_rate_limit_testing?.checked));
  set('enable_destructive_tests', boolText(form.elements.enable_destructive_tests?.checked));
  set('allow_account_generation', boolText(form.elements.allow_account_generation?.checked));
  set('allow_test_owned_object_creation', boolText(form.elements.allow_test_owned_object_creation?.checked));
}

function syncExecutionProfile(form) {
  const hidden = form.elements.execution_profile;
  if (!hidden) return;
  const destructivePolicy = form.elements.destructive_test_policy?.value || '';
  if (destructivePolicy === 'lab_full_allowed' || form.elements.enable_destructive_tests?.checked) {
    hidden.value = 'destructive-full-scan';
  } else if (destructivePolicy === 'authenticated_full') {
    hidden.value = 'authenticated-full-scan';
  } else if (destructivePolicy === 'standard_non_destructive') {
    hidden.value = 'standard-non-destructive-scan';
  } else if (
    form.elements.full?.checked ||
    form.elements.allow_authenticated_testing?.checked ||
    form.elements.allow_authorization_testing?.checked ||
    form.elements.allow_payload_testing?.checked ||
    form.elements.allow_rate_limit_testing?.checked
  ) {
    hidden.value = 'full-authorized-scan';
  } else {
    hidden.value = 'discovery_only';
  }
}

function syncExecutionProfileFlags(form) {
  const profile = form.elements.destructive_test_policy?.value || 'detect_only';
  const warning = form.querySelector('[data-destructive-warning]');
  const accountHelp = form.querySelector('[data-account-source-help]');
  const isSafeEnumeration = profile === 'detect_only';
  const isStandard = profile === 'standard_non_destructive';
  const isAuthenticated = profile === 'authenticated_full';
  const isDestructive = profile === 'lab_full_allowed';
  if (isSafeEnumeration) {
    form.elements.full.checked = false;
    form.elements.enumeration_only.checked = true;
    form.elements.allow_account_generation.checked = false;
    form.elements.allow_authenticated_testing.checked = false;
    form.elements.allow_authorization_testing.checked = false;
    form.elements.allow_payload_testing.checked = false;
    form.elements.allow_rate_limit_testing.checked = false;
    form.elements.enable_destructive_tests.checked = false;
    form.elements.allow_test_owned_object_creation.checked = false;
    if (['lab_full_allowed', 'manual_confirmation'].includes(form.elements.destructive_method_policy.value)) form.elements.destructive_method_policy.value = 'detect_only';
  } else if (isStandard) {
    form.elements.full.checked = true;
    form.elements.enumeration_only.checked = false;
    form.elements.allow_account_generation.checked = false;
    form.elements.allow_authenticated_testing.checked = false;
    form.elements.allow_authorization_testing.checked = false;
    form.elements.allow_payload_testing.checked = true;
    form.elements.allow_rate_limit_testing.checked = false;
    form.elements.enable_destructive_tests.checked = false;
    form.elements.allow_test_owned_object_creation.checked = false;
    if (form.elements.destructive_method_policy.value === 'lab_full_allowed') form.elements.destructive_method_policy.value = 'test_owned_only';
  } else if (isAuthenticated) {
    form.elements.full.checked = true;
    form.elements.enumeration_only.checked = false;
    if (form.elements.profile?.value === 'crapi' || form.elements.account_source?.value === 'generated_test_accounts') {
      form.elements.account_source.value = 'generated_test_accounts';
      form.elements.auth_mode.value = 'generated_test_accounts';
      form.elements.allow_account_generation.checked = true;
    }
    form.elements.allow_authenticated_testing.checked = true;
    form.elements.allow_authorization_testing.checked = true;
    form.elements.allow_payload_testing.checked = true;
    form.elements.allow_rate_limit_testing.checked = true;
    form.elements.enable_destructive_tests.checked = false;
    form.elements.allow_test_owned_object_creation.checked = true;
    if (form.elements.destructive_method_policy.value === 'lab_full_allowed') form.elements.destructive_method_policy.value = 'test_owned_only';
  } else if (isDestructive) {
    form.elements.full.checked = true;
    form.elements.enumeration_only.checked = false;
    form.elements.allow_account_generation.checked = true;
    form.elements.allow_authenticated_testing.checked = true;
    form.elements.allow_authorization_testing.checked = true;
    form.elements.allow_payload_testing.checked = true;
    form.elements.allow_rate_limit_testing.checked = true;
    form.elements.enable_destructive_tests.checked = true;
    form.elements.allow_test_owned_object_creation.checked = true;
    if (!['lab_full_allowed', 'test_owned_only', 'manual_confirmation'].includes(form.elements.destructive_method_policy.value)) {
      form.elements.destructive_method_policy.value = 'lab_full_allowed';
    }
  }
  if (warning) warning.hidden = !isDestructive;
  if (accountHelp) {
    const source = form.elements.account_source?.value || 'auto';
    accountHelp.textContent = source === 'credentials_file'
      ? 'SAIF will not create new users unless fallback account creation is explicitly enabled.'
      : source === 'generated_test_accounts'
        ? 'SAIF will create temporary test accounts through the registration endpoint, then login and validate sessions.'
        : 'Auto mode uses credentials if provided, otherwise SAIF can create temporary test accounts when registration is available.';
  }
}

function syncExecutionDescription(form) {
  const node = form.querySelector('[data-execution-description]');
  const option = form.elements.destructive_test_policy?.selectedOptions?.[0];
  if (node && option) node.textContent = option.dataset.description || '';
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
    let liveAbort = null;
    let liveTimer = null;
    let stopped = false;
    const updateLive = async () => {
      const disconnected = document.getElementById('live-disconnect');
      const stale = document.getElementById('live-stale');
      if (liveAbort) liveAbort.abort();
      liveAbort = new AbortController();
      const timeoutId = setTimeout(() => liveAbort.abort(), 8000);
      try {
        const response = await fetch(`/api/scans/${scanId}/live-state`, { cache: 'no-store', signal: liveAbort.signal, headers: { 'Connection': 'close' } });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const state = await response.json();
        if (disconnected) disconnected.hidden = true;
        if (stale) {
          stale.hidden = !state.stale;
          stale.textContent = state.stale_message || 'No worker heartbeat detected.';
        }
        const statusNode = document.getElementById('live-status-value');
        const phaseNode = document.getElementById('live-phase-value');
        const agentNode = document.getElementById('live-agent-value');
        const toolNode = document.getElementById('live-tool-value');
        const activityNode = document.getElementById('live-last-activity-value');
        if (statusNode) statusNode.innerHTML = badgeHtml(state.status);
        if (phaseNode) phaseNode.textContent = state.current_phase || '-';
        if (agentNode) agentNode.textContent = state.current_agent || '-';
        if (toolNode) toolNode.textContent = state.current_tool || '-';
        if (activityNode) activityNode.textContent = state.last_activity_at || '-';
        document.querySelectorAll('.timeline-step').forEach(step => {
          const phase = step.textContent.trim();
          step.classList.toggle('running', phase === state.current_phase);
          step.classList.toggle('pending', phase !== state.current_phase);
        });
        renderTable(document.getElementById('live-summary'), [{
          scan_id: state.scan_id,
          status: state.status,
          current_phase: state.current_phase,
          current_tool: state.current_tool,
          progress_message: state.progress_message,
          progress_percent: state.progress_percent,
        }]);
        renderTable(document.getElementById('live-process'), state.processes || []);
        renderTable(document.getElementById('live-events'), state.latest_events || []);
        renderTable(document.getElementById('live-tools'), state.latest_tool_runs || []);
        renderTable(document.getElementById('live-ai'), state.latest_ai_calls || []);
        renderTable(document.getElementById('live-payloads'), state.latest_payload_attempts || []);
        renderTable(document.getElementById('live-evidence'), state.latest_evidence || []);
        renderTable(document.getElementById('live-progress'), [{
          completed: state.completed_count,
          failed: state.failed_count,
          missing_prerequisite: state.missing_prerequisite_count,
          planned: state.total_planned_count,
          running_tool: state.running_tool ? state.running_tool.tool_name : '',
        }]);
        applyActionStates();
      } catch (error) {
        if (error.name !== 'AbortError' && disconnected) disconnected.hidden = false;
      } finally {
        clearTimeout(timeoutId);
        liveAbort = null;
        if (!stopped) liveTimer = setTimeout(updateLive, 2000);
      }
    };
    window.addEventListener('beforeunload', () => {
      stopped = true;
      if (liveTimer) clearTimeout(liveTimer);
      if (liveAbort) liveAbort.abort();
    });
    updateLive();
  }
}
