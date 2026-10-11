'use strict';
const $ = (id) => document.getElementById(id);
let state = null;
let busy = false;
let pendingNonce = null;
let confirmTimer = null;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

async function api(path, payload) {
  const response = await fetch(path, payload === undefined ? {cache: 'no-store'} : {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'The request could not be completed.');
  return result;
}

function showError(error) {
  $('error').textContent = error.message || 'Connection lost. Check that the local server is running.';
  $('error').hidden = false;
}

async function mutate(path, payload) {
  if (busy) return;
  busy = true;
  $('error').hidden = true;
  renderControls();
  try { state = await api(path, payload); render(); }
  catch (error) {
    showError(error);
    try { state = await api('/api/state'); render(); } catch (_) { /* Keep the last visible state on disconnect. */ }
  } finally { busy = false; renderControls(); }
}

function renderControls() {
  const active = Boolean(state?.intent) && !state?.reservation;
  const pending = Boolean(state?.pending);
  $('approve').disabled = busy || !state;
  $('reset').disabled = busy;
  $('step').disabled = busy || !active || pending || state?.phase === 'stopped';
  $('probe').disabled = busy || !active || pending || $('scenario').value === 'normal' || state?.phase === 'stopped';
  $('scenario').disabled = busy || pending;
  $('export').disabled = busy || !state || !state.audit.length;
  $('cancel-confirm').disabled = busy;
  updateConfirmClock();
}

function render() {
  const intent = state.intent;
  $('intent-fields').disabled = Boolean(intent) || busy;
  $('approve').hidden = Boolean(intent);
  $('reset').hidden = !intent;
  $('contract-status').hidden = !intent;
  if (intent) {
    $('date').value = intent.date; $('party').value = String(intent.party); $('time').value = intent.time;
    $('contract-status').textContent = `Intent approved · ${intent.budget.steps} steps remaining · synthetic contact ${intent.phone_mask}`;
  }
  document.querySelectorAll('.slots span').forEach((slot) => {
    slot.classList.toggle('selected', slot.textContent === (intent?.time || $('time').value));
  });
  const options = state.scenarios;
  if ($('scenario').options.length !== options.length) {
    $('scenario').replaceChildren(...options.map((scenario) => {
      const option = node('option', scenario.label); option.value = scenario.id; return option;
    }));
  }
  scenarioChanged();
  const last = state.audit.at(-1);
  $('decision').className = 'decision ' + (last?.verdict.toLowerCase() || 'ready');
  $('decision').querySelector('.decision-symbol').textContent = last?.verdict === 'DENY' ? '×' : last?.verdict === 'CONFIRM' ? '!' : '✓';
  const titles = {ALLOW: 'Action allowed', DENY: 'Action blocked', CONFIRM: 'Your confirmation is needed'};
  $('decision-title').textContent = state.reservation ? 'Fixture reservation complete' : last ? titles[last.verdict] : 'Ready for intent';
  $('decision-reason').textContent = last ? `${last.action} · ${last.reason.replaceAll('_', ' ').toLowerCase()}` : 'Approve the task to begin.';
  $('decision-rule').textContent = last ? last.rules.join(' · ') : '';
  $('receipt').hidden = !state.reservation;
  if (state.reservation) {
    $('receipt-id').textContent = state.reservation.id;
    $('receipt-details').textContent = `${state.reservation.report} ${state.reservation.party} guests · ${state.reservation.date} · ${state.reservation.time}`;
  }
  const progress = !intent ? 0 : state.reservation ? 4 : state.pending ? 3 : state.step_index >= 2 ? 2 : 1;
  document.querySelectorAll('.journey li').forEach((item, index) => {
    item.classList.toggle('current', index === progress); item.classList.toggle('done', index < progress);
    if (index === progress) item.setAttribute('aria-current', 'step'); else item.removeAttribute('aria-current');
  });
  renderAudit(); renderRules(); renderConfirmation(); renderControls();
}

function renderAudit() {
  $('audit-count').textContent = state.audit.length ? `${state.audit.length} decisions` : '';
  const rows = state.audit.map((entry) => {
    const row = node('tr');
    row.append(node('td', String(entry.seq)));
    const action = node('td', entry.action);
    action.append(node('span', `${entry.component} · ${entry.reason.replaceAll('_', ' ').toLowerCase()}`, 'action-detail'));
    row.append(action, node('td', entry.taint), node('td', entry.rules.join(', '), 'rule-cell'), node('td', entry.verdict, 'verdict ' + entry.verdict.toLowerCase()));
    return row;
  });
  if (!rows.length) { const row = node('tr'); const cell = node('td', 'Every decision leaves evidence.', 'empty'); cell.colSpan = 5; row.append(cell); rows.push(row); }
  $('audit-body').replaceChildren(...rows);
  if (state.audit.length) { const scroller = document.querySelector('.table-scroll'); scroller.scrollTop = scroller.scrollHeight; }
}

function renderRules() {
  if ($('rules-list').children.length) return;
  $('rules-list').replaceChildren(...state.rules.map((rule) => {
    const item = node('article', undefined, 'rule'); const content = node('div');
    content.append(node('h3', rule.title), node('p', rule.description)); item.append(node('code', rule.id), content); return item;
  }));
}

function scenarioChanged() {
  const scenario = state?.scenarios.find((item) => item.id === $('scenario').value);
  $('scenario-description').textContent = scenario?.description || '';
  renderControls();
}

function renderConfirmation() {
  const pending = state.pending;
  if (!pending) {
    pendingNonce = null; clearInterval(confirmTimer); confirmTimer = null;
    if ($('confirm-dialog').open) $('confirm-dialog').close();
    return;
  }
  if (pendingNonce !== pending.nonce) {
    pendingNonce = pending.nonce;
    $('confirm-action').textContent = pending.action;
    $('confirm-origin').textContent = pending.origin;
    $('confirm-data').textContent = JSON.stringify(pending.data, null, 2);
    if (!$('confirm-dialog').open) $('confirm-dialog').showModal();
    $('cancel-confirm').focus();
    clearInterval(confirmTimer); confirmTimer = setInterval(updateConfirmClock, 100);
  }
  updateConfirmClock();
}

function updateConfirmClock() {
  if (!state?.pending) return;
  const now = Date.now() / 1000;
  const remaining = Math.max(0, Math.ceil(state.pending.expires_at - now));
  const armed = now >= state.pending.ready_at;
  $('accept-confirm').disabled = busy || !armed || remaining === 0;
  $('confirm-timer').textContent = remaining === 0 ? 'Approval expired. Cancel, then request a fresh action.' : !armed ? 'Reviewing action…' : `One-use approval · expires in ${remaining}s`;
}

document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => {
  document.querySelectorAll('.view').forEach((view) => { view.hidden = view.id !== button.dataset.view + '-view'; });
  document.querySelectorAll('[data-view]').forEach((item) => {
    const selected = item === button; item.classList.toggle('active', selected);
    if (selected) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
  });
}));
document.querySelector('.brand').addEventListener('click', () => document.querySelector('[data-view="workspace"]').click());
$('intent-form').addEventListener('submit', (event) => {
  event.preventDefault(); mutate('/api/intent', {party: Number($('party').value), time: $('time').value, date: $('date').value});
});
$('time').addEventListener('change', () => { if (state) render(); });
$('reset').addEventListener('click', () => mutate('/api/reset', {}));
$('step').addEventListener('click', () => mutate('/api/step', {scenario: 'normal'}));
$('probe').addEventListener('click', () => mutate('/api/step', {scenario: $('scenario').value}));
$('scenario').addEventListener('change', scenarioChanged);
$('accept-confirm').addEventListener('click', () => mutate('/api/confirm', {nonce: pendingNonce, accept: true}));
$('cancel-confirm').addEventListener('click', () => mutate('/api/confirm', {nonce: pendingNonce, accept: false}));
$('confirm-dialog').addEventListener('cancel', (event) => { event.preventDefault(); mutate('/api/confirm', {nonce: pendingNonce, accept: false}); });
$('confirm-dialog').addEventListener('keydown', (event) => { if (event.key === 'Enter') event.preventDefault(); });
$('confirm-form').addEventListener('submit', (event) => event.preventDefault());
$('export').addEventListener('click', async () => {
  try {
    const trace = await api('/api/export');
    const url = URL.createObjectURL(new Blob([JSON.stringify(trace, null, 2)], {type: 'application/json'}));
    const link = node('a'); link.href = url; link.download = 'neo-decision-trace.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { showError(error); }
});
api('/api/state').then((value) => { state = value; render(); }).catch(showError);
