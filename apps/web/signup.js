const form = document.getElementById('signupForm');
const formPanel = document.getElementById('signupFormPanel');
const successPanel = document.getElementById('signupSuccessPanel');
const errorEl = document.getElementById('signupError');

function showError(message) {
  if (!errorEl) return;
  errorEl.hidden = !message;
  errorEl.textContent = message ?? '';
}

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');
  const data = new FormData(form);
  const body = {
    organization_name: data.get('organization_name'),
    contact_email: data.get('contact_email'),
    contact_name: data.get('contact_name'),
    requested_plan: data.get('requested_plan'),
    intended_use: data.get('intended_use'),
    region: data.get('region'),
    high_scale_interest: data.get('high_scale_interest') === 'on',
  };
  try {
    const res = await fetch('/v1/signup-requests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (res.status === 429) {
        showError('Too many sign-up attempts. Please try again later.');
        return;
      }
      if (json.error === 'duplicate_request') {
        showError('A pending request already exists for this organization or email domain.');
        return;
      }
      showError('Could not submit request. Check required fields and try again.');
      return;
    }
    formPanel.hidden = true;
    successPanel.hidden = false;
    document.getElementById('submittedRequestId').textContent = json.request?.id ?? '—';
    document.getElementById('submittedRequestState').textContent = json.request?.state ?? 'submitted';
  } catch {
    showError('Network error while submitting request.');
  }
});