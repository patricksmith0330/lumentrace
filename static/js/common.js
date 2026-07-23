(function () {
  const csrfToken = () => document.querySelector('meta[name="csrf-token"]')?.content || '';

  window.apiFetch = async function (url, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && typeof options.body !== 'string') {
      headers.set('Content-Type', 'application/json');
      options.body = JSON.stringify(options.body);
    }
    if (!['GET', 'HEAD'].includes((options.method || 'GET').toUpperCase())) {
      headers.set('X-CSRFToken', csrfToken());
    }
    const response = await fetch(url, { ...options, headers });
    let payload = {};
    try { payload = await response.json(); } catch (_) { /* no JSON body */ }
    if (!response.ok) {
      throw new Error(payload.message || `Request failed (${response.status})`);
    }
    return payload;
  };

  window.showToast = function (message, type = 'info') {
    const region = document.getElementById('toast-region');
    if (!region) return;
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.textContent = message;
    region.appendChild(toast);
    window.setTimeout(() => toast.remove(), 4500);
  };

  window.shellApp = function () {
    return {
      menuOpen: false,
      accountMenuOpen: false,
    };
  };

  window.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-flash]').forEach((element) => {
      window.setTimeout(() => element.remove(), 5500);
    });
  });
})();
