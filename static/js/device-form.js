window.deviceForm = function (initialIp = '', initialMac = '') {
  return {
    ip: initialIp,
    mac: initialMac,
    discovering: false,
    message: '',
    async discoverMac() {
      this.discovering = true;
      this.message = '';
      try {
        const data = await apiFetch(`/discover_mac?ip=${encodeURIComponent(this.ip)}`);
        this.mac = data.mac;
        this.message = 'MAC address found.';
      } catch (error) {
        this.message = error.message;
      } finally {
        this.discovering = false;
      }
    },
  };
};

window.removeDevice = async function (index, name) {
  if (!window.confirm(`Remove ${name}? This cannot be undone.`)) return;
  try {
    const data = await apiFetch('/remove_device', { method: 'POST', body: { index } });
    showToast(data.message, 'success');
    window.location.assign('/');
  } catch (error) {
    showToast(error.message, 'error');
  }
};
