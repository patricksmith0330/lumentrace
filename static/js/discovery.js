window.discoveryApp = function () {
  return {
    scanning: false,
    adding: false,
    hasScanned: false,
    devices: [],
    selected: [],
    get allSelected() { return this.devices.length > 0 && this.selected.length === this.devices.length; },
    isSelected(ip) { return this.selected.some((device) => device.ip === ip); },
    toggle(device) {
      this.selected = this.isSelected(device.ip)
        ? this.selected.filter((item) => item.ip !== device.ip)
        : [...this.selected, device];
    },
    toggleAll(checked) { this.selected = checked ? [...this.devices] : []; },
    async scan() {
      this.scanning = true;
      this.selected = [];
      try {
        const data = await apiFetch('/discover/scan', { method: 'POST' });
        this.devices = data.devices || [];
        this.hasScanned = true;
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        this.scanning = false;
      }
    },
    async addSelected() {
      this.adding = true;
      try {
        const data = await apiFetch('/add_selected_devices', { method: 'POST', body: this.selected });
        showToast(data.message, 'success');
        window.location.assign('/');
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        this.adding = false;
      }
    },
  };
};
