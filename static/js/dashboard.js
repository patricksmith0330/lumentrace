window.dashboardApp = function (refreshSeconds) {
  return {
    loading: true,
    connected: true,
    upsSystems: [],
    devices: [],
    logs: [],
    recoveryState: 'NORMAL',
    predictedTime: 'Insufficient data',
    query: '',
    waking: {},
    lastUpdated: '',
    timer: null,

    init() {
      this.refresh();
      this.timer = window.setInterval(() => this.refresh(), Math.max(5, refreshSeconds) * 1000);
    },

    async refresh() {
      this.loading = true;
      try {
        const data = await apiFetch('/api/dashboard');
        this.upsSystems = data.ups_systems || [];
        this.devices = (data.devices || []).map((device, index) => ({ ...device, index }));
        this.logs = data.logs || [];
        this.recoveryState = data.recovery_state || 'NORMAL';
        this.predictedTime = data.predicted_time || 'Insufficient data';
        this.connected = true;
        this.lastUpdated = `Updated ${new Intl.DateTimeFormat([], { hour: 'numeric', minute: '2-digit' }).format(new Date())}`;
      } catch (error) {
        this.connected = false;
        showToast(error.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    get filteredDevices() {
      const term = this.query.trim().toLowerCase();
      if (!term) return this.devices;
      return this.devices.filter((device) => [device.name, device.ip, device.mac].some((value) => (value || '').toLowerCase().includes(term)));
    },
    get onlineCount() { return this.devices.filter((device) => device.online).length; },
    get onBattery() { return this.upsSystems.some((ups) => ups.status === 'OB'); },
    get hasUpsError() { return this.upsSystems.some((ups) => !['OL', 'OB'].includes(ups.status)); },
    get healthClass() {
      if (!this.connected || this.hasUpsError) return 'is-error';
      if (!this.upsSystems.length || this.onBattery || this.recoveryState !== 'NORMAL') return 'is-warning';
      return 'is-healthy';
    },
    get healthTitle() {
      if (!this.connected) return 'Connection interrupted';
      if (this.hasUpsError) return 'UPS needs attention';
      if (this.onBattery) return 'Running on battery';
      if (this.recoveryState !== 'NORMAL') return 'Recovery in progress';
      return this.upsSystems.length ? 'Power is healthy' : 'Setup required';
    },
    get healthDetail() {
      if (!this.connected) return 'LumenTrace will try again automatically.';
      if (!this.upsSystems.length) return 'Configure a UPS to enable outage recovery.';
      if (this.onBattery) return 'Online devices have been captured for recovery.';
      if (this.recoveryState === 'WAITING_FOR_RECHARGE') return 'Waiting for every UPS to reach the wake threshold.';
      return `${this.onlineCount} of ${this.devices.length} devices online.`;
    },
    get summaryText() {
      if (!this.upsSystems.length) return 'Configure your first UPS and add the devices you want to recover.';
      return `${this.upsSystems.length} UPS ${this.upsSystems.length === 1 ? 'system' : 'systems'} · ${this.onlineCount} of ${this.devices.length} devices online`;
    },
    get recoveryLabel() {
      const labels = {
        NORMAL: 'Ready',
        OUTAGE_CAPTURED: 'Outage captured',
        WAITING_FOR_RECHARGE: 'Waiting for recharge',
        WAKING: 'Waking devices',
      };
      return labels[this.recoveryState] || 'Checking';
    },

    upsStatusLabel(status) {
      return ({ OL: 'Online', OB: 'On battery', TIMEOUT: 'Timed out', ERROR: 'Unavailable' })[status] || 'Unknown';
    },
    upsBadgeClass(status) {
      if (status === 'OL') return 'is-online';
      if (status === 'OB') return 'is-battery';
      return 'is-error';
    },
    meterClass(value) { return value < 35 ? 'is-low' : value < 70 ? 'is-medium' : ''; },

    async wake(device) {
      this.waking[device.ip] = true;
      try {
        const data = await apiFetch('/wake_device', { method: 'POST', body: { mac: device.mac } });
        showToast(data.message, 'success');
      } catch (error) {
        showToast(error.message, 'error');
      } finally {
        this.waking[device.ip] = false;
      }
    },
    formatDate(value) {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(date);
    },
    formatRelative(value) {
      const date = new Date(value.includes('T') ? value : value.replace(' ', 'T'));
      if (Number.isNaN(date.getTime())) return value;
      const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
      if (seconds < 60) return 'just now';
      if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
      if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
      return `${Math.floor(seconds / 86400)}d ago`;
    },
  };
};
