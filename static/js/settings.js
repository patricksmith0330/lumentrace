window.settingsApp = function () {
  return {
    settings: { ups_configs: [] },
    newUps: { name: '', ip: '', port: 3493 },
    busy: {},
    init() {
      this.settings = JSON.parse(document.getElementById('settings-data')?.textContent || '{"ups_configs":[]}');
      this.settings.ups_configs ||= [];
    },
    async addUps() {
      try {
        const data = await apiFetch('/api/ups', { method: 'POST', body: this.newUps });
        this.settings.ups_configs.push(data.ups);
        this.newUps = { name: '', ip: '', port: 3493 };
        showToast(data.message, 'success');
      } catch (error) { showToast(error.message, 'error'); }
    },
    async saveUps(ups) {
      this.busy[ups.id] = true;
      try {
        const data = await apiFetch(`/api/ups/${encodeURIComponent(ups.id)}`, { method: 'PUT', body: ups });
        showToast(data.message, 'success');
      } catch (error) { showToast(error.message, 'error'); }
      finally { this.busy[ups.id] = false; }
    },
    async removeUps(ups) {
      if (!window.confirm(`Remove ${ups.name}?`)) return;
      this.busy[ups.id] = true;
      try {
        const data = await apiFetch(`/api/ups/${encodeURIComponent(ups.id)}`, { method: 'DELETE' });
        this.settings.ups_configs = this.settings.ups_configs.filter((item) => item.id !== ups.id);
        showToast(data.message, 'success');
      } catch (error) { showToast(error.message, 'error'); }
      finally { this.busy[ups.id] = false; }
    },
    async testUps(ups) {
      const key = ups.id || 'new';
      this.busy[key] = true;
      try {
        const data = await apiFetch('/api/ups/test', { method: 'POST', body: ups });
        showToast(data.message, 'success');
      } catch (error) { showToast(error.message, 'error'); }
      finally { this.busy[key] = false; }
    },
  };
};
