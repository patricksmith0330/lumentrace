import time
import logging
import threading
from utils.network import is_device_online, send_wol
from utils.ups import get_ups_data, analyze_ups_status
from services.uptime import update_uptime_stats

logger = logging.getLogger(__name__)


class MonitoringService:
    
    def __init__(self, state_manager, poll_interval=10):
        self.state_manager = state_manager
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
    
    def start(self):
        if self.running:
            logger.warning("Monitoring service already running")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Monitoring service started")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Monitoring service stopped")
    
    def _monitor_loop(self):
        while self.running:
            try:
                self._check_status()
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
            
            time.sleep(self.poll_interval)
    
    def _check_status(self):
        with self.state_manager.locked() as state:
            self._check_status_locked(state)
            self.state_manager.save()

    def _check_status_locked(self, state):
        settings = state.get('settings', {})
        
        if settings.get('verbose_logging', False):
            self.state_manager.add_log("Polling UPS and device status...", 'DEBUG')
        
        ups_configs = settings.get('ups_configs', [])
        threshold = settings.get('wol_battery_threshold', 80)
        all_ups = get_ups_data(ups_configs, self.state_manager)
        
        if all_ups:
            overall_status, is_on_battery, is_online = analyze_ups_status(all_ups)
            
            if is_on_battery:
                on_battery_ups = [u['battery'] for u in all_ups if u.get('status') == 'OB']
                if on_battery_ups:
                    state['battery_history'].append({
                        'timestamp': time.time(),
                        'battery': min(on_battery_ups)
                    })
                    max_history = settings.get('log_retention', 100)
                    state['battery_history'] = state['battery_history'][-max_history:]
            
            recovery_state = state.get('recovery_state', 'NORMAL')

            if is_on_battery and recovery_state == 'NORMAL':
                self.state_manager.add_log('Outage detected. Taking snapshot of online devices.', 'WARNING')
                self.state_manager.add_event('power_outage', 'Power outage detected', {
                    'ups_status': [{'name': u['name'], 'battery': u['battery']} for u in all_ups]
                })
                
                state['outage_snapshot'] = [
                    d['mac'] for d in state['devices'] 
                    if d.get('mac') and is_device_online(d['ip'], self.state_manager)
                ]
                state['recovery_state'] = 'OUTAGE_CAPTURED'
                recovery_state = 'OUTAGE_CAPTURED'

            snapshot = state.get('outage_snapshot', [])
            all_online = all(u.get('status') == 'OL' for u in all_ups)
            batteries_ready = all(u.get('battery', 0) >= threshold for u in all_ups)

            if snapshot and not is_on_battery and recovery_state in {'OUTAGE_CAPTURED', 'WAITING_FOR_RECHARGE'}:
                if recovery_state != 'WAITING_FOR_RECHARGE':
                    self.state_manager.add_log('Power restored. Waiting for UPS batteries to recharge.', 'INFO')
                    self.state_manager.add_event('power_restored', 'Power has been restored', {
                        'ups_status': [{'name': u['name'], 'battery': u['battery']} for u in all_ups]
                    })
                state['recovery_state'] = 'WAITING_FOR_RECHARGE'

            if snapshot and all_online and batteries_ready:
                state['recovery_state'] = 'WAKING'
                self.state_manager.add_log(f'UPS units charged past {threshold}%. Sending WOL.', 'INFO')
                for mac in snapshot:
                    send_wol(mac, self.state_manager)
                state['outage_snapshot'] = []
                state['recovery_state'] = 'NORMAL'

            elif not snapshot and not is_on_battery:
                state['recovery_state'] = 'NORMAL'

            state['last_status'] = overall_status

        for dev in state['devices']:
            dev['online'] = is_device_online(dev['ip'], self.state_manager)

        update_uptime_stats(self.state_manager)
