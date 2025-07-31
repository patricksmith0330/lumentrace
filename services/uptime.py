import time
import logging

logger = logging.getLogger(__name__)

def update_uptime_stats(state_manager):
    current_time = time.time()
    state = state_manager.state
    
    for device in state['devices']:
        device_id = device['ip']
        
        if device_id not in state['uptime_stats']:
            state['uptime_stats'][device_id] = {
                'total_checks': 0,
                'online_checks': 0,
                'last_state': None,
                'last_change': current_time,
                'current_uptime': 0,
                'current_downtime': 0
            }
        
        stats = state['uptime_stats'][device_id]
        stats['total_checks'] += 1
        
        if device.get('online', False):
            stats['online_checks'] += 1
            
            if stats['last_state'] != 'online':
                if stats['last_state'] == 'offline':
                    downtime_duration = current_time - stats['last_change']
                    state_manager.add_event(
                        'device_online',
                        f"{device['name']} came online",
                        {
                            'device': device['name'],
                            'ip': device['ip'],
                            'downtime_duration': downtime_duration
                        }
                    )
                stats['last_state'] = 'online'
                stats['last_change'] = current_time
                stats['current_uptime'] = 0
            else:
                stats['current_uptime'] = current_time - stats['last_change']
        else:
            if stats['last_state'] != 'offline':
                if stats['last_state'] == 'online':
                    uptime_duration = current_time - stats['last_change']
                    state_manager.add_event(
                        'device_offline',
                        f"{device['name']} went offline",
                        {
                            'device': device['name'],
                            'ip': device['ip'],
                            'uptime_duration': uptime_duration
                        }
                    )
                stats['last_state'] = 'offline'
                stats['last_change'] = current_time
                stats['current_downtime'] = 0
            else:
                stats['current_downtime'] = current_time - stats['last_change']

def get_uptime_statistics(state_manager):
    stats = []
    state = state_manager.state
    
    for device in state['devices']:
        device_stats = state['uptime_stats'].get(device['ip'], {})
        
        if device_stats.get('total_checks', 0) > 0:
            uptime_percentage = (device_stats['online_checks'] / device_stats['total_checks']) * 100
        else:
            uptime_percentage = 0
        
        stats.append({
            'name': device['name'],
            'ip': device['ip'],
            'uptime_percentage': round(uptime_percentage, 2),
            'current_status': device_stats.get('last_state', 'unknown'),
            'current_uptime': device_stats.get('current_uptime', 0),
            'current_downtime': device_stats.get('current_downtime', 0)
        })
    
    return stats

def get_event_timeline(state_manager, limit=50):
    events = state_manager.get('event_timeline', [])
    return events[-limit:][::-1]