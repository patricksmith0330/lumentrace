import subprocess
import time
import logging
from collections import defaultdict
from config import CACHE_TTL

logger = logging.getLogger(__name__)

ups_cache = defaultdict(lambda: {'data': None, 'timestamp': 0})


def get_ups_data(ups_configs, state_manager=None):
    all_ups_data = []
    
    for config in ups_configs:
        ups_name = config.get('name')
        host = config.get('ip')
        port = config.get('port', 3493)
        ups_id = config.get('id', f"{ups_name}_{host}")
        
        cache_key = f"{host}:{port}:{ups_name}"
        
        if ups_cache[cache_key]['data'] and (time.time() - ups_cache[cache_key]['timestamp']) < CACHE_TTL:
            all_ups_data.append(ups_cache[cache_key]['data'])
            continue
        
        try:
            cmd = ['upsc', f'{ups_name}@{host}:{port}']
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
            
            if process.returncode != 0:
                error_message = process.stderr.strip() if process.stderr else f"Command returned {process.returncode}"
                raise RuntimeError(f"upsc failed: {error_message}")
            
            output = process.stdout
            data_map = {}
            for line in output.splitlines():
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    data_map[key] = value
            
            status = data_map.get('ups.status', 'UNKNOWN').split()[0]
            data = {
                'id': ups_id,
                'name': ups_name,
                'status': status,
                'battery': int(float(data_map.get('battery.charge', 0))),
                'input_voltage': float(data_map.get('input.voltage', 0)),
                'output_voltage': float(data_map.get('output.voltage', 0)),
                'load': float(data_map.get('ups.load', 0))
            }
            
            ups_cache[cache_key] = {'data': data, 'timestamp': time.time()}
            all_ups_data.append(data)
            
        except subprocess.TimeoutExpired:
            msg = f'UPS query for {ups_name}@{host} timed out.'
            if state_manager:
                state_manager.add_log(msg, 'WARNING')
            logger.warning(msg)
            
            all_ups_data.append({
                'id': ups_id,
                'name': ups_name,
                'status': 'TIMEOUT',
                'battery': 0,
                'input_voltage': 0,
                'output_voltage': 0,
                'load': 0
            })
            
        except Exception as e:
            msg = f'UPS query failed for {ups_name}@{host}: {e}'
            if state_manager:
                state_manager.add_log(msg, 'ERROR')
            logger.error(msg)
            
            all_ups_data.append({
                'id': ups_id,
                'name': ups_name,
                'status': 'ERROR',
                'battery': 0,
                'input_voltage': 0,
                'output_voltage': 0,
                'load': 0
            })
    
    return all_ups_data


def test_ups_connection(ups_config):
    try:
        name = ups_config['name']
        host = ups_config['ip']
        port = ups_config.get('port', 3493)
        
        cmd = ['upsc', f'{name}@{host}:{port}']
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        
        if process.returncode == 0:
            return True, "Connection successful"
        else:
            error_msg = process.stderr.strip() if process.stderr else "Unknown error"
            return False, f"Connection failed: {error_msg}"
            
    except subprocess.TimeoutExpired:
        return False, "Connection timeout"
    except Exception as e:
        return False, f"Error: {str(e)}"


def analyze_ups_status(ups_data_list):
    if not ups_data_list:
        return 'UNKNOWN', False, False
    
    is_on_battery = any(u.get('status') == 'OB' for u in ups_data_list)
    is_online = all(u.get('status') == 'OL' for u in ups_data_list)
    
    overall_status = 'OB' if is_on_battery else 'OL' if is_online else 'MIXED'
    
    return overall_status, is_on_battery, is_online