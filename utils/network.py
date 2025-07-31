import socket
import time
import logging
import re
import ipaddress
from datetime import datetime
from ping3 import ping
from scapy.all import srp, Ether, ARP, getmacbyip

logger = logging.getLogger(__name__)


def is_valid_mac(mac):
    return re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac) is not None


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_device_online(ip, state_manager=None):
    try:
        if ping(ip, timeout=0.8) is not None:
            if state_manager:
                for dev in state_manager.get('devices', []):
                    if dev['ip'] == ip:
                        dev['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        break
            return True
    except Exception as e:
        logger.debug(f"Ping failed for {ip}: {e}")
    return False


def send_wol(mac, state_manager=None):
    try:
        mac_bytes = bytes.fromhex(mac.replace(':', '').replace('-', ''))
        packet = b'\xff' * 6 + mac_bytes * 16
        
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, ('<broadcast>', 9))
        
        if state_manager:
            state_manager.add_log(f"WOL packet sent to MAC: {mac}", 'INFO')
            state_manager.add_event('wol_sent', f'Wake-on-LAN sent to {mac}', {'mac': mac})
        
        logger.info(f"WOL packet sent to MAC: {mac}")
        return True
        
    except Exception as e:
        if state_manager:
            state_manager.add_log(f'WOL failed for MAC {mac}: {e}', 'ERROR')
        logger.error(f'WOL failed for MAC {mac}: {e}')
        return False


def get_mac_from_ip(ip):
    try:
        ping(ip, timeout=0.5)
        time.sleep(0.5)
        
        mac = getmacbyip(ip)
        if mac:
            return mac.upper()
    except Exception as e:
        logger.warning(f"Failed to get MAC for {ip}: {e}")
    return None


def discover_devices(ip_range, timeout=2, state_manager=None):
    logger.info(f"Scanning network: {ip_range}")
    
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range), 
                     timeout=timeout, verbose=0)
        
        devices = [{'ip': r.psrc, 'mac': r.hwsrc.upper()} for s, r in ans]
        
        if state_manager:
            state_manager.add_log(f"Network scan completed. Found {len(devices)} devices.", 'INFO')
        
        return devices
        
    except Exception as e:
        error_msg = f"Network scan failed for range {ip_range}: {e}"
        if state_manager:
            state_manager.add_log(error_msg, 'ERROR')
        logger.error(error_msg)
        return []