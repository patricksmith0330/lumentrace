  # LumenTrace: Automated Wake-on-LAN for UPS Power Restoration

 <img width="1440" height="807" alt="Screenshot 2025-07-31 at 5 34 14 PM (1)" src="https://github.com/user-attachments/assets/a4c0a0c9-6c1d-4efc-a498-9fb25ac1528a" />

## Overview

LumenTrace is a smart tool designed to monitor UPS (Uninterruptible Power Supply) status and manage Wake-on-LAN (WOL) for your devices during power outages. With a clean, modern web interface, it provides real-time visibility into essential UPS metrics like battery level and load, and lets you configure devices to automatically power back on when electricity is restored.

LumenTrace goes beyond simple WOL automation. It intelligently tracks which devices were online at the time of the outage and retains this data—even if the LumenTrace host itself loses power and reboots. Once power is restored and all monitored UPS units are back online with batteries charged to your defined threshold (default: 80%), LumenTrace automatically sends WOL packets to bring those devices back up. This ensures a smooth and reliable recovery after power loss, regardless of whether the LumenTrace system remained powered throughout the event.

Inspired by the original [wolnut](https://github.com/hardwarehaven/wolnut) project.

---

## Setup Instructions

### Using Docker Compose

#### 1. Create `docker-compose.yml`

```yaml
services:
  lumentrace:
    image: pwsmith1988/lumentrace:latest
    container_name: lumentrace
    restart: unless-stopped
    environment:
      - TZ=America/New_York  # Replace with your timezone
    cap_add:
      - NET_RAW
      - NET_ADMIN
      - NET_BROADCAST
    network_mode: host
    volumes:
      - ./data:/data
    env_file: .env

volumes:
  lumentrace-data:
```

#### 2. Create `.env`

```bash
SECRET_KEY=YOURSECRETKEYHERE          #place your generated secrect key here
```

#### 3. Start the container

```bash
docker compose up -d
```
---

## 🚀 First-Time Configuration

Once the container is running, all configuration is managed through the web interface. Follow these steps to get started:

### Access the Web UI
Open your browser and navigate to http://your-host-ip:5000.

### Navigate to Settings
In the sidebar, click on the Settings icon.

### Configure Your UPS
Enter the required details for your setup, including the NUT Server IP Address and UPS Name. Adjust any other settings as needed.

### Save Settings
Click the "Save Settings" button. The application will immediately begin monitoring your UPS with the new configuration.

### Add Your Devices
Return to the Dashboard and begin adding the devices you wish to manage.

## License
LumenTrace is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](https://github.com/patricksmith0330/lumentrace/?tab=GPL-3.0-1-ov-file) for full details.
