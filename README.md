# GlitchTrap

A concurrent Nmap scanning tool that runs multiple scans in parallel from a JSON config, diffs results against previous runs, and reports new hosts and open ports to a Discord webhook.

This tool is specificially made for use for CCDC and may require modification for general use.

## Requirements

### System

- Python 3.10+
- `nmap` installed and available in `$PATH`

### Python packages

```
pip install -r requirements.txt
```

`requirements.txt` includes:
- `python-libnmap` — XML result parsing
- `requests` — Discord webhook delivery

## External Configuration

### Discord Webhook

Create a file named `webhook.link` in the project root containing your Discord webhook URL (no trailing newline required):

```
https://discord.com/api/webhooks/<id>/<token>
```

GlitchTrap will exit at startup if this file is missing.

## Scan Config JSON

Scans are defined in a JSON file with the following structure:

```json
{
  "name": "scan_set_name",
  "args": "-T4 --top-ports 1000 -A --host-timeout 100s --stats-every 30s",
  "timeout": "300",
  "scans": [
    { "name": "team01", "target": "192.168.1.0/24" },
    { "name": "team02", "target": "10.0.0.5" }
  ]
}
```

| Field | Description |
|-------|-------------|
| `name` | Label for this scan set. Used as the output subdirectory name and in Discord messages. |
| `args` | Nmap flags applied to every scan in this set. |
| `timeout` | Per-scan timeout in seconds. |
| `scans` | List of scan entries. Each requires a `name` and a `target` (IP, CIDR, or space-separated targets). |

## Usage

```
python GlitchTrap.py <INPUT_JSON> <OUTPUT_DIR>
```

**Example:**

```
python GlitchTrap.py scan1.json ./results
```

Results are written to `<OUTPUT_DIR>/<scan_name>/` in Nmap's three output formats (`.nmap`, `.xml`, `.gnmap`). A `<team>_latest.xml` backup is kept per target for diffing, alongside a `<team>_known_hosts.json` file that tracks all previously seen hosts and ports.

Up to 4 scans run concurrently. Discord notifications are sent after each scan completes (reporting new hosts/ports) and once when all scans finish.

## Output Structure

```
results/
└── <scan_name>/
    ├── team01_20260310_120000.xml
    ├── team01_20260310_120000.nmap
    ├── team01_20260310_120000.gnmap
    ├── team01_latest.xml
    └── team01_known_hosts.json
```

## Discord Notifications

GlitchTrap posts to Discord:
- **After each scan** — lists any new hosts or newly opened ports compared to all previous runs.
- **On scan failure or timeout** — posts an error message.
- **When all scans finish** — posts a completion summary.

New findings are tracked cumulatively in `<team>_known_hosts.json` so repeat scans only alert on genuinely new activity.

## Other Considerations

### Web access to logs (dev)

To host logs in a place where other team members can access them, a simple python web server can be used:

`sudo python3 -m http.server 80`

### SMB access to logs

To set up a simple SMB Share

```
sudo apt update
sudo apt install samba samba-common-bin
sudo nano /etc/samba/smb.conf
```

Then add the following:

```
[shared]
    path = /home/yourusername/shared
    browsable = yes
    read only = yes
    guest ok = yes
    guest only = yes
```

Finally use `sudo systemctl restart smbd` to restart the service and activate the shares.

### User can access the share via:

#### From Linux:

`smbclient //your-linux-ip/shared -N`

(-N means no password)

#### From Windows:

Open File Explorer
Type `\\your-linux-ip\shared` in the address bar
It should connect without prompting for credentials

#### From Mac:

Finder → Go → Connect to Server

Enter `smb://your-linux-ip/shared`

#### Common Issues
Permission denied? Make sure the directory is readable:

`chmod 755 ~/shared`

Share not showing up? Test the config:

`testparm`

Firewall blocking? Allow Samba:

`sudo ufw allow 139,445/tcp`

### Systemd Service & Timer Setup

#### Service: `GT-Top1000.service`

Create the file at `/etc/systemd/system/GT-Top1000.service`:

```ini
[Unit]
Description=Run Top1000 GlitchTrap Script

[Service]
ExecStart=/usr/bin/python3 /home/user/GlitchTrap/GlitchTrap.py
WorkingDirectory=/home/user/GlitchTrap
User=user
```

> **Note:** The service has no `[Install]` section intentionally — it is not meant to be enabled directly. It is started exclusively by the timer.

#### Timer: `GT-Top1000.timer`

Create the file at `/etc/systemd/system/GT-Top1000.timer`:

```ini
[Unit]
Description=Run Top1000 Every 10 minutes

[Timer]
OnBootSec=30s
OnCalendar=*:0/10
AccuracySec=1s
Unit=GT-Top1000.service

[Install]
WantedBy=timers.target
```

- `OnBootSec=30s` — fires 30 seconds after boot for the first run
- `OnCalendar=*:0/10` — fires every 10 minutes on the clock (e.g. :00, :10, :20...)
- `AccuracySec=1s` — reduces trigger jitter to ~1 second

---

#### Installation

After creating both unit files, run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now GT-Top1000.timer
```

This reloads systemd's unit index, enables the timer to survive reboots, and starts it immediately.


#### Verifying the Timer

**Check timer status and next trigger time:**
```bash
systemctl status GT-Top1000.timer
```

Expected output should show `Active: active (waiting)` and a future `Trigger:` time.

**List all active timers (with last/next run times):**
```bash
systemctl list-timers | grep GT
```

**Watch live service logs as the timer fires:**
```bash
journalctl -fu GT-Top1000.service
```

**View recent service run history:**
```bash
journalctl -u GT-Top1000.service --since "1 hour ago"
```