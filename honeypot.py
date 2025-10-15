#!/usr/bin/env python3

import socket
import threading
import paramiko
import time
from datetime import datetime
import os
import requests
import subprocess
import logging
import tkinter as tk
from tkinter import messagebox
from queue import Queue
import sys

# ================= CONFIGURATION =================
HOST = '0.0.0.0'
SERVICES = {
    22: "SSH",
    80: "HTTP",
    21: "FTP",
    23: "Telnet"
}

API_HOST = ('192.168.139.20')
API_PORT = 5000

LOG_FILE = "honeypot.log"
BANNED_IPS_FILE = "banned_ips.txt"
HOST_KEY_PATH = "host_key"

# Alert queue for desktop notifications
alert_queue = Queue()

# In-memory event storage
events = []


# ================= DESKTOP ALERT SYSTEM =================
class DesktopAlertSystem:
    def __init__(self):
        self.alert_methods = [
            self._try_notify_send,
            self._try_zenity_popup,
            self._try_tkinter_popup,
            self._try_console_bell,
            self._fallback_console
        ]
        self.last_alert_time = 0
        self.alert_cooldown = 5  # seconds between alerts

    def show_alert(self, alert_msg):
        """Show desktop alert using best available method"""
        current_time = time.time()

        # Rate limiting to prevent spam
        if current_time - self.last_alert_time < self.alert_cooldown:
            return True

        self.last_alert_time = current_time

        # Try all alert methods until one works
        for method in self.alert_methods:
            if method(alert_msg):
                return True
        return False

    def _try_notify_send(self, alert_msg):
        """Method 1: Use notify-send (Linux desktop notifications)"""
        try:
            # Check if we're in a graphical environment
            if not os.environ.get('DISPLAY'):
                return False

            result = subprocess.run([
                'notify-send',
                '🚨 Honeypot Intrusion Detected',
                alert_msg,
                '--urgency=critical',
                '--icon=dialog-warning',
                '--expire-time=10000',
                '--app-name=Honeypot'
            ], capture_output=True, timeout=5, check=True)

            print(f"✅ Desktop notification sent: {alert_msg}")
            return True

        except (subprocess.SubprocessError, FileNotFoundError, PermissionError):
            return False

    def _try_zenity_popup(self, alert_msg):
        """Method 2: Use zenity for GUI popups (no Python GUI dependencies)"""
        try:
            if not os.environ.get('DISPLAY'):
                return False

            # Escape quotes for shell
            safe_msg = alert_msg.replace('"', '\\"')

            result = subprocess.run([
                'zenity',
                '--warning',
                '--title=🚨 Honeypot Alert',
                '--text=' + safe_msg,
                '--width=400',
                '--height=200',
                '--timeout=10'
            ], capture_output=True, timeout=10)

            if result.returncode == 0:
                print(f"✅ Zenity popup shown: {alert_msg}")
                return True

        except (subprocess.SubprocessError, FileNotFoundError):
            return False
        return False

    def _try_tkinter_popup(self, alert_msg):
        """Method 3: Use tkinter as fallback"""
        try:
            if not os.environ.get('DISPLAY'):
                return False

            # Create minimal tkinter popup
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)

            # Use messagebox for simplicity
            messagebox.showwarning(
                "🚨 Honeypot Intrusion",
                alert_msg,
                parent=root
            )

            root.destroy()
            print(f"✅ Tkinter popup shown: {alert_msg}")
            return True

        except Exception as e:
            # Tkinter often fails in headless environments
            return False

    def _try_console_bell(self, alert_msg):
        """Method 4: Use console bell and visual effects"""
        try:
            # Visual alert in terminal
            print(f"\n🔔 \033[1;31mALERT: {alert_msg}\033[0m 🔔")

            # Try to trigger system bell
            print('\a', end='', flush=True)

            # Flash terminal (if supported)
            print('\033[5;31m⚠️ \033[0m', end='', flush=True)
            time.sleep(0.1)

            return True

        except:
            return False

    def _fallback_console(self, alert_msg):
        """Method 5: Final fallback to console logging"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] 🚨 \033[1;31mCRITICAL: {alert_msg}\033[0m")

            # Log to system log if possible
            try:
                subprocess.run([
                    'logger',
                    '-t', 'honeypot',
                    f'ALERT: {alert_msg}'
                ], timeout=2)
            except:
                pass

            return True

        except:
            # Ultimate fallback - just print
            print(f"ALERT: {alert_msg}")
            return True


# Global alert system instance
alert_system = DesktopAlertSystem()


def show_desktop_alert():
    """Main alert dispatcher - processes alert queue"""
    while True:
        if not alert_queue.empty():
            alert_msg = alert_queue.get()
            alert_system.show_alert(alert_msg)
        time.sleep(0.1)

# ================= IP BANNING SYSTEM =================
class IPBanSystem:
    def __init__(self, banned_ips_file):
        self.banned_ips_file = banned_ips_file
        self.banned_ips = self.load_banned_ips()
        self.failed_attempts = {}

    def load_banned_ips(self):
        try:
            with open(self.banned_ips_file, 'r') as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()

    def save_banned_ips(self):
        with open(self.banned_ips_file, 'w') as f:
            for ip in self.banned_ips:
                f.write(ip + '\n')

    def is_banned(self, ip):
        return ip in self.banned_ips

    def record_failed_attempt(self, ip, service, max_attempts=3):
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = {'count': 0, 'services': set()}

        self.failed_attempts[ip]['count'] += 1
        self.failed_attempts[ip]['services'].add(service)

        print(f"⚠️ Failed attempt {self.failed_attempts[ip]['count']}/{max_attempts} from {ip} on {service}")

        if self.failed_attempts[ip]['count'] >= max_attempts:
            services = ', '.join(self.failed_attempts[ip]['services'])
            self.ban_ip(ip, f"Too many failed attempts on {services}")
            return True
        return False

    def ban_ip(self, ip, reason=""):
        if ip not in self.banned_ips:
            self.banned_ips.add(ip)
            self.save_banned_ips()

            ban_msg = f"🚨 BANNED: {ip} - {reason}"
            print(ban_msg)

            # Send desktop alert
            alert_queue.put(ban_msg)

            # Add to system firewall
            try:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                               check=True, timeout=5)
                print(f"✅ Added firewall rule for {ip}")
            except:
                print(f"⚠️ Could not add firewall rule for {ip}")

            return True
        return False


# Create global ban system
ip_ban_system = IPBanSystem(BANNED_IPS_FILE)

# ================= FLASK API SERVER =================
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/api/event', methods=['POST'])
def api_log_event():
    """Receive and process events from honeypots"""
    try:
        event_data = request.json
        events.append(event_data)

        # Keep only the last 1000 events to prevent memory issues
        if len(events) > 1000:
            events.pop(0)

        # Show desktop alert for login attempts
        if 'login' in event_data['message'].lower() or 'attempt' in event_data['message'].lower():
            alert_msg = f"{event_data['service']} login attempt from {event_data['ip']}"
            alert_queue.put(alert_msg)

        print(f"[API] {event_data['timestamp']} - {event_data['service']} - "
              f"{event_data['ip']} - {event_data['message']}")

        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"[API Error] {e}")
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/events', methods=['GET'])
def get_events():
    """Retrieve recent events"""
    try:
        limit = min(int(request.args.get('limit', 100)), 1000)
        return jsonify(events[-limit:])
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/ban_ip', methods=['POST'])
def ban_ip():
    """Manually ban an IP address"""
    try:
        ip = request.json.get('ip')
        reason = request.json.get('reason', 'Manual ban')

        if ip_ban_system.ban_ip(ip, reason):
            return jsonify({'status': 'success', 'message': f'Banned {ip}'})
        else:
            return jsonify({'status': 'error', 'message': 'IP already banned'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/banned_ips', methods=['GET'])
def get_banned_ips():
    """Get list of banned IPs"""
    return jsonify({
        'status': 'success',
        'banned_ips': list(ip_ban_system.banned_ips)
    })


@app.route('/')
def index():
    """Simple status page"""
    return jsonify({
        'status': 'running',
        'events_count': len(events),
        'banned_ips_count': len(ip_ban_system.banned_ips),
        'services': list(SERVICES.values())
    })


def run_api_server():
    """Run the Flask API server"""
    print(f"[*] Starting API server on {API_HOST}:{API_PORT}")
    try:
        app.run(host=API_HOST, port=API_PORT, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"[-] API server error: {e}")


# ================= LOGGING SYSTEM =================
def log_event(service, client_ip, message, data=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_message = f"{timestamp} - {service} - {client_ip} - {message}"

    if data:
        log_message += f" - Data: {data}"

    print(log_message)

    with open(LOG_FILE, "a") as f:
        f.write(log_message + "\n")

    send_to_api(service, client_ip, message, data)


def send_to_api(service, client_ip, message, data=None):
    """Send event to API server"""
    event_data = {
        'timestamp': datetime.now().isoformat(),
        'service': service,
        'ip': client_ip,
        'message': message,
        'data': data
    }

    try:
        api_url = f'http://{API_HOST}:{API_PORT}/api/event'
        response = requests.post(api_url, json=event_data, timeout=2)
        if response.status_code == 200:
            print(f"[API] Successfully sent to {API_HOST}")
        else:
            print(f"[API] Error {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[API] Connection failed: {e}")


# ================= SSH FAKE SHELL =================
class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.login_attempts = 0
        self.max_attempts = 3
        self.username = None

    def check_auth_password(self, username, password):
        self.login_attempts += 1
        self.username = username

        log_event("SSH", self.client_ip, "Login attempt",
                  f"username: {username}, password: {password}, attempt: {self.login_attempts}")

        # Send desktop alert
        alert_msg = f"SSH login attempt from {self.client_ip}\nUsername: {username}\nPassword: {password}"
        alert_queue.put(alert_msg)

        # Check if should ban
        if ip_ban_system.record_failed_attempt(self.client_ip, "SSH", self.max_attempts):
            return paramiko.AUTH_FAILED

        # Fake successful login on first attempt to engage attacker
        if self.login_attempts == 1:
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_shell_request(self, channel):
        return True


class SSHShell:
    def __init__(self, channel, client_ip, username):
        self.channel = channel
        self.client_ip = client_ip
        self.username = username
        self.prompt = f"{username}@honeypot:~$ "

    def start(self):
        self.send_message("Welcome to Ubuntu 22.04.1 LTS\r\n")
        self.send_message("Last login: Mon Dec  6 14:32:17 2023 from 192.168.1.100\r\n\r\n")

        while True:
            try:
                self.channel.send(self.prompt)
                data = self.channel.recv(1024)
                if not data:
                    break

                command = data.decode('utf-8', errors='ignore').strip()

                if not command:
                    continue

                log_event("SSH", self.client_ip, "Command executed", f"{self.username}: {command}")

                if command == 'exit':
                    self.send_message("logout\r\n")
                    break
                elif command == 'whoami':
                    self.send_message(f"{self.username}\r\n")
                elif command == 'pwd':
                    self.send_message("/home/user\r\n")
                elif command == 'ls':
                    self.send_message("file1.txt  file2.txt  documents/\r\n")
                elif command == 'id':
                    self.send_message(
                        f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\r\n")
                elif command == 'uname -a':
                    self.send_message(
                        "Linux honeypot 5.15.0-60-generic #66-Ubuntu SMP Fri Jan 20 14:29:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                else:
                    self.send_message(f"{command}: command not found\r\n")

            except:
                break

        self.channel.close()

    def send_message(self, message):
        try:
            self.channel.send(message)
        except:
            pass


def handle_ssh_connection(client_socket, client_ip):
    try:
        # Check if IP is banned
        if ip_ban_system.is_banned(client_ip):
            log_event("SSH", client_ip, "Blocked (banned IP)")
            client_socket.close()
            return

        log_event("SSH", client_ip, "New connection")

        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1"

        # Generate host key if not exists
        if not os.path.exists(HOST_KEY_PATH):
            key = paramiko.RSAKey.generate(2048)
            key.write_private_key_file(HOST_KEY_PATH)
        host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)

        transport.add_server_key(host_key)
        ssh_server = SSHServer(client_ip)
        transport.start_server(server=ssh_server)

        channel = transport.accept(10)
        if channel:
            # Start interactive shell
            shell = SSHShell(channel, client_ip, ssh_server.username or "unknown")
            shell.start()

        transport.close()

    except Exception as e:
        log_event("SSH", client_ip, f"Error: {str(e)}")
    finally:
        client_socket.close()


# ================= HTTP SERVER =================
def handle_http_connection(client_socket, client_ip):
    try:
        # Check if IP is banned
        if ip_ban_system.is_banned(client_ip):
            log_event("HTTP", client_ip, "Blocked (banned IP)")
            client_socket.close()
            return

        log_event("HTTP", client_ip, "Connection established")

        # Send HTTP response
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        response += "<html><body><h1>Welcome to Test Server</h1><p>Nothing to see here...</p></body></html>"
        client_socket.send(response.encode())

        # Receive and log request
        data = client_socket.recv(1024)
        if data:
            decoded_data = data.decode('utf-8', errors='ignore').strip()
            log_event("HTTP", client_ip, "Request received", decoded_data)

            # Check for suspicious patterns
            if any(pattern in decoded_data.lower() for pattern in ['admin', 'login', 'wp-', 'config', 'phpmyadmin']):
                log_event("HTTP", client_ip, "Admin access attempt", decoded_data)
                ip_ban_system.record_failed_attempt(client_ip, "HTTP")
            elif any(pattern in decoded_data.lower() for pattern in ['cmd=', 'exec=', 'system(', 'passthru(']):
                log_event("HTTP", client_ip, "Command injection attempt", decoded_data)
                ip_ban_system.record_failed_attempt(client_ip, "HTTP")

    except Exception as e:
        log_event("HTTP", client_ip, f"Error: {str(e)}")
    finally:
        client_socket.close()


# ================= FTP SERVER =================
def handle_ftp_connection(client_socket, client_ip):
    try:
        # Check if IP is banned
        if ip_ban_system.is_banned(client_ip):
            log_event("FTP", client_ip, "Blocked (banned IP)")
            client_socket.close()
            return

        log_event("FTP", client_ip, "Connection established")

        # Send FTP banner
        banner = "220 Welcome to FTP Server\r\n"
        client_socket.send(banner.encode())

        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            decoded_data = data.decode('utf-8', errors='ignore').strip()
            log_event("FTP", client_ip, "Command received", decoded_data)

            if decoded_data.upper().startswith("USER"):
                client_socket.send("331 Password required\r\n".encode())
            elif decoded_data.upper().startswith("PASS"):
                client_socket.send("530 Login incorrect\r\n".encode())
                # Record failed attempt
                if ip_ban_system.record_failed_attempt(client_ip, "FTP"):
                    break
            elif decoded_data.upper().startswith("QUIT"):
                client_socket.send("221 Goodbye\r\n".encode())
                break
            else:
                client_socket.send("500 Unknown command\r\n".encode())

    except Exception as e:
        log_event("FTP", client_ip, f"Error: {str(e)}")
    finally:
        client_socket.close()


# ================= TELNET SERVER =================
def handle_telnet_connection(client_socket, client_ip):
    try:
        # Check if banned
        if ip_ban_system.is_banned(client_ip):
            client_socket.close()
            return

        # Send login prompt
        client_socket.send(b"Welcome to Telnet Server\r\nlogin: ")
        username = client_socket.recv(1024).decode().strip()

        client_socket.send(b"password: ")
        password = client_socket.recv(1024).decode().strip()

        # Log attempt
        log_event("Telnet", client_ip, f"Login attempt: {username}/{password}")
        alert_queue.put(f"Telnet login from {client_ip}: {username}/{password}")

        # Check for ban
        if ip_ban_system.record_failed_attempt(client_ip, "Telnet"):
            client_socket.send(b"Access denied. IP blocked.\r\n")
        else:
            client_socket.send(b"Login incorrect\r\n")

    except Exception as e:
        log_event("Telnet", client_ip, f"Error: {str(e)}")
    finally:
        client_socket.close()


# ================= SERVICE LISTENER =================
def service_listener(port, service_name):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((HOST, port))
        sock.listen(100)
        log_event(service_name, "SYSTEM", f"Listener started on port {port}")

        while True:
            client_socket, address = sock.accept()
            client_ip = address[0]

            if service_name == "SSH":
                thread = threading.Thread(target=handle_ssh_connection, args=(client_socket, client_ip))
            elif service_name == "HTTP":
                thread = threading.Thread(target=handle_http_connection, args=(client_socket, client_ip))
            elif service_name == "FTP":
                thread = threading.Thread(target=handle_ftp_connection, args=(client_socket, client_ip))
            elif service_name == "Telnet":
                thread = threading.Thread(target=handle_telnet_connection, args=(client_socket, client_ip))

            thread.daemon = True
            thread.start()

    except Exception as e:
        log_event(service_name, "SYSTEM", f"Fatal error: {str(e)}")
    finally:
        sock.close()


# ================= MAIN EXECUTION =================
def main():
    print("🚀 Starting Multi-Port Honeypot with Interactive SSH Shell")
    print(f"📍 Listening on ports: {', '.join([f'{port} ({service})' for port, service in SERVICES.items()])}")
    print(f"📝 Log file: {LOG_FILE}")
    print(f"🚫 Banned IPs: {BANNED_IPS_FILE}")
    print(f"🔔 Desktop alerts: ENABLED")
    print(f"🎯 Auto-ban after: 3 failed attempts across all services")
    print("Press Ctrl+C to stop\n")

    # Show banned IPs on startup
    if ip_ban_system.banned_ips:
        print(f"📋 Currently banned IPs: {', '.join(ip_ban_system.banned_ips)}")

    # Start desktop alert system
    alert_thread = threading.Thread(target=show_desktop_alert)
    alert_thread.daemon = True
    alert_thread.start()

    # Start service listeners
    listener_threads = []
    for port, service_name in SERVICES.items():
        thread = threading.Thread(target=service_listener, args=(port, service_name))
        thread.daemon = True
        listener_threads.append(thread)
        thread.start()

    # Run API server in the main thread (not as daemon)
    print(f"[*] Starting API server on {API_HOST}:{API_PORT}")
    try:
        # Test if we can bind to the port
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_socket.bind((API_HOST, API_PORT))
        test_socket.close()

        # Start the Flask server
        app.run(host=API_HOST, port=API_PORT, debug=False, use_reloader=False, threaded=True)
    except socket.error as e:
        print(f"[-] Failed to start API server: {e}")
        print("[-] API endpoints will not be available")
        # Keep the main thread alive even if API fails
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down honeypot...")
            ip_ban_system.save_banned_ips()
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()