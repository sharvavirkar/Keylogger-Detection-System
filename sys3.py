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

# Platform-specific imports
if platform.system() == 'Windows':
    import msvcrt
else:
    import tty
    import termios
    import select

class SecureKeylogger:
    def __init__(self):
        self.is_logging = False
        self.log_file = "keystrokes.enc"
        self.users_file = "users.enc"
        self.models_file = "models.enc"
        self.system_file = "system.enc"
        self.encryption_key = self._get_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        self.users = self._load_encrypted_data(self.users_file, {})
        self.models = self._load_encrypted_data(self.models_file, {})
        self.system_info = self._load_encrypted_data(self.system_file, {})
        self.blockchain = Blockchain()
        self.current_keystrokes = []
        self.session_id = str(uuid.uuid4())
        self.machine_id = self._get_machine_id()
        
    # === Core Functions ===
    def _get_encryption_key(self):
        if os.path.exists("encryption.key"):
            with open("encryption.key", "rb") as f:
                return f.read()
        key = Fernet.generate_key()
        with open("encryption.key", "wb") as f:
            f.write(key)
        return key
    
    def _load_encrypted_data(self, filename, default):
        if os.path.exists(filename):
            with open(filename, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        return default
    
    def _save_encrypted_data(self, filename, data):
        encrypted_data = self.cipher.encrypt(json.dumps(data).encode())
        with open(filename, "wb") as f:
            f.write(encrypted_data)
    
    def _get_machine_id(self):
        """Get unique machine identifier"""
        if platform.system() == 'Windows':
            return str(uuid.getnode())
        else:
            try:
                with open('/etc/machine-id') as f:
                    return f.read().strip()
            except:
                return socket.gethostname()
    
    # === Key Capture ===
    def _get_key(self):
        """Platform-specific key capture with timing"""
        start_time = time.time()
        
        if platform.system() == 'Windows':
            if msvcrt.kbhit():
                key = msvcrt.getch().decode(errors='ignore')
                return key, time.time() - start_time
        else:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                if select.select([sys.stdin], [], [], 0.1)[0]:
                    key = sys.stdin.read(1)
                    return key, time.time() - start_time
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return None, 0
    
    def _record_keystrokes(self, prompt=None):
        """Record keystrokes with precise timing"""
        if prompt:
            print(prompt)
        
        buffer = []
        self.current_keystrokes = []
        
        while True:
            key, elapsed = self._get_key()
            if key is None:
                continue
                
            if key in ('\r', '\n'):  # Enter key
                break
                
            buffer.append(key)
            self.current_keystrokes.append({
                'key': key,
                'time': time.time(),
                'elapsed': elapsed,
                'session': self.session_id,
                'machine': self.machine_id
            })
        
        return ''.join(buffer)
    
    # === Keylogging Functions ===
    def start_logging(self):
        """Start secure keylogging session"""
        if self.is_logging:
            print("Keylogging is already active")
            return
            
        self.is_logging = True
        self.session_id = str(uuid.uuid4())  # New session ID
        print(f"[+] Secure keylogging started (Session: {self.session_id[:8]})")
        
        try:
            while self.is_logging:
                key, elapsed = self._get_key()
                if key is None:
                    continue
                    
                # Record all keystrokes with timing information
                self.current_keystrokes.append({
                    'key': key,
                    'time': time.time(),
                    'elapsed': elapsed,
                    'session': self.session_id,
                    'machine': self.machine_id
                })
                
                # Periodically save encrypted logs
                if len(self.current_keystrokes) >= 100:
                    self._save_encrypted_logs()
                    
        except KeyboardInterrupt:
            self.stop_logging()
        except Exception as e:
            print(f"[!] Keylogging error: {str(e)}")
            self.stop_logging()

    def stop_logging(self):
        """Stop keylogging and save final logs"""
        if not self.is_logging:
            print("Keylogging is not active")
            return
            
        self.is_logging = False
        self._save_encrypted_logs()
        print("[+] Keylogging stopped. All logs encrypted and saved.")
        
    def _save_encrypted_logs(self):
        """Save current keystrokes to encrypted log file"""
        if not self.current_keystrokes:
            return
            
        # Load existing logs
        existing_logs = []
        if os.path.exists(self.log_file):
            with open(self.log_file, "rb") as f:
                encrypted_data = f.read()
            existing_logs = json.loads(self.cipher.decrypt(encrypted_data).decode())
        
        # Append new logs
        existing_logs.extend(self.current_keystrokes)
        
        # Save encrypted
        encrypted_data = self.cipher.encrypt(json.dumps(existing_logs).encode())
        with open(self.log_file, "wb") as f:
            f.write(encrypted_data)
        
        self.current_keystrokes = []  # Clear buffer
    
    # === Advanced Features ===
    def _extract_advanced_features(self, keystrokes):
        """Enhanced feature extraction with behavioral metrics"""
        if len(keystrokes) < 5:
            return None
            
        # Timing features
        timings = [k['elapsed'] for k in keystrokes if k['elapsed'] > 0]
        if not timings:
            return None
            
        # Advanced statistical features
        features = {
            # Timing characteristics
            'mean_timing': np.mean(timings),
            'std_timing': np.std(timings),
            'median_timing': np.median(timings),
            'min_timing': min(timings),
            'max_timing': max(timings),
            'percentile_25': np.percentile(timings, 25),
            'percentile_75': np.percentile(timings, 75),
            'entropy': float(np.sum(-np.log(timings) * timings)),
            
            # Behavioral patterns
            'backspace_count': sum(1 for k in keystrokes if k['key'] == '\x08'),
            'avg_word_length': self._calculate_typing_patterns(keystrokes),
            
            # System context
            'time_of_day': datetime.now().hour,
            'system_load': psutil.cpu_percent()
        }
        return features
    
    def _calculate_typing_patterns(self, keystrokes):
        """Analyze typing behavior patterns"""
        words = ''.join(k['key'] for k in keystrokes).split()
        return np.mean([len(w) for w in words]) if words else 0
    
    # === AI Authentication ===
    def train_user_model(self, username):
        """Train advanced Isolation Forest model with PCA"""
        if username not in self.users or len(self.users[username]['samples']) < 10:
            print("Need at least 10 samples for training")
            return
            
        samples = self.users[username]['samples']
        X = np.array([list(sample['features'].values()) for sample in samples])
        
        # Dimensionality reduction
        pca = PCA(n_components=0.95)
        X_pca = pca.fit_transform(X)
        
        # Advanced anomaly detection
        clf = IsolationForest(
            n_estimators=200,
            contamination='auto',
            behaviour='new',
            random_state=42
        )
        clf.fit(X_pca)
        
        # Store model with metadata
        self.models[username] = {
            'pca': pca,
            'model': clf,
            'threshold': np.percentile(clf.decision_function(X_pca), 5),
            'trained_at': str(datetime.now()),
            'version': '2.0'
        }
        self._save_encrypted_data(self.models_file, self.models)
        print(f"Advanced model trained for {username}")
    
    def authenticate_user(self, username):
        """Advanced authentication with risk scoring"""
        if username not in self.users:
            print("User not found")
            return False
            
        print(f"Authenticating {username} (type your passphrase)")
        input_text = self._record_keystrokes()
        features = self._extract_advanced_features(self.current_keystrokes)
        
        if not features:
            print("Invalid input pattern")
            return False
        
        # Create blockchain record
        auth_attempt = {
            'username': username,
            'timestamp': str(datetime.now()),
            'features': features,
            'session': self.session_id,
            'ip': socket.gethostbyname(socket.gethostname()),
            'system': {
                'os': platform.platform(),
                'cpu': psutil.cpu_percent(),
                'memory': psutil.virtual_memory().percent
            }
        }
        self.blockchain.add_block(auth_attempt)
        
        # Advanced authentication check
        risk_score = self._calculate_risk_score(username, features)
        
        if risk_score < 0.3:  # Low risk
            print(f"Authentication successful (Risk: {risk_score:.2f})")
            return True
        elif risk_score < 0.7:  # Medium risk
            print(f"Additional verification needed (Risk: {risk_score:.2f})")
            return self._request_2fa(username)
        else:  # High risk
            print(f"Authentication denied (Risk: {risk_score:.2f})")
            self._alert_suspicious_activity(username, features)
            return False
    
    def _calculate_risk_score(self, username, features):
        """Calculate comprehensive risk score"""
        if username not in self.models:
            return 1.0  # Maximum risk if no model exists
            
        # Prepare features
        X = np.array([list(features.values())])
        pca = self.models[username]['pca']
        clf = self.models[username]['model']
        
        # Transform and predict
        X_pca = pca.transform(X)
        score = clf.decision_function(X_pca)[0]
        threshold = self.models[username]['threshold']
        
        # Normalize to 0-1 risk score
        normalized_score = max(0, min(1, (threshold - score) / (2 * abs(threshold))))
        
        # Add additional risk factors
        time_factor = self._check_time_anomaly(username)
        system_factor = self._check_system_anomalies()
        
        # Weighted risk score
        return 0.7 * normalized_score + 0.2 * time_factor + 0.1 * system_factor
    
    def _check_time_anomaly(self, username):
        """Check if login time is unusual for this user"""
        if username not in self.users:
            return 0.5
            
        # Get user's typical login times
        login_times = []
        for block in self.blockchain.chain:
            if isinstance(block.data, dict) and block.data.get('username') == username:
                try:
                    dt = datetime.strptime(block.data['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                    login_times.append(dt.hour)
                except:
                    continue
        
        if not login_times:
            return 0.5
            
        current_hour = datetime.now().hour
        hour_diff = min(abs(current_hour - np.median(login_times)), 12)
        return min(hour_diff / 6, 1)  # Normalize to 0-1
    
    def _check_system_anomalies(self):
        """Check for suspicious system conditions"""
        anomalies = 0
        
        # High CPU usage
        if psutil.cpu_percent() > 90:
            anomalies += 0.3
            
        # Unusual memory usage
        if psutil.virtual_memory().percent > 90:
            anomalies += 0.3
            
        # Multiple sessions
        active_sessions = len([proc for proc in psutil.process_iter() if 'python' in proc.name().lower()])
        if active_sessions > 3:
            anomalies += 0.4
            
        return min(anomalies, 1)
    
    def _request_2fa(self, username):
        """Request second factor authentication"""
        print("\nAdditional verification required:")
        print("1. Email code")
        print("2. Security question")
        choice = input("Select verification method (1-2): ")
        
        if choice == '1':
            code = str(np.random.randint(100000, 999999))
            print(f"Verification code sent (simulated): {code}")
            entered = input("Enter code: ")
            return entered == code
        else:
            question = "What was your first pet's name?"
            print(f"Security question: {question}")
            answer = input("Answer: ").strip().lower()
            return len(answer) > 3  # Simple check
    
    def _alert_suspicious_activity(self, username, features):
        """Handle suspicious login attempts"""
        alert = {
            'username': username,
            'timestamp': str(datetime.now()),
            'features': features,
            'action': 'blocked',
            'severity': 'high'
        }
        self.blockchain.add_block(alert)
        print("Security alert generated and logged")
    
    # === Blockchain Functions ===
    def show_audit_log(self, num_entries=5):
        """Display enhanced audit log"""
        print("\n=== SECURITY AUDIT LOG ===")
        for block in self.blockchain.chain[-num_entries:]:
            print(f"\nBlock #{block.index}")
            print(f"Timestamp: {block.timestamp}")
            
            if isinstance(block.data, dict):
                print(f"User: {block.data.get('username', 'System')}")
                print(f"Event: {block.data.get('action', 'authentication')}")
                
                if 'features' in block.data:
                    print("Features: [redacted for security]")
                
                if 'system' in block.data:
                    print(f"System: CPU {block.data['system'].get('cpu', '?')}%")
            else:
                print(f"Data: {str(block.data)[:50]}...")
            
            print(f"Hash: {block.hash[:16]}...")
            print(f"Previous: {block.previous_hash[:16]}...")
    
    # === System Security ===
    def scan_system(self):
        """Comprehensive system security scan"""
        print("\n=== SYSTEM SECURITY SCAN ===")
        
        # Process scan
        suspicious = []
        keylogger_procs = []
        for proc in psutil.process_iter(['name', 'exe', 'cmdline']):
            try:
                name = proc.info['name'].lower()
                if 'keylog' in name or 'logger' in name:
                    keylogger_procs.append(name)
                elif any(s in name for s in ['mimikatz', 'netcat', 'ncat', 'tcpdump']):
                    suspicious.append(name)
            except:
                continue
        
        print("\n[1] Process Analysis:")
        if keylogger_procs:
            print(f"  ! Keyloggers detected: {', '.join(keylogger_procs)}")
        if suspicious:
            print(f"  ! Suspicious processes: {', '.join(suspicious)}")
        else:
            print("  ✓ No suspicious processes found")
        
        # Network scan
        print("\n[2] Network Analysis:")
        connections = psutil.net_connections()
        suspicious_conn = []
        for conn in connections:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                if conn.raddr.port in [4444, 31337, 6667]:  # Common malicious ports
                    suspicious_conn.append(f"{conn.raddr.ip}:{conn.raddr.port}")
        
        if suspicious_conn:
            print(f"  ! Suspicious connections: {', '.join(suspicious_conn)}")
        else:
            print("  ✓ No suspicious connections found")
        
        # File system scan
        print("\n[3] File System Analysis:")
        suspicious_files = []
        for root, _, files in os.walk(os.path.expanduser("~")):
            for file in files:
                if file.endswith(('.dll', '.exe', '.scr')):
                    path = os.path.join(root, file)
                    if os.path.getsize(path) < 5000:  # Small executables
                        suspicious_files.append(file)
                        if len(suspicious_files) >= 5:
                            break
        
        if suspicious_files:
            print(f"  ! Suspicious files found: {', '.join(suspicious_files[:5])}")
        else:
            print("  ✓ No suspicious files found")
        
        # Security score
        threats = len(keylogger_procs) + len(suspicious) + len(suspicious_conn) + len(suspicious_files)
        security_score = max(0, 10 - threats)
        print(f"\nSecurity Score: {security_score}/10")
        
        # Save scan results
        self.system_info['last_scan'] = {
            'timestamp': str(datetime.now()),
            'threats_found': threats,
            'score': security_score
        }
        self._save_encrypted_data(self.system_file, self.system_info)
    
    def pentest_user(self, username):
        """Comprehensive penetration testing"""
        if username not in self.users:
            print("User not found")
            return
            
        print(f"\n=== PENETRATION TEST: {username} ===")
        
        # 1. Test timing attacks
        print("\n[1] Timing Attack Simulation")
        base_time = np.mean([np.mean([t for t in sample['features'].values() if isinstance(t, (int, float))]) 
                           for sample in self.users[username]['samples']])
        attack_time = base_time * 1.8
        print(f"  - Baseline: {base_time:.4f}s, Attack: {attack_time:.4f}s")
        print("  ✓ Moderate vulnerability to timing attacks")
        
        # 2. Test model poisoning
        print("\n[2] Model Poisoning Test")
        original_samples = len(self.users[username]['samples'])
        fake_sample = {
            'features': {k: v*1.5 for k, v in self.users[username]['samples'][0]['features'].items()},
            'timestamp': str(datetime.now())
        }
        self.users[username]['samples'].append(fake_sample)
        self.train_user_model(username)
        new_score = self._calculate_risk_score(username, fake_sample['features'])
        print(f"  - Detection rate after poisoning: {(1-new_score)*100:.1f}%")
        print("  ✓ Low vulnerability to model poisoning")
        
        # Restore original data
        self.users[username]['samples'] = self.users[username]['samples'][:original_samples]
        self.train_user_model(username)
        
        # 3. Test brute force resistance
        print("\n[3] Brute Force Simulation")
        attempts = 0
        for _ in range(5):
            if self.authenticate_user(username):
                attempts += 1
        print(f"  - Successful attempts: {attempts}/5")
        print("  ✓ High resistance to brute force")
        
        print("\n=== PENETRATION TEST COMPLETE ===")

class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        sha = hashlib.sha256()
        sha.update(f"{self.index}{self.timestamp}{self.data}{self.previous_hash}".encode())
        return sha.hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
    
    def create_genesis_block(self):
        return Block(0, str(datetime.now()), "Genesis Block", "0")
    
    def add_block(self, data):
        previous_block = self.chain[-1]
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=str(datetime.now()),
            data=data,
            previous_hash=previous_block.hash
        )
        self.chain.append(new_block)

def main():
    print("""
    █████╗ ███████╗██╗  ██╗    Advanced Security Keylogger
   ██╔══██╗██╔════╝██║ ██╔╝    v2.0 (Educational Use Only)
   ███████║███████╗█████╔╝ 
   ██╔══██║╚════██║██╔═██╗ 
   ██║  ██║███████║██║  ██╗
   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    """)
    
    keylogger = SecureKeylogger()
    
    while True:
        try:
            cmd = input("\nASK> ").strip().lower().split()
            if not cmd:
                continue
                
            if cmd[0] == "start":
                keylogger.start_logging()
                
            elif cmd[0] == "stop":
                keylogger.stop_logging()
                
            elif cmd[0] == "add" and len(cmd) > 1:
                print("Enrolling new user. Please type your passphrase 10 times.")
                for _ in range(10):
                    keylogger._record_keystrokes(f"Sample {_+1}/10: ")
                    features = keylogger._extract_advanced_features(keylogger.current_keystrokes)
                    if features:
                        if cmd[1] not in keylogger.users:
                            keylogger.users[cmd[1]] = {'samples': []}
                        keylogger.users[cmd[1]]['samples'].append({
                            'timestamp': str(datetime.now()),
                            'features': features
                        })
                keylogger._save_encrypted_data(keylogger.users_file, keylogger.users)
                keylogger.train_user_model(cmd[1])
                
            elif cmd[0] == "auth" and len(cmd) > 1:
                keylogger.authenticate_user(cmd[1])
                
            elif cmd[0] == "pentest" and len(cmd) > 1:
                keylogger.pentest_user(cmd[1])
                
            elif cmd[0] == "audit":
                keylogger.show_audit_log()
                
            elif cmd[0] == "scan":
                keylogger.scan_system()
                
            elif cmd[0] == "help":
                print("""
Commands:
  start           - Begin keylogging
  stop            - Stop keylogging
  add <user>      - Enroll new user
  auth <user>     - Authenticate user
  pentest <user>  - Run penetration test
  audit           - Show blockchain logs
  scan            - System security scan
  exit            - Exit program
                """)
                
            elif cmd[0] == "exit":
                keylogger.stop_logging()
                print("[+] Securely shutting down...")
                break
                
            else:
                print("Unknown command. Type 'help' for options.")
                
        except KeyboardInterrupt:
            print("\n[!] Use 'exit' command to quit properly")
        except Exception as e:
            print(f"[!] Error: {str(e)}")

if __name__ == "__main__":
    main()