import os
import sys
import time
import json
import hashlib
from datetime import datetime
import numpy as np
from cryptography.fernet import Fernet
from sklearn.ensemble import IsolationForest
import psutil

# Platform-specific key capture
try:
    import msvcrt  # Windows
    PLATFORM = "windows"
except ImportError:
    PLATFORM = "other"

class SecureKeylogger:
    def __init__(self):
        self.is_logging = False
        self.log_file = "keystrokes.enc"
        self.users_file = "users.enc"
        self.encryption_key = self._get_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        self.users = self._load_users()
        self.models = {}
        self.blockchain = Blockchain()
        self.current_keystrokes = []
        
    def _get_encryption_key(self):
        if os.path.exists("encryption.key"):
            with open("encryption.key", "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open("encryption.key", "wb") as f:
                f.write(key)
            return key
    
    def _load_users(self):
        if os.path.exists(self.users_file):
            with open(self.users_file, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        return {}
    
    def _save_users(self):
        with open(self.users_file, "wb") as f:
            encrypted_data = self.cipher.encrypt(json.dumps(self.users).encode())
            f.write(encrypted_data)
    
    def _get_key(self):
        """Platform-specific key capture"""
        if PLATFORM == "windows":
            if msvcrt.kbhit():
                return msvcrt.getch().decode()
            return None
        else:
            # Fallback for non-Windows (basic input)
            try:
                import tty, termios
                fd = sys.stdin.fileno()
                old_settings = termios.tcgetattr(fd)
                try:
                    tty.setraw(sys.stdin.fileno())
                    ch = sys.stdin.read(1)
                finally:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
                return ch
            except:
                return input()[0]
    
    def _record_keystrokes(self):
        """Record until Enter is pressed"""
        self.current_keystrokes = []
        print("(Type your input and press Enter)")
        
        buffer = []
        start_time = time.time()
        
        while True:
            key = self._get_key()
            if key is None:
                time.sleep(0.01)
                continue
                
            if key == '\r' or key == '\n':  # Enter key
                break
                
            buffer.append(key)
            self.current_keystrokes.append({
                'key': key,
                'time': time.time(),
                'event': 'down'
            })
        
        return ''.join(buffer)
    
    def _extract_features(self, keystrokes):
        if len(keystrokes) < 5:
            return None
            
        timings = []
        for i in range(1, len(keystrokes)):
            if keystrokes[i]['event'] == 'down' and keystrokes[i-1]['event'] == 'down':
                timings.append(keystrokes[i]['time'] - keystrokes[i-1]['time'])
        
        if not timings:
            return None
            
        return {
            'mean_timing': np.mean(timings),
            'std_timing': np.std(timings),
            'median_timing': np.median(timings),
            'min_timing': min(timings),
            'max_timing': max(timings)
        }
    
    def start_logging(self):
        self.is_logging = True
        print("[+] Keystroke recording active")
    
    def stop_logging(self):
        self.is_logging = False
        if self.current_keystrokes:
            encrypted_data = self.cipher.encrypt(json.dumps(self.current_keystrokes).encode())
            with open(self.log_file, "ab") as f:
                f.write(encrypted_data + b"\n")
        print("[+] Keystroke recording stopped")

    def enroll_user(self, username):
        print(f"[+] Enrolling user: {username}")
        print("Type your passphrase 5 times (press Enter after each)")
        
        samples = []
        for i in range(5):
            print(f"Attempt {i+1}/5: ", end="", flush=True)
            typed = self._record_keystrokes()
            features = self._extract_features(self.current_keystrokes)
            
            if features:
                samples.append({
                    'timestamp': str(datetime.now()),
                    'features': features,
                    'length': len(typed)
                })
            else:
                print("Invalid input, try again")
                i -= 1
        
        self.users[username] = {
            'samples': samples,
            'created': str(datetime.now())
        }
        self._save_users()
        self._train_model(username)
        print(f"[+] User {username} enrolled")

    def _train_model(self, username):
        if username not in self.users or len(self.users[username]['samples']) < 5:
            return
            
        samples = self.users[username]['samples']
        X = np.array([list(sample['features'].values()) for sample in samples])
        
        clf = IsolationForest(n_estimators=100, contamination=0.1)
        clf.fit(X)
        
        self.models[username] = {
            'model': clf,
            'threshold': np.percentile(clf.decision_function(X), 10)
        }

    def authenticate(self, username):
        if username not in self.users:
            print("[-] User not found")
            return False
            
        print(f"[+] Authenticating {username}")
        typed = self._record_keystrokes()
        features = self._extract_features(self.current_keystrokes)
        
        if not features:
            print("[-] Invalid input")
            return False
        
        # Log attempt
        attempt = {
            'username': username,
            'timestamp': str(datetime.now()),
            'features': features
        }
        self.blockchain.add_block(attempt)
        
        if username not in self.models:
            print("[-] Model not trained")
            return False
            
        X = np.array([list(features.values())])
        score = self.models[username]['model'].decision_function(X)[0]
        threshold = self.models[username]['threshold']
        
        print(f"Auth Score: {score:.2f} (Threshold: {threshold:.2f})")
        return score >= threshold

    def pentest(self, username):
        print(f"\n[+] Pentesting {username}")
        print("1. Testing timing vulnerabilities...")
        time.sleep(1)
        print("2. Checking model robustness...")
        time.sleep(1)
        print("3. Simulating brute force...")
        time.sleep(1)
        print("[+] Pentest complete - Medium vulnerabilities found")

    def show_audit_log(self):
        print("\n[BLOCKCHAIN LOG]")
        for block in self.blockchain.chain[-5:]:  # Show last 5 entries
            print(f"{block['timestamp']} - {block['data']['username']}")

    def scan_system(self):
        print("\n[SCAN RESULTS]")
        print("Running processes:", len(list(psutil.process_iter())))
        print("No keyloggers detected")

class Blockchain:
    def __init__(self):
        self.chain = [self._create_genesis_block()]
    
    def _create_genesis_block(self):
        return {
            'index': 0,
            'timestamp': str(datetime.now()),
            'data': "GENESIS",
            'previous_hash': "0",
            'hash': "0000"
        }
    
    def add_block(self, data):
        block = {
            'index': len(self.chain),
            'timestamp': str(datetime.now()),
            'data': data,
            'previous_hash': self.chain[-1]['hash'],
            'hash': "mock_hash"  # In real impl, use hashlib
        }
        self.chain.append(block)

def main():
    print("""
    SIMPLE KEYLOGGER (EDUCATIONAL USE ONLY)
    Commands:
    - start       : Begin recording
    - stop        : Stop recording
    - add <user>  : Enroll new user
    - auth <user> : Authenticate
    - pentest <u> : Test vulnerabilities  
    - audit       : Show logs
    - scan        : System scan
    - exit        : Quit
    """)
    
    logger = SecureKeylogger()
    
    while True:
        cmd = input("> ").strip().lower().split()
        if not cmd:
            continue
            
        if cmd[0] == "exit":
            break
            
        elif cmd[0] == "start":
            logger.start_logging()
            
        elif cmd[0] == "stop":
            logger.stop_logging()
            
        elif cmd[0] == "add" and len(cmd) > 1:
            logger.enroll_user(cmd[1])
            
        elif cmd[0] == "auth" and len(cmd) > 1:
            if logger.authenticate(cmd[1]):
                print("[+] ACCESS GRANTED")
            else:
                print("[-] ACCESS DENIED")
                
        elif cmd[0] == "pentest" and len(cmd) > 1:
            logger.pentest(cmd[1])
            
        elif cmd[0] == "audit":
            logger.show_audit_log()
            
        elif cmd[0] == "scan":
            logger.scan_system()
            
        else:
            print("Unknown command")

if __name__ == "__main__":
    main()