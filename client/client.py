import socket
import json
import hashlib
import time
import os
from pathlib import Path
import psutil

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Group parameters for Zero-Knowledge Proof
# Small primes used for demonstration - use larger primes in production
P = 3557  # Prime modulus
g = 3     # Generator 1
h = 5     # Generator 2 (for Pedersen commitment)

# File paths for storing encrypted user data and metrics
secrets_file = Path("client/client_secrets.json")

def get_encryption_key():
    """Generate or load AES key for encrypting local storage"""
    key_file = Path("client.key")
    if key_file.exists():
        with open(key_file, "rb") as f:
            return f.read()
    else:
        # Generate new 128-bit AES key
        key = get_random_bytes(16)
        with open(key_file, "wb") as f:
            f.write(key)
        return key

encryption_key = get_encryption_key()

# Verify the encryption key length
print(f"Encryption Key Length: {len(encryption_key)} bytes")

# ------------------- Encryption Helpers -------------------
def encrypt_data(data):
    cipher = AES.new(encryption_key, AES.MODE_CFB)
    ciphertext = cipher.iv + cipher.encrypt(data)
    return ciphertext

def decrypt_data(data):
    iv = data[:16]
    cipher = AES.new(encryption_key, AES.MODE_CFB, iv=iv)
    plaintext = cipher.decrypt(data[16:])
    return plaintext

# ------------------- File Handling -------------------
def load_secrets():
    if secrets_file.exists():
        try:
            with secrets_file.open("rb") as f:
                encrypted_data = f.read()
            decrypted_data = decrypt_data(encrypted_data)
            secrets = json.loads(decrypted_data.decode())
            print("Secrets loaded from file.")
            return secrets
        except Exception as e:
            print(f"Error loading secrets: {e}")
            return {}
    else:
        print("No secrets file found, starting fresh.")
        return {}

def save_secrets(secrets):
    try:
        data = json.dumps(secrets).encode()
        encrypted_data = encrypt_data(data)
        with secrets_file.open("wb") as f:
            f.write(encrypted_data)
    except Exception as e:
        print(f"Error saving secrets: {e}")

# ------------------- ZKP Operations -------------------
def compute_challenge(C, A):
    """
    Compute challenge for Schnorr protocol
    C: Commitment value
    A: First message in ZKP
    Returns: Challenge value e
    """
    concat = f"{C:x}{A:x}".encode()
    hash_digest = hashlib.sha256(concat).digest()
    e = bytes_to_long(hash_digest) % (P - 1)
    return e

def pow_mod(base, exp):
    return pow(base, exp, P)

def mul_mod(a, b):
    return (a * b) % P

def store_secret(secrets, username, pass_val, r_val):
    secrets[username] = {
        "password_val": pass_val,
        "r_val": f"{r_val:x}"
    }
    save_secrets(secrets)

def retrieve_secret(secrets, username, password):
    sd = secrets.get(username)
    if not sd:
        return None, None, False
    if sd["password_val"] != password:
        return None, None, False
    p_val = sd["password_val"]
    r_val = int(sd["r_val"], 16)
    return p_val, r_val, True

# ------------------- Client Operations -------------------
def sign_up(secrets, username, password):
    """
    Handle user registration using Pedersen commitment
    - Creates commitment to password without revealing it
    - Stores necessary values for later proof generation
    """
    pass_val = password
    r_val = bytes_to_long(get_random_bytes(2))
    # Generate Pedersen commitment: C = g^password * h^r
    comm1 = pow_mod(g, pass_val)
    comm2 = pow_mod(h, r_val)
    commitment = mul_mod(comm1, comm2)
    commitment_hex = f"{commitment:x}"

    # Send commitment to server
    start = time.time()
    req = {
        "operation": "SIGN_UP",
        "username": username,
        "commitment": commitment_hex
    }
    send_request(req)
    elapsed = time.time() - start
    print(f"[Client] SignUp round-trip took: {elapsed:.4f} seconds")

    # Store values needed for future proofs
    store_secret(secrets, username, password, r_val)

def login(secrets, username, password):
    """
    Handle login using Schnorr protocol for zero-knowledge proof
    - Proves knowledge of password without revealing it
    - Uses stored values from sign-up
    """
    start_time = time.time()
    network_start = time.time()
    
    # Retrieve stored values
    retrieved = retrieve_secret(secrets, username, password)
    if not retrieved[2]:
        print("Invalid username or password.")
        return
        
    p_val, r_val, _ = retrieved
    
    # Reconstruct commitment
    C1 = pow_mod(g, p_val)
    C2 = pow_mod(h, r_val)
    C_val = mul_mod(C1, C2)

    # Generate random values for ZKP
    alpha = bytes_to_long(get_random_bytes(2)) % (P - 2) + 1
    beta = bytes_to_long(get_random_bytes(2)) % (P - 2) + 1

    # Compute first message
    A1 = pow_mod(g, alpha)
    A2 = pow_mod(h, beta)
    A_val = mul_mod(A1, A2)

    # Get challenge from server
    e_val = compute_challenge(C_val, A_val)

    # Compute responses
    s1 = (e_val * p_val + alpha) % (P - 1)
    s2 = (e_val * r_val + beta) % (P - 1)

    # Send proof to server
    start = time.time()
    req = {
        "operation": "LOGIN",
        "username": username,
        "A": f"{A_val:x}",
        "s1": f"{s1:x}",
        "s2": f"{s2:x}"
    }
    send_request(req)
    elapsed = time.time() - start
    print(f"[Client] Login round-trip took: {elapsed:.4f} seconds")

    # Record performance metrics
    network_end = time.time()
    metrics = {
        "total_time": time.time() - start_time,
        "network_time": network_end - network_start,
        "cpu_usage": get_performance_metrics()["cpu_percent"],
        "memory_usage": get_performance_metrics()["memory_usage"]
    }
    log_metrics(metrics)

def send_request(data):
    try:
        with socket.create_connection(("127.0.0.1", 9998)) as sock:
            sock.sendall((json.dumps(data) + "\n").encode())
            response = sock.recv(4096).decode().strip()
            print(f"Server response: {response}")
    except Exception as e:
        print(f"Error connecting to server: {e}")

# Move these functions before the main() function
def validate_password(password):
    # For demo purposes we're using integers, but add some basic validation
    if not isinstance(password, int):
        return False, "Password must be an integer"
    if password < 0:
        return False, "Password must be positive"
    if password >= P:
        return False, "Password too large"
    return True, ""

def validate_username(username):
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters"
    if not username.isalnum():
        return False, "Username must be alphanumeric"
    return True, ""

def get_performance_metrics():
    process = psutil.Process()
    return {
        "cpu_percent": process.cpu_percent(),
        "memory_usage": process.memory_info().rss / 1024 / 1024,  # MB
        "time": time.time()
    }

def log_metrics(metrics):
    metrics_file = Path("client/client_metrics.json")
    try:
        if metrics_file.exists():
            with open(metrics_file, "r") as f:
                existing_metrics = json.load(f)
        else:
            existing_metrics = []
            
        existing_metrics.append(metrics)
        
        with open(metrics_file, "w") as f:
            json.dump(existing_metrics, f, indent=2)
            
        print("\nPerformance Metrics:")
        print(f"Total Time: {metrics['total_time']:.4f} seconds")
        print(f"Network Time: {metrics['network_time']:.4f} seconds")
        print(f"CPU Usage: {metrics['cpu_usage']:.2f}%")
        print(f"Memory Usage: {metrics['memory_usage']:.2f} MB")
    except Exception as e:
        print(f"Error logging metrics: {e}")

def main():
    secrets = load_secrets()

    while True:
        print("\nSelect an operation:")
        print("1 - Sign Up")
        print("2 - Login")
        print("3 - Exit")
        try:
            choice = int(input("Enter choice: ").strip())
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue

        if choice == 1:
            username = input("Enter username: ").strip()
            valid, msg = validate_username(username)
            if not valid:
                print(f"Invalid username: {msg}")
                continue
                
            try:
                password = int(input("Enter password (integer for demo): ").strip())
                valid, msg = validate_password(password)
                if not valid:
                    print(f"Invalid password: {msg}")
                    continue
            except ValueError:
                print("Password must be an integer.")
                continue
                
            sign_up(secrets, username, password)
            
        elif choice == 2:
            username = input("Enter username: ").strip()
            valid, msg = validate_username(username)
            if not valid:
                print(f"Invalid username: {msg}")
                continue
                
            try:
                password = int(input("Enter password (integer for demo): ").strip())
                valid, msg = validate_password(password)
                if not valid:
                    print(f"Invalid password: {msg}")
                    continue
            except ValueError:
                print("Password must be an integer.")
                continue
                
            login(secrets, username, password)
            
        elif choice == 3:
            print("Exiting client...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main() 