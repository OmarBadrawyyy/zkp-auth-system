import socket
import json
import hashlib
import time
import threading
from pathlib import Path
import logging
import ssl
import sys
import signal
import psutil

from Crypto.Util.number import bytes_to_long
from Crypto.Random import get_random_bytes

# ------------------- Configuration -------------------
# For demonstration purposes, using small primes.
# In production, use secure, large primes (e.g., 2048-bit primes).
P = 3557
g = 3
h = 5

# Path to server data file
server_data_file = Path("server/server_data.json")
user_records = []

# Initialize a lock for thread-safe access to user_records
user_records_lock = threading.Lock()

# ------------------- Logging Setup -------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("server.log")
    ]
)

# ------------------- JSON Storage -------------------
def load_user_records():
    global user_records
    if server_data_file.exists():
        try:
            with server_data_file.open("r") as f:
                user_records = json.load(f)
            logging.info(f"Server data loaded from {server_data_file}")
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing {server_data_file}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error loading {server_data_file}: {e}")
    else:
        logging.info("No existing server data found, starting fresh.")

def save_user_records():
    try:
        with server_data_file.open("w") as f:
            json.dump(user_records, f, indent=2)
        logging.info(f"Server data saved to {server_data_file}")
    except Exception as e:
        logging.error(f"Error writing {server_data_file}: {e}")

# ------------------- Helper Math -------------------
def compute_challenge(C, A):
    concat = f"{C:x}{A:x}".encode()
    hash_digest = hashlib.sha256(concat).digest()
    e = bytes_to_long(hash_digest) % (P - 1)
    return e

def pow_mod(base, exp):
    return pow(base, exp, P)

def mul_mod(a, b):
    return (a * b) % P

# Add input validation function
def validate_request_data(req):
    if not isinstance(req, dict):
        return False, "Invalid request format"
        
    operation = req.get("operation")
    if operation not in ["SIGN_UP", "LOGIN"]:
        return False, "Invalid operation"
        
    username = req.get("username")
    if not username or not isinstance(username, str) or len(username) < 3:
        return False, "Invalid username"
        
    return True, ""

# ------------------- Handle Connection -------------------
def handle_connection(conn, addr):
    """
    Handle incoming client connections
    - Processes sign-up and login requests
    - Verifies zero-knowledge proofs
    - Maintains thread safety for shared resources
    """
    start_time = time.time()
    operation = "unknown"
    try:
        data = conn.recv(4096)
        if not data:
            logging.warning(f"No data received from {addr}")
            return
            
        req = json.loads(data.decode().strip())
        
        # Validate request format
        valid, error_msg = validate_request_data(req)
        if not valid:
            conn.sendall(error_msg.encode() + b"\n")
            logging.warning(f"Invalid request from {addr}: {error_msg}")
            return
            
        operation = req.get("operation")
        username = req.get("username")

        if operation == "SIGN_UP":
            # Handle user registration
            commitment = req.get("commitment")
            if not commitment or not isinstance(commitment, str):
                conn.sendall(b"Invalid commitment value.\n")
                logging.warning(f"SIGN_UP with invalid commitment from {addr}")
                return

            with user_records_lock:
                # Prevent duplicate usernames
                if any(u["username"] == username for u in user_records):
                    conn.sendall(b"Username already exists.\n")
                    logging.info(f"SIGN_UP failed for '{username}': Username already exists.")
                    return

                # Rate limiting
                recent_signups = [u for u in user_records 
                                if time.time() - u.get("signup_time", 0) < 3600]
                if len(recent_signups) > 100:
                    conn.sendall(b"Too many sign-ups. Please try again later.\n")
                    logging.warning(f"Sign-up rate limit exceeded from {addr}")
                    return

                # Store commitment
                user_records.append({
                    "username": username,
                    "commitment": commitment,
                    "signup_time": time.time()
                })
                save_user_records()

        elif operation == "LOGIN":
            # Handle login verification
            A_hex = req.get("A")
            s1_hex = req.get("s1")
            s2_hex = req.get("s2")

            # Verify ZKP
            try:
                C_val = int(record["commitment"], 16)
                A_val = int(A_hex, 16)
                s1_val = int(s1_hex, 16)
                s2_val = int(s2_hex, 16)
                
                e_val = compute_challenge(C_val, A_val)

                # Verify the proof: g^s1 * h^s2 = A * C^e
                left = mul_mod(pow_mod(g, s1_val), pow_mod(h, s2_val))
                right = mul_mod(A_val, pow_mod(C_val, e_val))

                if left == right:
                    conn.sendall(b"Login successful (ZKP verified).\n")
                    logging.info(f"LOGIN successful for '{username}'.")
                else:
                    conn.sendall(b"Login failed.\n")
                    logging.info(f"LOGIN failed for '{username}': ZKP verification failed.")

            except ValueError:
                conn.sendall(b"Invalid numeric values in LOGIN data.\n")
                logging.warning(f"LOGIN failed for '{username}': Invalid numeric values.")
                return

    finally:
        # Record metrics and close connection
        end_time = time.time()
        log_server_metrics(operation, start_time, end_time)
        conn.close()

# ------------------- Signal Handling for Graceful Shutdown -------------------
def signal_handler(sig, frame):
    logging.info("Shutdown signal received. Shutting down the server gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ------------------- Start Server -------------------
def start_server():
    load_user_records()
    host = '0.0.0.0'
    port = 9998

    # Optional: Implement TLS for secure communication
    # Uncomment and configure the following lines if you have SSL certificates
    # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # context.load_cert_chain(certfile='path/to/cert.pem', keyfile='path/to/key.pem')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            s.listen()
            logging.info(f"Server listening on port {port}...")
            while True:
                conn, addr = s.accept()
                thread = threading.Thread(target=handle_connection, args=(conn, addr))
                thread.daemon = True  # Allows threads to exit when main thread exits
                thread.start()
        except Exception as e:
            logging.critical(f"Server encountered a fatal error: {e}")
        finally:
            s.close()

def get_performance_metrics():
    process = psutil.Process()
    return {
        "cpu_percent": process.cpu_percent(),
        "memory_usage": process.memory_info().rss / 1024 / 1024,
        "time": time.time()
    }

def log_server_metrics(operation, start_time, end_time):
    metrics = {
        "operation": operation,
        "processing_time": end_time - start_time,
        "performance": get_performance_metrics()
    }
    
    metrics_file = Path("server/server_metrics.json")
    try:
        if metrics_file.exists():
            with open(metrics_file, "r") as f:
                existing_metrics = json.load(f)
        else:
            existing_metrics = []
            
        existing_metrics.append(metrics)
        
        with open(metrics_file, "w") as f:
            json.dump(existing_metrics, f, indent=2)
    except Exception as e:
        logging.error(f"Error logging metrics: {e}")

if __name__ == "__main__":
    start_server() 