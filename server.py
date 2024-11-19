# server.py
import socket
import hashlib
import secrets
from typing import Tuple

CLIENT_IP = ''

# Server configuration
HOST = '127.0.0.1'
PORT = 65432
M = 2**128  # For 128-bit key size

# Store registered users (in-memory dictionary)
registered_users = {}

def generate_hash(data: str) -> str:
    """Generate SHA-256 hash of input data."""
    return hashlib.sha256(data.encode()).hexdigest()

def register_user(user_id: str, password: str) -> None:
    """Register a new user with hash-based identity and password."""
    hid = generate_hash(user_id)
    hpsw = generate_hash(user_id + password)
    registered_users[hid] = hpsw
    print(f"Registered user {user_id} with HID: {hid}")

def verify_login(user_id: str, password: str) -> bool:
    """Verify user login credentials."""
    hid = generate_hash(user_id)
    hpsw = generate_hash(user_id + password)
    return hid in registered_users and registered_users[hid] == hpsw

def generate_random_numbers() -> Tuple[int, int]:
    """Generate two random numbers for key exchange."""
    while True:
        N1 = secrets.randbits(128)
        N2 = secrets.randbits(128)
        if N1 != 0 and N2 != 0:
            print(f"\nServer generated N1: {N1}, N2: {N2}")  
            return N1, N2

def extract_user_random(FR_U: int, N1: int, N2: int) -> int:
    """Extract user's random number from final result."""
    Res_S = FR_U - (N1 + N2)
    N_U = (Res_S // (N1 * N2)) - 1
    print(f"Server extracted N_U: {N_U}")  
    return N_U

def calculate_server_final_result(N_S: int, N1: int, N2: int) -> int:
    """Calculate server's final result for key exchange."""
    S = (N_S * N1) + N1
    FR_S = (S * N2) + N1 + N2
    return FR_S

def calculate_session_key(N_U: int, N_S: int) -> int:
    """Calculate final session key."""
    return (N_U ^ N_S) % M

def calculate_hmac(CLIENT_IP: str, random_num: int, session_key: int) -> str:
    """Calculate HMAC using SHA-256."""
    data = f"{CLIENT_IP}||{random_num}"
    key = session_key.to_bytes(16, byteorder='big')
    print(f"\n\nInput for Server calculated Client HMAC: IP = {CLIENT_IP}, Random Number N_U = {random_num}, Session Key = {session_key}, Data = {data}")  
    return hashlib.sha256(data.encode() + key).hexdigest()


def start_server():
    """Main server function."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        print(f"\nServer listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = server.accept()
            CLIENT_IP = addr
            with conn:
                print(f"Connected by {addr}")
                try:
                    # Receive login credentials
                    user_id_len = int.from_bytes(conn.recv(4), byteorder='big')
                    user_id = conn.recv(user_id_len).decode()
                    
                    pwd_len = int.from_bytes(conn.recv(4), byteorder='big')
                    password = conn.recv(pwd_len).decode()
                    
                    print(f"\nLogin attempt - User ID: {user_id}")  
                    
                    if verify_login(user_id, password):
                        conn.sendall(b"LOGIN_SUCCESS")
                        print("\n-------------Login successful!-------------") 
                        
                        # Generate and send random numbers
                        N1, N2 = generate_random_numbers()
                        conn.sendall(f"{N1},{N2}".encode())
                        
                        # Receive client's final result
                        FR_U = int(conn.recv(1024).decode())
                        print(f"\nServer received FR_U: {FR_U}")  
                        
                        # Extract user's random number
                        N_U = extract_user_random(FR_U, N1, N2)
                        
                        # Generate server's random number and final result
                        N_S = secrets.randbits(128)
                        print(f"\nServer generated N_S: {N_S}")  
                        FR_S = calculate_server_final_result(N_S, N1, N2)
                        conn.sendall(str(FR_S).encode())
                        print(f"Server calculated FR_S: {FR_S}")  
                        
                        # Calculate session key
                        session_key = calculate_session_key(N_U, N_S)
                        print(f"\n\nServer session key: {session_key}")  
                        
                        # Calculate and verify HMAC
                        server_hmac = calculate_hmac(HOST, N_U, session_key)
                        print(f"Server calculated client HMAC: {server_hmac}")  
                        client_hmac = conn.recv(1024).decode()
                        print(f"Server received client HMAC: {client_hmac}")  
                        
                        if client_hmac == server_hmac:
                            conn.sendall(b"AUTH_SUCCESS")
                            print(f"\n\n-------------Authentication successful for {user_id}!------------")  
                        else:
                            conn.sendall(b"AUTH_FAILED")
                            print(f"\n\n-------------Authentication failed for {user_id}!-----------------")  
                    else:
                        conn.sendall(b"LOGIN_FAILED")
                        print(f"\n--------------Login failed for {user_id}!--------------")  
                        
                except Exception as e:
                    print(f"Error: {e}")
                    conn.sendall(b"ERROR")

if __name__ == "__main__":
    # Register a test user
    register_user("user1", "password1")
    register_user("user2", "password2")
    register_user("user3", "password3")
    start_server()
