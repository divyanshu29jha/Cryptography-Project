# client.py
import socket
import hashlib
import secrets
import tkinter as tk
from tkinter import messagebox

# Client configuration
HOST = '127.0.0.1'
PORT = 65432
M = 2**128  # For 128-bit key size

def generate_hash(data: str) -> str:
    """Generate SHA-256 hash of input data."""
    return hashlib.sha256(data.encode()).hexdigest()

def calculate_client_final_result(N_U: int, N1: int, N2: int) -> int:
    """Calculate client's final result for key exchange."""
    Res_U = (N_U * N1) + N1
    FR_U = (Res_U * N2) + N1 + N2
    return FR_U

def extract_server_random(FR_S: int, N1: int, N2: int) -> int:
    """Extract server's random number from final result."""
    Res_S = FR_S - (N1 + N2)
    N_S = (Res_S // (N1 * N2)) - 1
    print(f"Client extracted N_S: {N_S}")  
    return N_S

def calculate_session_key(N_U: int, N_S: int) -> int:
    """Calculate final session key."""
    return (N_U ^ N_S) % M

def calculate_hmac(ip_address: str, random_num: int, session_key: int) -> str:
    """Calculate HMAC using SHA-256."""
    data = f"{ip_address}||{random_num}"
    key = session_key.to_bytes(16, byteorder='big')
    print(f"\n\nInput for Client generated HMAC: IP = {ip_address}, Random Number N_U = {random_num}, Session Key = {session_key}, Data = {data}")  
    return hashlib.sha256(data.encode() + key).hexdigest()

# Tkinter GUI Client
class ClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Client Key Exchange and Authentication")

        # User ID
        tk.Label(root, text="User ID:").grid(row=0, column=0, padx=5, pady=5)
        self.user_id_entry = tk.Entry(root)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5)

        # Password
        tk.Label(root, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        # Connect Button
        self.connect_btn = tk.Button(root, text="Connect and Authenticate", command=self.authenticate)
        self.connect_btn.grid(row=2, column=0, columnspan=2, pady=10)

        # Status Label
        self.status_label = tk.Label(root, text="", fg="blue")
        self.status_label.grid(row=3, column=0, columnspan=2, pady=5)

    def authenticate(self):
        user_id = self.user_id_entry.get()
        password = self.password_entry.get()

        if not user_id or not password:
            messagebox.showerror("Input Error", "Please enter both User ID and Password.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect((HOST, PORT))
                print(f"Connected to server at {HOST}:{PORT}")
                self.status_label.config(text="Connected to server.")
                
                # Send login credentials
                client.sendall(len(user_id).to_bytes(4, byteorder='big'))
                client.sendall(user_id.encode())
                client.sendall(len(password).to_bytes(4, byteorder='big'))
                client.sendall(password.encode())
                
                # Receive login response
                response = client.recv(1024).decode()
                if response == "LOGIN_SUCCESS":
                    print("\n------------Login successful! Starting key exchange...--------------")
                    self.status_label.config(text="Login successful. Starting key exchange...")

                    # Receive random numbers from server
                    N1, N2 = map(int, client.recv(1024).decode().split(','))
                    print(f"\nClient received N1: {N1}, N2: {N2}")  
                    
                    # Generate client's random number and calculate final result
                    N_U = secrets.randbits(128)
                    print(f"\nClient generated N_U: {N_U}")  
                    FR_U = calculate_client_final_result(N_U, N1, N2)
                    print(f"Client calculated FR_U: {FR_U}")  
                    client.sendall(str(FR_U).encode())
                    
                    # Receive server's final result
                    FR_S = int(client.recv(1024).decode())
                    print(f"\nClient received FR_S: {FR_S}") 
                    
                    # Extract server's random number and calculate session key
                    N_S = extract_server_random(FR_S, N1, N2)
                    session_key = calculate_session_key(N_U, N_S)
                    print(f"\n\nClient session key: {session_key}")  

                    # Calculate and send HMAC
                    client_hmac = calculate_hmac(HOST, N_U, session_key)
                    print(f"Client generated HMAC: {client_hmac}")  
                    client.sendall(client_hmac.encode())
                    
                    # Receive authentication result
                    auth_result = client.recv(1024).decode()
                    
                    if auth_result == "AUTH_SUCCESS":
                        print("\n\n------------Authentication successful!--------------")
                        print(f"Established session key: {session_key}")
                        self.status_label.config(text="Authentication successful!")
                        messagebox.showinfo("Success", f"Authentication successful! Session key established: {session_key}")
                    else:
                        print("Authentication failed!")
                        self.status_label.config(text="Authentication failed.")
                        messagebox.showerror("Failure", "Authentication failed!")
                else:
                    print("Login failed! Invalid credentials.")
                    self.status_label.config(text="Login failed.")
                    messagebox.showerror("Login Failed", "Invalid credentials.")
        except Exception as e:
            print(f"Unexpected response: {response}")
            self.status_label.config(text="Connection error.")
            messagebox.showerror("Error", f"An error occurred: {e}")

# Run the Client GUI
root = tk.Tk()
app = ClientApp(root)
root.mainloop()
