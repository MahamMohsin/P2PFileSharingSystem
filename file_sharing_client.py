from tkinter import *
from tkinter import filedialog, simpledialog, messagebox
import socket
import os
import threading
import requests
from flask import Flask, request, send_file, jsonify
import random
from functools import wraps

# Import custom modules
from encryption_module import FileEncryption, get_encryptor
from error_handler import ErrorHandler, get_user_friendly_message, NetworkError, FileError, AuthenticationError
from retry_mechanism import RetryMechanism, RetryConfig, retry_operation

# ========= CONFIG ==========
DISCOVERY_SERVER = "127.0.0.1"
DISCOVERY_PORT = 5000
PEER_PORT = random.randint(8001, 8999)

FILES_DIR = "shared_files"
os.makedirs(FILES_DIR, exist_ok=True)

DOWNLOAD_DIR = "downloaded"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

ENCRYPTED_DIR = "encrypted_files"
os.makedirs(ENCRYPTED_DIR, exist_ok=True)

AUTH_TOKEN = "secret123"  # Default token (changeable)

# GLOBAL ENCRYPTION PASSWORD - set by user
ENCRYPTION_PASSWORD = None
encryptor = None

app = Flask(__name__)
error_handler = ErrorHandler()
retry_config = RetryConfig(max_attempts=3, base_delay=1, backoff_factor=2)
retry_mechanism = RetryMechanism(retry_config)

# ========== AUTH DECORATOR ==========
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            token = request.headers.get('Authorization')
            if token != AUTH_TOKEN:
                error_handler.log_warning(f"Unauthorized access attempt from {request.remote_addr}")
                return jsonify({"error": "Unauthorized"}), 401
            return f(*args, **kwargs)
        except Exception as e:
            error_handler.log_error("AUTH ERROR", "Authentication check failed", e)
            return jsonify({"error": "Authentication error"}), 500
    return decorated

# ========== FLASK PEER ENDPOINTS ==========
@app.route('/files', methods=['GET'])
@require_auth
def list_files():
    try:
        files = os.listdir(FILES_DIR)
        error_handler.log_info(f"File list requested: {len(files)} files")
        return {"files": files}
    except Exception as e:
        error_handler.log_error("FILE LIST ERROR", "Failed to list files", e)
        return {"error": "Failed to list files"}, 500

@app.route('/upload', methods=['POST'])
@require_auth
def upload_file():
    try:
        if 'file' not in request.files:
            return {"error": "No file provided"}, 400
        
        file = request.files['file']
        filename = file.filename
        
        # Check if file is encrypted
        is_encrypted = request.form.get('encrypted', 'false').lower() == 'true'
        
        # Save file
        file_path = os.path.join(FILES_DIR, filename)
        file.save(file_path)
        
        if is_encrypted:
            error_handler.log_info(f"Encrypted file '{filename}' uploaded successfully")
        else:
            error_handler.log_info(f"File '{filename}' uploaded successfully")
        
        return {"message": f"File '{filename}' uploaded successfully"}
    
    except Exception as e:
        error_handler.log_error("UPLOAD ERROR", f"Failed to upload file", e)
        return {"error": get_user_friendly_message(e)}, 500

@app.route('/download/<filename>', methods=['GET'])
@require_auth
def download_file(filename):
    try:
        file_path = os.path.join(FILES_DIR, filename)
        
        if not os.path.exists(file_path):
            error_handler.log_warning(f"File not found: {filename}")
            return {"error": "File not found"}, 404
        
        error_handler.log_info(f"File '{filename}' downloaded by peer")
        return send_file(file_path, as_attachment=True)
    
    except Exception as e:
        error_handler.log_error("DOWNLOAD ERROR", f"Failed to serve file {filename}", e)
        return {"error": get_user_friendly_message(e)}, 500

# ========== NETWORKING LOGIC WITH ERROR HANDLING ==========
def start_flask_server():
    try:
        error_handler.log_info(f"Starting Flask server on port {PEER_PORT}")
        app.run(host='0.0.0.0', port=PEER_PORT, debug=False)
    except Exception as e:
        error_handler.log_error("SERVER ERROR", "Failed to start Flask server", e)
        log_message("[ERROR] Failed to start peer server")

def request_file_from_peer_base(peer, filename, token, decrypt_password=None):
    """Base function for downloading from peer (used with retry)"""
    url = f"http://{peer}/download/{filename}"
    headers = {"Authorization": token}
    
    response = requests.get(url, headers=headers, stream=True, timeout=30)
    
    if response.status_code == 200:
        file_path = os.path.join(DOWNLOAD_DIR, filename)
        
        # Download file
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
        
        # Decrypt if it's an encrypted file and password provided
        if filename.endswith('.encrypted') and decrypt_password:
            try:
                temp_encryptor = get_encryptor(decrypt_password)
                decrypted_path = os.path.join(DOWNLOAD_DIR, filename[:-10])
                temp_encryptor.decrypt_file(file_path, decrypted_path)
                os.remove(file_path)  # Remove encrypted version
                error_handler.log_info(f"File decrypted: {filename}")
                return decrypted_path
            except Exception as e:
                error_handler.log_error("DECRYPTION ERROR", f"Failed to decrypt {filename}", e)
                log_message(f"[DECRYPTION ERROR] Wrong password or corrupted file")
                raise Exception("Decryption failed. Please verify your password matches the encryption password.")
        
        return file_path
    else:
        error_msg = response.json().get('error', 'Unknown error')
        raise Exception(f"Download failed: {error_msg}")

def request_file_from_peer(peer, filename, token, decrypt_password=None):
    """Download file with retry mechanism"""
    def on_retry(attempt, error, delay):
        log_message(f"[RETRY {attempt}] Download failed. Retrying in {delay}s...")
    
    success, result, error = retry_operation(
        request_file_from_peer_base,
        peer, filename, token, decrypt_password,
        max_attempts=3,
        on_retry=on_retry
    )
    
    if success:
        log_message(f"[DOWNLOADED] '{filename}' from {peer} to '{DOWNLOAD_DIR}' folder")
    else:
        error_msg = get_user_friendly_message(error)
        log_message(f"[ERROR] {error_msg}")
        messagebox.showerror("Download Failed", error_msg)

def register_peer_base():
    """Base function for peer registration (used with retry)"""
    peer_address = f"127.0.0.1:{PEER_PORT}"
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((DISCOVERY_SERVER, DISCOVERY_PORT))
    s.send(f"REGISTER {peer_address}".encode())
    response = s.recv(1024).decode()
    s.close()
    
    if response != "Registered":
        raise Exception(f"Registration failed: {response}")
    
    return response

def register_peer():
    """Register peer with retry mechanism"""
    def on_retry(attempt, error, delay):
        log_message(f"[RETRY {attempt}] Registration failed. Retrying in {delay}s...")
    
    success, result, error = retry_operation(
        register_peer_base,
        max_attempts=3,
        on_retry=on_retry
    )
    
    if success:
        log_message(f"[SUCCESS] Registered with discovery server")
    else:
        error_msg = get_user_friendly_message(error)
        log_message(f"[ERROR] {error_msg}")
        messagebox.showwarning("Registration Failed", 
            f"{error_msg}\n\nPlease ensure the discovery server is running.")

def get_peer_list():
    """Get list of active peers with error handling"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((DISCOVERY_SERVER, DISCOVERY_PORT))
        s.send(b"GET_PEERS")
        peers = s.recv(4096).decode()
        s.close()
        
        peers = eval(peers) if peers else []

        # Filter out the current peer
        self_address = f"127.0.0.1:{PEER_PORT}"
        peers = [peer for peer in peers if peer != self_address]

        # Validate active peers
        valid_peers = []
        for peer in peers:
            try:
                response = requests.get(
                    f"http://{peer}/files", 
                    headers={"Authorization": AUTH_TOKEN}, 
                    timeout=2
                )
                if response.status_code == 200:
                    valid_peers.append(peer)
            except:
                continue

        if valid_peers:
            log_message("[RETRIEVED] Active Peers:\n" + "\n".join(valid_peers))
        else:
            log_message("[INFO] No active peers found.")
        
        return valid_peers

    except Exception as e:
        error_handler.log_error("PEER LIST ERROR", "Failed to retrieve peer list", e)
        error_msg = get_user_friendly_message(e)
        log_message(f"[ERROR] {error_msg}")
        return []

# ========== FILE ACTIONS WITH ENCRYPTION & RETRY ==========
def upload_files():
    """Upload file with encryption and retry"""
    global encryptor
    
    try:
        # Request token
        token = simpledialog.askstring("Enter Token", "Enter your authorization token:")
        if not token:
            return

        # Ask if user wants encryption
        encrypt_file = messagebox.askyesno(
            "Encryption", 
            "Do you want to encrypt this file before uploading?"
        )

        # If encryption is chosen, ask for password
        encryption_password = None
        if encrypt_file:
            encryption_password = simpledialog.askstring(
                "Encryption Password", 
                "Enter encryption password (remember this for decryption!):",
                show='*'
            )
            if not encryption_password:
                messagebox.showwarning("Password Required", "Encryption password is required for encryption!")
                return
            
            # Confirm password
            confirm_password = simpledialog.askstring(
                "Confirm Password", 
                "Confirm encryption password:",
                show='*'
            )
            if encryption_password != confirm_password:
                messagebox.showerror("Password Mismatch", "Passwords do not match!")
                return

        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        file_name = os.path.basename(file_path)
        
        # Encryption process
        upload_path = file_path
        if encrypt_file:
            try:
                temp_encryptor = get_encryptor(encryption_password)
                encrypted_path = os.path.join(ENCRYPTED_DIR, file_name + '.encrypted')
                temp_encryptor.encrypt_file(file_path, encrypted_path)
                upload_path = encrypted_path
                file_name = file_name + '.encrypted'
                log_message(f"[ENCRYPTED] File encrypted successfully")
            except Exception as e:
                error_handler.log_error("ENCRYPTION ERROR", "Failed to encrypt file", e)
                messagebox.showerror("Encryption Failed", get_user_friendly_message(e))
                return

        # Upload with retry
        def upload_attempt():
            files = {'file': open(upload_path, 'rb')}
            headers = {'Authorization': token}
            data = {'encrypted': 'true' if encrypt_file else 'false'}
            
            try:
                response = requests.post(
                    f"http://127.0.0.1:{PEER_PORT}/upload", 
                    files=files, 
                    headers=headers,
                    data=data,
                    timeout=30
                )
                files['file'].close()
                
                if response.status_code != 200:
                    raise Exception(response.json().get('error', 'Upload failed'))
                
                return response
            finally:
                if 'file' in files and not files['file'].closed:
                    files['file'].close()

        def on_retry(attempt, error, delay):
            log_message(f"[RETRY {attempt}] Upload failed. Retrying in {delay}s...")

        success, result, error = retry_operation(
            upload_attempt,
            max_attempts=3,
            on_retry=on_retry
        )

        if success:
            log_message(f"[SUCCESS] File '{file_name}' uploaded successfully")
            if encrypt_file:
                messagebox.showinfo("Success", 
                    f"File uploaded and encrypted successfully!\n\n"
                    f"⚠️ Remember your password: You'll need it to decrypt this file!")
            else:
                messagebox.showinfo("Success", "File uploaded successfully!")
        else:
            error_msg = get_user_friendly_message(error)
            log_message(f"[ERROR] {error_msg}")
            messagebox.showerror("Upload Failed", error_msg)
        
        # Cleanup encrypted file
        if encrypt_file and os.path.exists(upload_path):
            os.remove(upload_path)

    except Exception as e:
        error_handler.log_error("UPLOAD ERROR", "Upload process failed", e)
        messagebox.showerror("Error", get_user_friendly_message(e))

def download_file_gui():
    """Download file with decryption and retry"""
    try:
        peers = get_peer_list()
        if not peers:
            messagebox.showinfo("No Peers", "No active peers found.")
            return

        # Prompt for token
        token = simpledialog.askstring("Enter Token", "Enter your authorization token:")
        if not token:
            return

        all_files = {}

        for peer in peers:
            try:
                response = requests.get(
                    f"http://{peer}/files", 
                    headers={"Authorization": token},
                    timeout=5
                )
                if response.status_code == 200:
                    files = response.json().get("files", [])
                    all_files[peer] = files
            except Exception as e:
                error_handler.log_warning(f"Failed to get files from {peer}: {str(e)}")
                continue

        options = []
        for peer, files in all_files.items():
            for file in files:
                options.append(f"{file} from {peer}")

        if not options:
            log_message("[NOT FOUND] No files found on peers.")
            messagebox.showinfo("No Files", "No files available on peers.")
            return

        selected = simpledialog.askstring(
            "Download", 
            "Enter number to download:\n\n" + "\n".join(f"{i+1}. {opt}" for i, opt in enumerate(options))
        )
        
        if not selected:
            return
        
        try:
            index = int(selected.split('.')[0]) - 1
            peer_info = options[index]
            filename, _, peer = peer_info.partition(" from ")
            filename = filename.strip()
            
            # Check if file is encrypted and ask for password
            decrypt_password = None
            if filename.endswith('.encrypted'):
                decrypt_password = simpledialog.askstring(
                    "Decryption Password", 
                    f"File '{filename}' is encrypted.\nEnter decryption password:",
                    show='*'
                )
                if not decrypt_password:
                    messagebox.showwarning("Password Required", 
                        "Decryption password is required for encrypted files!")
                    return
            
            # Download in separate thread
            threading.Thread(
                target=request_file_from_peer, 
                args=(peer, filename, token, decrypt_password),
                daemon=True
            ).start()
            
        except ValueError:
            error_handler.log_error("DOWNLOAD ERROR", "Invalid selection", None)
            log_message("[ERROR] Invalid selection. Please enter a number.")
            messagebox.showerror("Error", "Invalid selection. Please enter a number.")
        except Exception as e:
            error_handler.log_error("DOWNLOAD ERROR", "Download selection error", e)
            log_message("[ERROR] Invalid selection.")
            messagebox.showerror("Error", "Invalid selection.")

    except Exception as e:
        error_handler.log_error("DOWNLOAD GUI ERROR", "Download interface error", e)
        messagebox.showerror("Error", get_user_friendly_message(e))

def show_local_files():
    """Show local files with error handling"""
    try:
        files = os.listdir(FILES_DIR)
        if files:
            log_message("[SUCCESS] Local Files:\n" + "\n".join(files))
        else:
            log_message("[NOT AVAILABLE] No files available.")
    except Exception as e:
        error_handler.log_error("FILE LIST ERROR", "Failed to list local files", e)
        log_message(f"[ERROR] {get_user_friendly_message(e)}")

# ========== LOGGING ==========
def log_message(msg):
    try:
        output_box.config(state=NORMAL)
        output_box.insert(END, msg + '\n\n')
        output_box.config(state=DISABLED)
        output_box.see(END)
    except:
        pass  # GUI might not be ready

def start_network():
    """Start network with error handling"""
    try:
        threading.Thread(target=start_flask_server, daemon=True).start()
        time.sleep(1)  # Give server time to start
        register_peer()
        log_message("[CLIENT STARTED] Peer server running and registered.")
    except Exception as e:
        error_handler.log_error("STARTUP ERROR", "Failed to start network", e)
        log_message(f"[ERROR] {get_user_friendly_message(e)}")

# ========== GUI ==========
root = Tk()
root.title("ShareIt - Secure P2P")
root.geometry("500x650+500+150")
root.configure(bg="#f4fdfe")
root.resizable(False, False)

try:
    image_icon = PhotoImage(file="icon.png")
    root.iconphoto(False, image_icon)
except:
    pass  # Icon file not found

Label(root, text="P2P FILE TRANSFER", font=('Press Start 2P', 13, 'bold'), bg="#f4fdfe").pack(pady=20)
Frame(root, width=400, height=2, bg='#f3f5f6').pack()

Button(root, text="START NETWORK", width=25, height=2, font=('Roboto', 10, 'bold'), 
       bg="dark turquoise", fg="white", command=start_network).pack(pady=10)
Button(root, text="VIEW LOCAL FILES", width=25, height=2, font=('Roboto', 10, 'bold'), 
       bg="blue violet", fg="white", command=show_local_files).pack(pady=5)
Button(root, text="UPLOAD A FILE", width=25, height=2, font=('Roboto', 10, 'bold'), 
       bg="blue violet", fg="white", command=upload_files).pack(pady=5)
Button(root, text="DOWNLOAD A FILE", width=25, height=2, font=('Roboto', 10, 'bold'), 
       bg="blue violet", fg="white", command=download_file_gui).pack(pady=5)
Button(root, text="VIEW PEERS", width=25, height=2, font=('Roboto', 10, 'bold'), 
       bg="blue violet", fg="white", command=get_peer_list).pack(pady=5)
Button(root, text="EXIT", width=25, height=2, font=('Roboto', 10, 'bold'), 
       bg="tomato", fg="white", command=root.destroy).pack(pady=5)

Label(root, text="LOGS / OUTPUT", font=('Roboto', 12, 'bold'), bg="#f4fdfe").pack(pady=10)

output_box = Text(root, height=12, width=60, font=('Consolas', 10), state=DISABLED, bg="#fff")
output_box.pack(pady=5)

# Add time import at the top
import time

root.mainloop()