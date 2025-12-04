# P2P File Sharing System

A secure, hybrid peer-to-peer file sharing application with end-to-end encryption, built using Python. This system enables direct file transfers between peers while using a centralized discovery server for peer registration.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📖 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Security](#-security)
- [Project Structure](#-project-structure)
- [Configuration](#-configuration)
- [API Documentation](#-api-documentation)

## ✨ Features

### Core Functionality
- **Hybrid P2P Architecture**: Direct peer-to-peer file transfers with centralized peer discovery
- **Secure File Transfers**: End-to-end encryption using Fernet symmetric encryption
- **Token-based Authentication**: Secure peer communication with authentication tokens
- **Automatic Retry**: Exponential backoff retry mechanism for failed operations
- **Comprehensive Error Handling**: Centralized error management with detailed logging

### User Experience
- **Modern Dark UI**: Clean, professional graphical interface built with Tkinter
- **Real-time Logging**: Color-coded activity logs for easy monitoring
- **File Encryption**: Optional password-based encryption for uploaded files
- **Peer Management**: Easy peer discovery and file browsing

## 🏗️ Architecture

### System Design

This system implements a **hybrid peer-to-peer architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│                    Discovery Server                          │
│                    (Port 5000)                               │
│  • Maintains peer registry                                   │
│  • Handles peer registration                                 │
│  • Does NOT store or transfer files                          │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
    ┌───────┐          ┌───────┐          ┌───────┐
    │ Peer1 │◄────────►│ Peer2 │◄────────►│ Peer3 │
    └───────┘          └───────┘          └───────┘
         Direct P2P File Transfers
```

**Centralized Component:**
- Discovery server maintains a registry of active peers and their addresses
- Acts as a "phone book" for peers to find each other
- Lightweight - only handles registration, not file transfers

**Decentralized Component:**
- All file transfers happen directly between peers
- Each peer runs its own Flask server to handle file requests
- Files remain on individual peers - no central storage

**Benefits:**
- ✅ Simple peer discovery without complex DHT implementations
- ✅ Privacy - files never touch the central server
- ✅ Scalable - central server only handles lightweight operations
- ✅ Bandwidth efficient - no bottleneck at central server

**Trade-offs:**
- ⚠️ Discovery server is a single point of failure for finding new peers
- ⚠️ Already-connected peers can continue transferring files even if discovery server is down

### Components

#### 1. Peer Discovery Server (`peer_discovery_server.py`)
- Maintains registry of active peers
- Handles peer registration and lookup
- Runs on port 5000

#### 2. File Sharing Client (`file_sharing_client.py`)
- Main application with GUI
- Flask server for handling peer requests
- File upload/download functionality
- Encryption/decryption integration

#### 3. Encryption Module (`encryption_module.py`)
- Password-based encryption using PBKDF2HMAC
- Fernet symmetric encryption
- File and data encryption/decryption

#### 4. Error Handler (`error_handler.py`)
- Centralized error handling
- Custom exception classes (NetworkError, FileError, AuthenticationError, EncryptionError)
- Comprehensive logging to file and console

#### 5. Retry Mechanism (`retry_mechanism.py`)
- Exponential backoff retry logic
- Configurable retry attempts (default: 3)
- Callback support for retry events

## 📋 Prerequisites

- **Python**: 3.8 or higher
- **pip**: Python package installer
- **Operating System**: Windows, Linux, or macOS

## 🚀 Installation

1. **Clone or download the repository**
   ```bash
   cd P2PFileSharingSystem
   ```

2. **Install required dependencies**
   ```bash
   pip install -r requirements.txt
   ```

   Dependencies:
   - Flask 3.0.0
   - requests 2.31.0
   - cryptography 41.0.7

## 💻 Usage

### Step 1: Start the Discovery Server

Open a terminal and run:

```bash
python peer_discovery_server.py
```

You should see:
```
[DISCOVERY SERVER] Running on port 5000
```

**Keep this terminal running** - it needs to stay active for peers to discover each other.

### Step 2: Start Peer Clients

Open **new terminal windows** for each peer you want to run:

```bash
python file_sharing_client.py
```

The GUI application will open for each peer.

### Step 3: Using the Application

1. **Start Network**
   - Click the "Start Network" button
   - Your peer will register with the discovery server
   - A random port (5001-6000) will be assigned

2. **Upload Files**
   - Click "Upload File"
   - Select a file from your system
   - Choose whether to encrypt (optional)
   - If encrypting, set a password
   - File is added to your shared directory

3. **Download Files**
   - Click "Refresh Peers" to see active peers
   - Click "Download File"
   - Select a peer from the list
   - Select a file from that peer
   - If encrypted, enter the decryption password
   - File is downloaded to your system

4. **View Local Files**
   - Click "View Local Files" to see your shared files

## 🔐 Security

### Encryption

- **Algorithm**: Fernet (symmetric encryption based on AES-128)
- **Key Derivation**: PBKDF2HMAC with SHA-256
- **Iterations**: 100,000 iterations for key derivation
- **Salt**: Fixed salt (in production, use random salt per file)
- **Password Protection**: User-defined passwords for file encryption

### Authentication

- **Token-based**: Each peer generates a random 16-character authentication token
- **Request Validation**: All peer-to-peer requests require valid authentication tokens
- **Decorator**: `@require_auth` decorator validates tokens on Flask endpoints

### Security Considerations

⚠️ **Important Notes:**
- This is an educational project demonstrating P2P concepts
- For production use, implement:
  - Dynamic salt generation and storage
  - HTTPS/TLS for peer communication
  - More robust authentication (e.g., OAuth, JWT)
  - Rate limiting and DDoS protection

## 📁 Project Structure

```
P2PFileSharingSystem/
├── file_sharing_client.py      # Main client application with GUI
├── peer_discovery_server.py    # Centralized peer discovery server
├── encryption_module.py         # File encryption/decryption module
├── error_handler.py            # Centralized error handling
├── retry_mechanism.py          # Retry logic with exponential backoff
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

## ⚙️ Configuration

### Retry Configuration

Edit `retry_mechanism.py` to customize retry behavior:

```python
retry_config = RetryConfig(
    max_attempts=3,      # Maximum retry attempts
    base_delay=1,        # Initial delay in seconds
    backoff_factor=2,    # Exponential backoff multiplier
    max_delay=10         # Maximum delay between retries
)
```

### Network Configuration

Default settings in `file_sharing_client.py`:

```python
DISCOVERY_SERVER = "127.0.0.1"  # Discovery server address
DISCOVERY_PORT = 5000            # Discovery server port
PEER_PORT_RANGE = (5001, 6000)  # Random port range for peers
```

### Encryption Configuration

Default settings in `encryption_module.py`:

```python
iterations=100000    # PBKDF2 iterations
algorithm=SHA256     # Hash algorithm
```

## 📡 API Documentation

Each peer runs a Flask server with the following endpoints:

### `GET /list_files`

List all files available on this peer.

**Headers:**
- `Authorization: <token>`

**Response:**
```json
{
  "files": ["file1.txt", "file2.pdf", "image.png"]
}
```

### `POST /upload`

Upload a file to this peer.

**Headers:**
- `Authorization: <token>`

**Body:**
- Multipart form data with file

**Response:**
```json
{
  "message": "File uploaded successfully",
  "filename": "example.txt"
}
```

### `GET /download/<filename>`

Download a file from this peer.

**Headers:**
- `Authorization: <token>`

**Response:**
- File content (binary)

## 🐛 Error Handling

### Error Types

- **NetworkError**: Connection failures, timeouts
- **FileError**: File not found, permission denied
- **AuthenticationError**: Invalid or missing tokens
- **EncryptionError**: Decryption failures, invalid passwords

### Logging

Two types of logs are maintained:

1. **Console/GUI Logs**: Real-time color-coded messages
   - 🟢 Green: Success
   - 🔵 Blue: Information
   - 🟡 Yellow: Warning
   - 🔴 Red: Error

2. **File Logs**: Detailed logs in `p2p_errors.log`
   - Timestamps
   - Stack traces
   - Error context

## 🔄 Retry Mechanism

Failed operations are automatically retried with exponential backoff:

```
Attempt 1: Immediate
Attempt 2: Wait 1 second
Attempt 3: Wait 2 seconds
```

Retry is applied to:
- Peer registration
- File downloads
- File uploads
- Network requests

## 🎨 User Interface

### Color Scheme

- **Background**: Dark navy (#0a0e27)
- **Cards**: Slate gray (#1a1f3a)
- **Accent 1**: Cyan (#00d4ff)
- **Accent 2**: Purple (#a855f7)
- **Text**: White/Gray

### Features

- Hover effects on buttons
- Responsive layout
- Real-time log updates
- Clean, modern design

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Implement DHT for fully decentralized peer discovery
- Add support for large file transfers with chunking
- Implement resume capability for interrupted transfers
- Add peer reputation system
- Create web-based interface

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- **Flask**: Web framework for peer servers
- **Cryptography**: Encryption library
- **Tkinter**: GUI framework

## 📞 Support

For issues or questions, please open an issue in the repository.

---

**© 2025 Secure P2P File Sharing System**
