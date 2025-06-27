# PyChat - LAN Based Secure Chat Room

A secure, encrypted group chat application designed for local area networks (LAN) built in Python with real-time messaging, file sharing, and comprehensive admin controls.

## 🔐 Features

- **LAN-Optimized**: Designed specifically for local area network communication
- **End-to-End Encryption**: All messages and files are encrypted using Fernet symmetric encryption
- **Group Management**: Create and join chat groups with admin approval system
- **Real-time Messaging**: Instant message delivery to all online group members
- **File Sharing**: Securely share files with all group members
- **Admin Controls**: 
  - Approve/deny join requests
  - Kick members from groups
  - Transfer admin privileges
  - View member lists and pending requests
- **Multi-threaded Architecture**: Concurrent handling of multiple clients
- **Cross-platform**: Works on Windows, macOS, and Linux

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- Required packages: `cryptography`

### Installation

1. Clone the repository:
```bash
git clone https://github.com/m-ahmad3/PyChat-LAN-Secure.git
cd Pychat-LAN-Secure
```

2. Install dependencies:
```bash
pip install cryptography
```

### Usage

1. **Start the server:**
```bash
python Server.py <IP> <Port>
# Example for LAN:
python Server.py 192.168.1.100 8000
# Or for local testing:
python Server.py localhost 8000
```

2. **Connect clients:**
```bash
python Client.py <IP> <Port>
# Example for LAN:
python Client.py 192.168.1.100 8000
# Or for local testing:
python Client.py localhost 8000
```

3. **Create or join a group:**
   - Enter your username when prompted
   - Enter the group name (creates new group if it doesn't exist)
   - First user becomes the admin automatically

## 📋 Commands

Once connected, use these commands:

| Command | Description | Admin Only |
|---------|-------------|------------|
| `/1` | View join requests | ✅ |
| `/2` | Approve join requests | ✅ |
| `/3` | Disconnect from chat | ❌ |
| `/4` | View all group members | ❌ |
| `/5` | View online members | ❌ |
| `/6` | Transfer admin privileges | ✅ |
| `/7` | Check current group admin | ❌ |
| `/8` | Kick a member | ✅ |
| `/9` | Share a file | ❌ |

Type any other text to send a regular message to the group.

## 🏗️ Architecture

### Server Components
- **Group Management**: Handles group creation, member management, and permissions
- **Encryption Layer**: Encrypts/decrypts all communications using Fernet
- **Multi-threading**: Each client connection runs in a separate thread
- **File Transfer**: Secure file sharing with automatic cleanup

### Client Components
- **Dual Threading**: Separate threads for sending and receiving messages
- **State Management**: Tracks connection status and user permissions
- **Interactive CLI**: User-friendly command-line interface

## 🔧 Technical Details

### Security
- Uses Fernet (AES 128 encryption) for symmetric encryption
- Encryption key is generated server-side and shared during handshake
- All messages, files, and commands are encrypted in transit
- No data persistence - all information is stored in memory

### Network Protocol
- TCP socket communication
- Custom protocol with length-prefixed encrypted messages
- Automatic reconnection handling for network interruptions

### File Transfer
- Files are encrypted before transmission
- Temporary server-side storage with automatic cleanup
- Supports any file type and size (within memory limits)


## 🐛 Known Issues

- Large file transfers may consume significant memory
- Server shutdown requires manual process termination
- No message history persistence between sessions
