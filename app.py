from peer import Peer

import socket, threading, requests, json, sys
import asyncio
import sys
import signal
from encoder import Encoder
from aes import AES

# Base URL for the signaling server used for registration and discovery.
# Clients use this endpoint to register, list peers, and find addresses.
SIGNAL_SERVER = "http://localhost:8000"


class P2PEncryptedChatApp:
    # Coordinates peer networking, encryption, and command handling for the CLI.
    # Owns the local TCP server socket and manages peer connections.
    # Uses the signaling server to discover and register peers.
    # Construct the chat app instance and local server socket.
    # Steps:
    # - Create encoder and peer objects.
    # - Pick an available port and bind a listening TCP socket.
    # - Initialize connection-tracking structures and debug mode.
    def __init__(self, username, debug = False):
        
        self.debug = debug
        
        self.encoder = Encoder('utf-8')  
        self.peer = Peer(username, None, self.encoder,debug)
        self.peer.port = self.assign_unique_port()  
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("0.0.0.0", self.peer.port))
        self.server.listen(10)
        
        
        
        
        self._connecting = set()  # guard against double-connect races
    
    # Determine this machine's local IP address.
    # Uses hostname resolution to obtain a LAN-reachable address.
    # Returned IP is used for peer registration and discovery.
    def get_peer_ip(self):
        ip = socket.gethostbyname(socket.gethostname())
        return ip
    
    # Choose a port that does not collide with existing peers.
    # Steps:
    # - Query signaling server for active peers.
    # - If peers share the same IP, find the next unused port.
    # - Default to 5000 when no conflicts exist.
    def assign_unique_port(self):
        if self.debug:
            print("Assigning port...")
        ip = self.get_peer_ip()
        peers = self.get_active_peers()
        if ip in [u["ip"] for u in peers.values()]:
            used_ports = {info["port"] for info in self.get_active_peers().values()}
            port = 5000
            while port in used_ports:
                port += 1
            if self.debug:
                print("Same Local IP Detected. Assigning unique port...")
            return port
        else:
            return 5000
    
    
    # Accept incoming TCP connections forever.
    # For each new socket, spawn a thread to handle the handshake.
    # Keeps the main thread free for the CLI loop.
    def listen(self):
        while True:
            if self.debug:
                print("Waiting for incoming connections...")
            conn, addr = self.server.accept()
            threading.Thread(target=self.handle_incoming, args=(conn,), daemon=True).start()

    
    # Send a length-prefixed payload over TCP.
    # Prefixing avoids message boundary ambiguity in a stream socket.
    # The receiver can read the exact payload size deterministically.
    def send_framed(self, sock, data: bytes):
        # Prefix with 4-byte length, then the data
        length = len(data).to_bytes(4, byteorder='big')
        sock.sendall(length + data)

    # Receive a length-prefixed payload from TCP.
    # Reads the 4-byte length prefix first, then the payload.
    # Returns None if the peer disconnects.
    def recv_framed(self, sock) :
        # Read exactly 4 bytes for the length
        raw_len = self._recv_exact(sock, 4)
        if not raw_len:
            return None
        length = int.from_bytes(raw_len, byteorder='big')
        # Read exactly that many bytes
        return self._recv_exact(sock, length)

    # Read exactly n bytes from a socket.
    # Loops until the byte count is satisfied or the peer disconnects.
    # Used by recv_framed to enforce payload boundaries.
    def _recv_exact(self, sock, n) :
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    # Register this peer with the signaling server.
    # Sends username, IP, and port; exits on failure to avoid ghost peers.
    # Successful registration lets other peers discover this instance.
    def register(self):
        print("Connecting to intermediate server....")
        ip = self.get_peer_ip()
        status = requests.post(f"{SIGNAL_SERVER}/register", json={
            "username": self.peer.username, "ip": ip, "port": self.peer.port
        })
        
        if status.status_code == 200:
            print(f"Registered as {self.peer.username} at {ip}:{self.peer.port}")
        else:
            print(f"Failed to register. Reason: {status.json().get('message', 'Unknown error')}")
            sys.exit(1)

    # Print all groups this peer belongs to.
    # Reads the local in-memory group map.
    # No network calls are required.
    def list_my_groups(self):
        if not self.peer.groups:
            print("You are not in any groups.")
            return
        print("Groups you are in:")
        for group in self.peer.groups:
            print(f"  - {group}")

    # Print the usernames for a specific group.
    # Validates group existence before listing.
    # Uses the local group map populated by announcements.
    def list_group_members(self, group_name):
        if group_name not in self.peer.groups:
            print(f"Group '{group_name}' not found.")
            return
        members = self.peer.groups[group_name]
        print(f"Members of group '{group_name}': {', '.join(members)}")
    
    # Establish a connection to a remote peer by username.
    # Steps:
    # - Prevent self-connects and duplicate in-progress connects.
    # - Query signaling server for the peer's IP/port.
    # - Open TCP socket and exchange handshake with public keys.
    # - Decrypt session key and store connection metadata.
    def connect_to(self, username):
        if username == self.peer.username:
            return # don't connect to self
        if username in self.peer.connections:
            return  # already connected, reuse existing socket
        if username in self._connecting:
            return  # connection attempt already in progress
        
        
        
        
        print(f"Connecting to {username}...")
        info = requests.get(f"{SIGNAL_SERVER}/find/{username}").json()
        if not info:
            print(f"User {username} not found.")
            return

        self._connecting.add(username)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((info["ip"], info["port"]))
            # Send our hello with public key
            
            
            hello = self.encoder.encode(json.dumps({
                "type": "hello",
                "from": self.peer.username,
                "public_key": self.peer.public_key,
            }))
            if self.debug:
                print(f"Handshaking with {username} by sending {hello}")
            self.send_framed(s, hello)

            # Wait for hello response with their public key
            
            raw = self.recv_framed(s)
            if not raw:
                raise Exception("Connection closed before handshake completed")
            msg = json.loads(raw)
            if self.debug:
                print(f"Got a message back from handshaking containing {msg}")
            if msg["type"] == "hello":
                encrypted_session_key = Encoder.represent_hex_in_bytes(msg["session_key"]) #type: ignore
                session_key = self.peer.decrypt_session_key(encrypted_session_key) #type: ignore
                self.peer.init_aes(session_key)
                
                
                
                self.peer.connections[username] = {"socket": s, "public_key": msg["public_key"], "session_key": session_key} #session key in bytes
                if self.debug:
                    print("Saved connection Successfully ")
            else:
                raise Exception("Expected hello response, got something else")
            if self.debug:
                print("Now iterating on saved connection to listen for any incoming message or group updates on a separate thread")
            threading.Thread(target=self.handle_incoming_loop, args=(username, s), daemon=True).start()
            print(f"Connected to {username}")
        except Exception as e:
            print(f"Failed to connect to {username}: {e}")
        finally:
            self._connecting.discard(username)

    # Handle an inbound connection initiated by another peer.
    # Steps:
    # - Read the peer's hello and public key.
    # - Create a new AES session key and encrypt it with their public key.
    # - Store connection and reply with our hello + encrypted session key.
    def handle_incoming(self, conn):
        raw = self.recv_framed(conn)
        msg = json.loads(raw) #type:ignore
        sender = msg["from"]
        if sender not in self.peer.connections:
            sender_public_key = msg["public_key"]
            session_key = AES.generate_aes_key(128) 
            self.peer.init_aes(session_key)
            encrypted_session_key = self.peer.encrypt_session_key(session_key, sender_public_key[0], sender_public_key[1])
            self.peer.connections[sender] = {
                "socket": conn,
                "public_key": sender_public_key,
                "session_key": session_key
                
            }
            hello = self.encoder.encode(json.dumps({
                "type": "hello",
                "from": self.peer.username,
                "public_key": self.peer.public_key,
                "session_key": Encoder.represent_bytes_in_hex(encrypted_session_key) #bytes
            }))
            self.send_framed(conn, hello)
        print(f"\n[{sender} connected]")
        self.handle_incoming_loop(sender, conn)

    # Receive and process messages from a connected peer.
    # Steps:
    # - Read framed ciphertext messages.
    # - Decrypt using the stored session key and IV.
    # - Update group membership and display the message.
    def handle_incoming_loop(self, username, conn):
        while True:
            try:
                data = self.recv_framed(conn)
                if not data:
                    break
                data = json.loads(self.encoder.decode(data))
                decrypted = self.peer.decrypt_message(Encoder.represent_hex_in_bytes(data["ciphertext"]), 
                                                      self.peer.connections[username]["session_key"],
                                                      iv=Encoder.represent_hex_in_bytes(data["iv"])) #type: ignore
                msg = json.loads(self.encoder.decode(decrypted))
                if msg['type'] == 'group_announce':
                    self.peer.groups[msg["group"]] = msg["members"]
                self.display(msg)
            except Exception as e:
                print(f"\n[Error from {username}]: {e}")
                break
        self.peer.connections.pop(username, None)
        print(f"\n[{username} disconnected]")

    # Remove this peer from the signaling server.
    # Sends a simple unregister request by username.
    # Used when quitting or handling Ctrl+C.
    def unregister(self):
        requests.post(f"{SIGNAL_SERVER}/unregister", json={"username": self.peer.username})
        print(f"Unregistered {self.peer.username}")

    # Fetch the current peer directory from the signaling server.
    # Removes this peer from the returned list to avoid self-targeting.
    # Returns a dict mapping usernames to address info.
    def get_active_peers(self):
        peers = requests.get(f"{SIGNAL_SERVER}/peers").json()
        peers.pop(self.peer.username, None)
        return peers

    # Ensure a connection to a peer exists.
    # Initiates a connection only if not already connected.
    # Prevents redundant socket creation.
    def connect_if_needed(self, username):
        if username not in self.peer.connections:
            self.connect_to(username)
        # connect_to stores socket before returning, no wait needed


    # Send a direct message to a single peer.
    # Steps:
    # - Ensure a connection exists (handshake if needed).
    # - Build a JSON payload, encrypt with AES-CBC using a fresh IV.
    # - Frame and send the ciphertext to the peer.
    def send(self, to_username, text):
        self.connect_if_needed(to_username)
        if to_username not in self.peer.connections:
            print(f"Could not reach {to_username}")
            return

        iv = AES.generate_iv()
        msg = self.encoder.encode(json.dumps({
            "type": "dm",
            "from": self.peer.username,
            "to": to_username,
            "text": text
        }))
        encrypted = self.peer.encrypt_message(msg,self.peer.connections[to_username]["session_key"] ,iv)
        message = json.dumps({
            "iv": self.encoder.represent_bytes_in_hex(iv),   
            "ciphertext": self.encoder.represent_bytes_in_hex(encrypted)
        })
        encoded_message = self.encoder.encode(message)
      
        
        self.send_framed(self.peer.connections[to_username]["socket"],  encoded_message)
        print(f"[you -> {to_username}]: {text}")

    # Create a new group and announce it to members.
    # Steps:
    # - Store group membership locally (including self).
    # - Ensure connections to members exist.
    # - Send encrypted group_announce messages to each member.
    def create_group(self, group_name, members):
        all_members = members + [self.peer.username]
        self.peer.groups[group_name] = all_members
        for m in members:
            self.connect_if_needed(m)
        for m in members:
            if m in self.peer.connections:
                ann = self.encoder.encode(json.dumps({
                    "type": "group_announce",
                    "from": self.peer.username,
                    "group": group_name,
                    "members": all_members
                }))+ b"\n"
                iv = AES.generate_iv()
                encrypted_ann = self.peer.encrypt_message(ann,self.peer.connections[m]["session_key"] ,iv)
                message = json.dumps({
                    "iv": self.encoder.represent_bytes_in_hex(iv),   
                    "ciphertext": self.encoder.represent_bytes_in_hex(encrypted_ann) #type: ignore
                })
                encoded_message = self.encoder.encode(message)
                
                
                self.send_framed(self.peer.connections[m]["socket"], encoded_message)
        print(f"Group '{group_name}' created with members: {', '.join(members)}")

    # Disconnect from a peer and clean up state.
    # Closes the socket and removes the entry from connections.
    # Prints status to inform the user.
    def disconnect_from(self, username):
        if username in self.peer.connections:
            self.peer.connections[username]["socket"].close()
            del self.peer.connections[username]
            print(f"Disconnected from {username}")
        else:
            print(f"Not connected to {username}")

    # Send a message to all members of a group.
    # Steps:
    # - Validate group exists.
    # - Ensure connections to each member.
    # - Encrypt and send the message to each member.
    def send_group(self, group_name, text):
        if group_name not in self.peer.groups:
            print("Unknown group")
            return
        msg = self.encoder.encode(json.dumps({
            "type": "group",
            "from": self.peer.username,
            "group": group_name,
            "text": text
        })) + b"\n"
        for member in self.peer.groups[group_name]:
            self.connect_if_needed(member)
            if member in self.peer.connections:
                iv = AES.generate_iv()
                encrypted = self.peer.encrypt_message(msg,self.peer.connections[member]["session_key"] ,iv)
                message = json.dumps({
                    "iv": self.encoder.represent_bytes_in_hex(iv),   
                    "ciphertext": self.encoder.represent_bytes_in_hex(encrypted)
                })
                encoded_message = self.encoder.encode(message)
                self.send_framed(self.peer.connections[member]["socket"], encoded_message)
        print(f"[you -> {group_name}]: {text}")

    # Display an incoming message on the console.
    # Handles direct messages, group messages, and group announcements.
    # Prints a prompt hint so the user can continue typing.
    def display(self, msg):
        print("\npress enter to continue...", end="")  
        if msg["type"] == "dm":
            print(f"\n[DM from {msg['from']}]: {msg['text']}")
        elif msg["type"] == "group":
            print(f"\n[{msg['group']} | {msg['from']}]: {msg['text']}")
        elif msg["type"] == "group_announce":
            print(f"\n[Added to group '{msg['group']}' by {msg['from']}]")

    # Run the interactive CLI loop.
    # Registers with the signaling server, starts listener thread,
    # and dispatches user commands (/dm, /connect, /quit, etc.).
    def run(self, username):
        self.register()
        threading.Thread(target=self.listen, daemon=True).start()
        print("Commands: /connect <user>  /disconnect <user>  /dm <user> <msg>  /create-group <name> <u1,u2> /list-group <group>  /dm-group <group> <msg> /my-groups  /list-peers   /quit")
        while True:
            
            line = input(f"{username}> ").strip()
            if line.startswith("/connect "):
                self.connect_to(line.split()[1])
            elif line.startswith("/disconnect "):
                self.disconnect_from(line.split()[1])
            elif line.startswith("/dm "):
                # /dm <username> <message>
                parts = line.split(" ", 2)
                if len(parts) < 3:
                    print("Usage: /dm <user> <message>")
                else:
                    self.send(parts[1], parts[2])
            elif line.startswith("/create-group "):
                parts = line.split(" ", 2)
                self.create_group(parts[1], parts[2].split(","))
            elif line.startswith("/dm-group "):
                parts = line.split(" ", 2)
                self.send_group(parts[1], parts[2])
            elif line.startswith("/list-group "):
                parts = line.split(" ", 1)
                if len(parts) < 2:
                    print("Usage: /list-group <group>")
                else:
                    self.list_group_members(parts[1])
            elif line == "/my-groups":
                self.list_my_groups()
            elif line == "/list-peers":
                print("Fetching active peers...")
                peers = self.get_active_peers()
                if peers:
                    print("Active peers:\n" + "\n".join(f"  - {p}" for p in peers))
                else:
                    print("No active peers found.")
            elif line == "/quit":
                self.unregister()
                sys.exit()


if __name__ == "__main__":
    
    
    debug = False
    if len(sys.argv) > 1 and sys.argv[1] == "--debug":
        debug = True
        
    
    app = P2PEncryptedChatApp(
        username=input("Enter your username: "),
        debug = debug
    )       

    # Handle Ctrl+C to unregister cleanly before exiting.
    # Ensures the signaling server does not retain a stale entry.
    # Called by the signal module on SIGINT.
    def signal_handler(sig, frame):
        print("\nExiting...")
        app.unregister()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    app.run(app.peer.username)