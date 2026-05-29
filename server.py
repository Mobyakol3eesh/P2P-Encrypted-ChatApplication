from flask import Flask, request, jsonify
import threading

app = Flask(__name__)
# In-memory peer registry keyed by username; values store IP and port.
# This is shared across requests, so access is protected by a lock.
peers = {} 
lock = threading.Lock()

# Register a peer by username and address.
# Steps:
# - Read JSON payload containing username, IP, and port.
# - Reject if username already exists in the directory.
# - Reject if the same IP+port is already registered to any user.
# - Store the entry under a lock to avoid concurrent modification issues.
# - Return a simple status JSON so the client can proceed or exit.
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    if data['username'] in peers:
        return jsonify({"status": "error", "message": "Username already taken."}), 400
    if data['ip'] in [u["ip"] for u in peers.values()] and data['port'] in [u["port"] for u in peers.values()]:
        return jsonify({"status": "error", "message": "IP with port address already in use."}), 400
    
    with lock:
        peers[data["username"]] = {"ip": data["ip"], "port": data["port"]}
    return jsonify({"status": "ok"})

# Remove a peer registration.
# Steps:
# - Read JSON payload containing the username.
# - Under lock, delete the entry if it exists.
# - Always return a success status so clients can exit cleanly.
@app.route("/unregister", methods=["POST"])
def unregister():
    data = request.json
    with lock:
        if data["username"] in peers:
            del peers[data["username"]]
    return jsonify({"status": "ok"})

# Return the full peer directory.
# Steps:
# - Acquire lock to prevent reading a partially-updated dict.
# - Serialize and return the current peers mapping.
@app.route("/peers", methods=["GET"])
def list_peers():
    with lock:
        return jsonify(peers)

# Look up a single peer by username.
# Steps:
# - Acquire lock and fetch the peer entry if present.
# - Return the entry or an empty dict when missing.
@app.route("/find/<username>")
def find(username):
    with lock:
        return jsonify(peers.get(username, {}))

# Start the signaling server when this module is executed directly.
# Listens on all interfaces so peers on the LAN can register/discover.
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
