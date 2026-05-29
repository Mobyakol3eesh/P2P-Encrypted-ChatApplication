from flask import Flask, request, jsonify
import threading

app = Flask(__name__)
peers = {} 
lock = threading.Lock()

@app.route("/register", methods=["POST"])
# Register a peer by username and address.
# Steps:
# - Read JSON payload containing username, IP, and port.
# - Reject if username already exists in the directory.
# - Reject if the same IP+port is already registered to any user.
# - Store the entry under a lock to avoid concurrent modification issues.
# - Return a simple status JSON so the client can proceed or exit.
def register():
    """Register a peer by username and network endpoint."""
    data = request.json
    if data['username'] in peers:
        return jsonify({"status": "error", "message": "Username already taken."}), 400
    if data['ip'] in [u["ip"] for u in peers.values()] and data['port'] in [u["port"] for u in peers.values()]:
        return jsonify({"status": "error", "message": "IP with port address already in use."}), 400
    
    with lock:
        peers[data["username"]] = {"ip": data["ip"], "port": data["port"]}
    return jsonify({"status": "ok"})

@app.route("/unregister", methods=["POST"])
# Remove a peer registration.
# Steps:
# - Read JSON payload containing the username.
# - Under lock, delete the entry if it exists.
# - Always return a success status so clients can exit cleanly.
def unregister():
    """Remove a peer registration entry by username."""
    data = request.json
    with lock:
        if data["username"] in peers:
            del peers[data["username"]]
    return jsonify({"status": "ok"})

@app.route("/peers", methods=["GET"])
# Return the full peer directory.
# Steps:
# - Acquire lock to prevent reading a partially-updated dict.
# - Serialize and return the current peers mapping.
def list_peers():
    """Return the currently registered peer directory."""
    with lock:
        return jsonify(peers)

@app.route("/find/<username>")
# Look up a single peer by username.
# Steps:
# - Acquire lock and fetch the peer entry if present.
# - Return the entry or an empty dict when missing.
def find(username):
    """Return network details for a specific username, if registered."""
    with lock:
        return jsonify(peers.get(username, {}))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
