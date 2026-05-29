from flask import Flask, request, jsonify
import threading

app = Flask(__name__)
peers = {} 
lock = threading.Lock()

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

@app.route("/unregister", methods=["POST"])
def unregister():
    data = request.json
    with lock:
        if data["username"] in peers:
            del peers[data["username"]]
    return jsonify({"status": "ok"})

@app.route("/peers", methods=["GET"])
def list_peers():
    with lock:
        return jsonify(peers)

@app.route("/find/<username>")
def find(username):
    with lock:
        return jsonify(peers.get(username, {}))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
