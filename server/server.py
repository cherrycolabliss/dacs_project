import secrets
from flask import Flask, request, jsonify
import uuid
from tinydb import TinyDB,Query
import datetime
import socket
import json
import base64
import os
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

DB = TinyDB("Users.json")
challenge_db = TinyDB("challenges.json")

users = DB.table("users")
login_sessions = DB.table("Sessions")
public_key_db = DB.table("Public_Keys")


Challenge = Query()
UserQ = Query()
SessionQ = Query()
PubKeyQ = Query()


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    device_id = data['device_id']
    user = users.search(UserQ.user == username) or None
    if user is None:
        document = {
            'user':user,
            "devices":[data.get("device_id")]
        }
        users.upsert({users[username] : [device_id]},UserQ.user == user)
    else:
        if device_id not in users.get("devices",[]):
            new_devices = user.get("devices", []) + [device_id]
            users.update({"devices": new_devices}, UserQ.username == username)
    return jsonify({"status": "ok", "username": username, "device_id": device_id}), 201

@app.route('/login/request', methods=['POST'])
def login_request():
    data = request.json
    username = data['username']
    device_id = data['device_id']
    if username not in users or device_id not in users[username]["devices"]:
        return jsonify({"error": "User or device not registered"}), 400
    session_id = str(uuid.uuid4())
    challenge = str(uuid.uuid4())
    login_sessions[session_id] = {"username": username, "challenge": challenge}
    return jsonify({"session": session_id, "challenge": challenge}), 200

@app.route('/login/response', methods=['POST'])
def login_response():
    data = request.jsonss
    session_id = data['session']
    response = data['response']
    if session_id not in login_sessions:
        return jsonify({"error": "invalid session"}), 400
    challenge = login_sessions[session_id]["challenge"]
    if response == challenge:
        return jsonify({"status": "login success"}), 200
    return jsonify({"status": "login failed"}), 403

@app.route('/recive_public_key', methods=['POST'])
def rec_public_key():
    try:
        json = request.get_json()
        print(json)
        id = list(json.keys())[0]
        print(id)
        data = json.get(id)
        print(data)
        document = {
            'record_id':id,
            'public_key':data.get("Pub_key"),
            "device":data.get("device_id")
        }
        public_key_db.upsert(document,PubKeyQ.record_id == document.get("record_id"))
        return jsonify({"status":"OK","msg" :"successfully add to db"}) , 200
    except Exception as e:
        return jsonify({"status":"Err","msg":str(e)}), 500


##### PHASE 4 BY ERLAND #####

# For testing the server, run the file and open http://127.0.0.1:5000/test in the browser
@app.route("/test", methods=["GET"])
def test_route():
    return jsonify({"message": "Server is running!"})


@app.route("/request_challenge", methods=["POST"])
def request_challenge():
    data = request.get_json()
    username = data.get("user")

    # Look up user in TinyDB
    record = users.get(UserQ.user == username)
    if not record:
        return jsonify({"error": "unknown user"}), 400

    # Generate challenge
    challenge = secrets.token_bytes(32)
    challenge_b64 = base64.b64encode(challenge).decode()

    # Store in challenge DB
    challenge_db.upsert(
        {"user": username, "challenge": challenge_b64},
        Challenge.user == username
    )

    return jsonify({"challenge": challenge_b64})

@app.route("/verify_signature", methods=["POST"])
def verify_signature():
    data = request.get_json()
    username = data.get("user")
    signature_b64 = data.get("signature")

    # Load stored challenge
    entry = challenge_db.get(Challenge.user == username)
    if not entry:
        return jsonify({"status": "failed", "reason": "no challenge"}), 400

    challenge_bytes = base64.b64decode(entry["challenge"])

    # Delete challenge after use
    challenge_db.remove(Challenge.user == username)

    # Load public key from user DB
    record = DB.get(users.user == username)
    public_pem = record["public_key"].encode()
    public_key = load_pem_public_key(public_pem)

    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(
            signature,
            challenge_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception:
        return jsonify({"status": "failed"})

    return jsonify({"status": "success"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
    app.run(debug=True)
