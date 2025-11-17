from flask import Flask, request, jsonify
import uuid
from tinydb import TinyDB,Query
import datetime
from flask import make_response

app = Flask(__name__)

DB = TinyDB("DB.json")

registerPage = open("webui/register.html").read()
loginPage = open("webui/login.html").read()
style = open("webui/style.css").read()
script = open("webui/script.js").read()
users = DB.table("users")
login_sessions = DB.table("Sessions")
public_key_db = DB.table("Public_Keys")

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
        users.upsert({username : [device_id]},UserQ.user == user)
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
    data = request.json
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
    
@app.route("/register")
def registerpage():
    return registerPage

@app.route("/")
def loginpage():
    return make_response(loginPage)

@app.route("/style.css")
def styling():
    res = make_response(style)
    res.headers['Content-Type'] = 'text/css; charset=utf-8'
    return res

@app.route("/script.js")
def jsscript():
    res = make_response(script)
    res.headers['Content-Type'] = 'text/javascript; charset=utf-8'
    return res

if __name__ == '__main__':
    app.run(debug=True)
