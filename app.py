import time
import json
import base64
import asyncio
import sys
import httpx
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from datetime import datetime, timedelta

from google.protobuf import json_format
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
from google.protobuf.message import Message

# ============================================================
#  PART 1 — Protobuf Definitions (FreeFire & AccountPersonalShow)
# ============================================================

_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC, 6, 30, 0, "", "FreeFire.proto",
)

_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x0e\x46reeFire.proto"c\n\x08LoginReq\x12\x0f\n\x07open_id\x18\x16 \x01(\t'
    b'\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0blogin_token\x18\x1d '
    b'\x01(\t\x12\x1b\n\x13orign_platform_type\x18\x63 \x01(\t"]\n\x10\x42lacklist'
    b'InfoRes\x12\x1e\n\nban_reason\x18\x01 \x01(\x0e\x32\n.BanReason\x12\x17\n'
    b'\x0f\x65xpire_duration\x18\x02 \x01(\r\x12\x10\n\x08\x62\x61n_time\x18\x03'
    b' \x01(\r"f\n\x0eLoginQueueInfo\x12\r\n\x05\x61llow\x18\x01 \x01(\x08\x12'
    b'\x16\n\x0equeue_position\x18\x02 \x01(\r\x12\x16\n\x0eneed_wait_secs\x18'
    b'\x03 \x01(\r\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08"\xa0\x03\n\x08'
    b'LoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x04\x12\x13\n\x0block_region'
    b'\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t\x12\x11\n\tip_'
    b'region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t'
    b'\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\x19\n\x11recommend_'
    b'regions\x18\x07 \x03(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03ttl'
    b'\x18\t \x01(\r\x12\x12\n\nserver_url\x18\n \x01(\t\x12\x16\n\x0e\x65mul'
    b'ator_score\x18\x0b \x01(\r\x12$\n\tblacklist\x18\x0c \x01(\x0b\x32\x11.'
    b'BlacklistInfoRes\x12#\n\nqueue_info\x18\r \x01(\x0b\x32\x0f.LoginQueue'
    b'Info\x12\x0e\n\x06tp_url\x18\x0e \x01(\t\x12\x15\n\rapp_server_id\x18'
    b'\x0f \x01(\r\x12\x0f\n\x07\x61no_url\x18\x10 \x01(\t\x12\x0f\n\x07ip_city'
    b'\x11 \x01(\t\x12\x16\n\x0eip_subdivision\x18\x12 \x01(\t*\xa8\x01\n'
    b'\tBanReason\x12\x16\n\x12\x42\x41N_REASON_UNKNOWN\x10\x00\x12\x1b\n\x17'
    b'\x42\x41N_REASON_IN_GAME_AUTO\x10\x01\x12\x15\n\x11\x42\x41N_REASON_'
    b'REFUND\x10\x02\x12\x15\n\x11\x42\x41N_REASON_OTHERS\x10\x03\x12\x16\n'
    b'\x12\x42\x41N_REASON_SKINMOD\x10\x04\x12 \n\x1b\x42\x41N_REASON_IN_GAME'
    b'_AUTO_NEW\x10\xf6\x07\x62\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "FreeFire_pb2", _globals)

LoginReq = _globals["LoginReq"]
LoginRes = _globals["LoginRes"]

# প্রোটো ফাইল ইম্পোর্ট চেক
try:
    import main_pb2, AccountPersonalShow_pb2
    print("✅ Proto files (main_pb2, AccountPersonalShow_pb2) imported successfully")
except ImportError as e:
    print(f"❌ Proto import error: {e}")
    sys.exit(1)


# ============================================================
#  PART 2 — Settings & Configuration
# ============================================================

MAIN_KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")
RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"
LOGIN_URL = "https://loginbp.ppmainecoonghj.com/"
SERVER_URL = "https://clientbp.ppmainecoonghj.com"
REGION = "BD"

# Fast HTTP client
HTTP_LIMITS = httpx.Limits(max_keepalive_connections=20, max_connections=50)
HTTP_TIMEOUT = httpx.Timeout(15.0, connect=5.0)
_http_client = httpx.Client(limits=HTTP_LIMITS, timeout=HTTP_TIMEOUT)


# ============================================================
#  PART 3 — Flask App
# ============================================================

app = Flask(__name__)
CORS(app)


# ============================================================
#  PART 4 — Helpers & Crypto Functions
# ============================================================

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))


def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


def try_parse_login_res(data: bytes):
    try:
        msg = LoginRes()
        msg.ParseFromString(data)
        if msg.account_id and msg.account_id > 0:
            return json.loads(json_format.MessageToJson(msg))
    except Exception:
        pass
    return None


def extract_login_res(raw: bytes) -> dict:
    parsed = try_parse_login_res(raw)
    if parsed:
        return parsed

    idx = 0
    while True:
        idx = raw.find(b"\x08", idx)
        if idx == -1:
            break
        parsed = try_parse_login_res(raw[idx:])
        if parsed:
            return parsed
        idx += 1

    jwt_marker = raw.find(b"eyJhbGciOiJIUzI1NiIs")
    if jwt_marker != -1:
        for i in range(jwt_marker - 1, max(jwt_marker - 300, -1), -1):
            if raw[i] == 0x42:
                parsed = try_parse_login_res(raw[i:])
                if parsed:
                    return parsed
                break

    raise Exception(f"Could not parse LoginRes. Raw: {raw[:200]}")


def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = (
        account
        + "&response_type=token&client_type=2"
        + "&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        + "&client_id=100067"
    )
    headers = {
        "User-Agent": USERAGENT,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    resp = _http_client.post(url, data=payload, headers=headers)
    data = resp.json()
    return data.get("access_token", "0"), data.get("open_id", "0")


def generate_jwt_token(uid: str, password: str):
    start_time = time.time()

    token_val, open_id = get_access_token(f"uid={uid}&password={password}")
    if token_val == "0" or open_id == "0":
        raise Exception("Invalid UID or Password — access token not received")

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4",
    })
    proto_bytes = json_to_proto(body, LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    headers = {
        "User-Agent": USERAGENT,
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-Ga-Sv": "1789534056",
        "Authorization": "Bearer",
        "X-Ga": "v1 1",
        "Releaseversion": RELEASEVERSION,
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
        "PlAy_VeR": "1.132.1",
        "Ob_VeR": RELEASEVERSION,
    }

    resp = _http_client.post(f"{LOGIN_URL}MajorLogin", data=payload, headers=headers)
    msg = extract_login_res(resp.content)

    elapsed = time.time() - start_time

    return {
        "access_token": token_val,
        "open_id": open_id,
        "real_uid": str(msg.get("accountId", "")),
        "status": "success",
        "time": f"{elapsed:.2f}s",
        "token": f"{msg.get('token', '')}",
    }


# ============================================================
#  PART 5 — Profile Info Fetching Helpers
# ============================================================

async def json_to_proto_async(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

async def GetAccountInformation(uid, jwt_token):
    try:
        token = f"Bearer {jwt_token}"
        payload = await json_to_proto_async(json.dumps({'a': uid, 'b': '7'}), main_pb2.GetPlayerPersonalShow())
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Authorization': token,
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(SERVER_URL + '/GetPlayerPersonalShow', data=data_enc, headers=headers)

            if resp.status_code != 200:
                return None

            account_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
            account_info.ParseFromString(resp.content)
            result = json.loads(json_format.MessageToJson(account_info))

            is_banned = result.get("isBanned", False)
            if isinstance(is_banned, bool):
                result["ban_status"] = "🔴 BANNED" if is_banned else "🟢 UNBANNED"
            else:
                result["ban_status"] = "❓ UNKNOWN"

            result["region"] = REGION
            return result
    except Exception as e:
        print(f"❌ Error fetching account info: {e}")
        return None

def get_item_name(item_id):
    if not item_id or item_id == "0" or item_id == 0:
        return "N/A"
    try:
        response = httpx.get(f"https://api.danger.workers.dev/item/{item_id}", timeout=3)
        if response.status_code == 200:
            return response.json().get("name", str(item_id))
        return str(item_id)
    except:
        return str(item_id)

def get_rank_name(rp):
    try:
        rp = int(rp)
    except:
        return "N/A"
    if rp == 0: return "Bronze I"
    if rp < 100: return "Bronze II"
    if rp < 200: return "Bronze III"
    if rp < 300: return "Silver I"
    if rp < 400: return "Silver II"
    if rp < 500: return "Silver III"
    if rp < 600: return "Gold I"
    if rp < 700: return "Gold II"
    if rp < 800: return "Gold III"
    if rp < 900: return "Platinum I"
    if rp < 1000: return "Platinum II"
    if rp < 1100: return "Platinum III"
    if rp < 1200: return "Diamond I"
    if rp < 1300: return "Diamond II"
    if rp < 1400: return "Diamond III"
    if rp < 1500: return "Heroic"
    if rp < 2000: return "Master"
    return "Grandmaster"

def ts_to_bst(ts):
    try:
        dt = datetime.fromtimestamp(int(ts)) + timedelta(hours=6)
        return dt.strftime("%d %b %Y at %I:%M:%S %p") + " (BST)"
    except:
        return "N/A"


# ============================================================
#  PART 6 — Flask API Routes
# ============================================================

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "status": "running",
        "version": "OB55",
        "endpoints": {
            "token": "/token?uid=UID&password=PASS",
            "info": "/info?uid=UID&jwt=YOUR_JWT_TOKEN"
        },
        "credit": "@MHX Tools Hub"
    }), 200


@app.route("/token", methods=["GET"])
def get_jwt_token():
    uid = request.args.get("uid")
    password = request.args.get("password")

    if not uid or not password:
        return jsonify({
            "status": "error",
            "error": "Both uid and password parameters are required"
        }), 400

    try:
        token_data = generate_jwt_token(uid, password)
        resp = jsonify(token_data)
        resp.headers.add("Access-Control-Allow-Origin", "*")
        return resp, 200
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": f"Failed to generate token: {str(e)}"
        }), 500


@app.route("/info", methods=["GET", "OPTIONS"])
@app.route("/api/v1/player", methods=["GET", "OPTIONS"])
def get_full_info():
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type,Authorization")
        return response, 200

    uid = request.args.get("uid")
    jwt_token = request.args.get("jwt") # আপনি కావాలంటే এখানে সরাসরি JWT টোকেন পাস করতে পারবেন

    if not uid:
        return jsonify({"error": "UID required"}), 400

    try:
        uid_int = int(uid)
    except:
        return jsonify({"error": "Invalid UID"}), 400

    # যদি ইউজার JWT টোকেন না দেয়, তবে আপনার কোডে থাকা ডিফল্ট/স্ট্যাটিক টোকেন ব্যবহার করবে
    if not jwt_token:
        # এখানে আপনার নিজস্ব Static JWT টোকেন বসিয়ে দিতে পারেন বা আগের জেনারেট করা টোকেন ব্যবহার করতে পারেন
        jwt_token = "eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxODgyMDk5NTQyMCwibmlja25hbWUiOiJmQzF0WjNWeEtDWTllaXN5Iiwibm90aV9yZWdpb24iOiJCRCIsImxvY2tfcmVnaW9uIjoiQkDiLCJleHRlcm5hbF9pZCI6ImY1MDU3MmJjYTI5MjIzM2IyZDc2ZTQzMDI4NzhhMmU1IiwiZXh0ZXJuYWxfdHlwZSI6NCwicGxhdF9pZCI6MCwiY2xpZW50X3ZlcnNpb24iOiIiLCJjbGllbnRfdmVyc2lvbl9jb2RlOiIiLCJlbXVsYXRvcl9zY29yZSI6MTAwLCJpc19lbXVsYXRvciI6dHJ1ZSwiY291bnRyeV9jb2RlIjoiQkQiLCJleHRlcm5hbF91aWQiOjgzMjM5MzczNDcsInJlZ19hdmF0YXIiOjEwMjAwMDAwNywic291cmNlIjowLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzkyOSA2Mjg2NCwiY2xpZW50X3R5cGUiOjEsInNpZ25hdHVyZV9tZDUiOiIiLCJ1c2luZ192ZXJzaW9uIjowLCJyZWxlYXNlX2NoYW5uZWwiOiIiLCJyZWxlYXNlX3ZlcnNpb24iOiJPQjU1IiwiZXhwIjoxNzkyODY2MzYyfQ.apNOEAJyoWuK7HiCPLZG4g1WFl3HAbrA7GlKaJxg448"

    try:
        account_data = asyncio.run(GetAccountInformation(uid_int, jwt_token))
    except Exception as e:
        print(f"❌ Global error: {e}")
        account_data = None

    if not account_data:
        return jsonify({"error": "Player not found or Token expired"}), 404

    used_region = account_data.get("region", "BD")
    basic = account_data.get("basicInfo", {})
    clan = account_data.get("clanBasicInfo", {})
    social = account_data.get("socialInfo", {})
    pet = account_data.get("petInfo", {})
    captain = account_data.get("captainBasicInfo", {})
    credit = account_data.get("creditScoreInfo", {})

    prime_level = "N/A"
    try:
        prime_data = basic.get("primeLevel")
        if isinstance(prime_data, dict):
            prime_level = prime_data.get("level", "N/A")
        elif prime_data is not None:
            prime_level = str(prime_data)
    except:
        prime_level = "N/A"

    response = {
        "status": "success",
        "server_used": used_region,
        "BanStatus": account_data.get("ban_status", "❓ UNKNOWN"),
        "BasicInformation": {
            "PrimeLevel": prime_level,
            "Name": basic.get("nickname", "N/A"),
            "UID": uid,
            "Level": basic.get("level", "N/A"),
            "Exp": basic.get("exp", "N/A"),
            "Region": basic.get("region", "BD"),
            "Likes": basic.get("liked", "N/A"),
            "HonorScore": credit.get("creditScore", "N/A"),
            "CelebrityStatus": "Yes" if basic.get("showBrRank") else "No",
            "Title": get_item_name(basic.get("title", "0")),
            "Signature": social.get("signature", "N/A")
        },
        "ActivityInformation": {
            "MostRecentOB": basic.get("releaseVersion", "N/A"),
            "BooyahPass": "Yes" if basic.get("hasElitePass") else "No",
            "CurrentBpBadges": basic.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(basic.get("rankingPoints", 0)),
            "BRPoints": basic.get("rankingPoints", 0),
            "ShowBRRank": "True" if basic.get("showBrRank") else "False",
            "ShowCSRank": "True" if basic.get("showCsRank") else "False",
            "CreatedAt": ts_to_bst(basic.get("createAt", 0)),
            "LastLogin": ts_to_bst(basic.get("lastLoginAt", 0))
        },
        "GuildInformation": {
            "GuildName": clan.get("clanName", "No Guild"),
            "GuildID": clan.get("clanId", "N/A"),
            "GuildLevel": clan.get("clanLevel", "N/A"),
            "LiveMembers": clan.get("memberNum", "N/A"),
            "MaxMembers": clan.get("capacity", "N/A")
        },
        "PetDetails": {
            "Equipped": "Yes" if pet.get("isSelected") else "No",
            "PetNick": pet.get("name", "N/A"),
            "PetType": get_item_name(pet.get("id", "0")),
            "PetSkill": get_item_name(pet.get("selectedSkillId", "0")),
            "PetSkin": get_item_name(pet.get("skinId", "0")),
            "PetExp": pet.get("exp", "N/A"),
            "PetLevel": pet.get("level", "N/A")
        },
        "LeaderInformation": {
            "Name": captain.get("nickname", "N/A"),
            "UID": captain.get("accountId", "N/A"),
            "Level": captain.get("level", "N/A"),
            "Region": captain.get("region", "BD"),
            "BooyahPass": "Yes" if captain.get("hasElitePass") else "No",
            "CreatedAt": ts_to_bst(captain.get("createAt", 0)),
            "LastLogin": ts_to_bst(captain.get("lastLoginAt", 0)),
            "MostRecentOB": captain.get("releaseVersion", "N/A"),
            "Title": get_item_name(captain.get("title", "0")),
            "BpBadges": captain.get("badgeCnt", "N/A"),
            "BRRank": get_rank_name(captain.get("rankingPoints", 0)),
            "BRPoints": goal_rp if 'goal_rp' in locals() else captain.get("rankingPoints", 0)
        }
    }

    resp = jsonify(response)
    resp.headers.add("Access-Control-Allow-Origin", "*")
    return resp, 200


# ============================================================
#  ENTRY POINT
# ============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
