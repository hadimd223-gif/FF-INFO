import asyncio
import time
import httpx
import json
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from datetime import datetime, timedelta
from google.protobuf import json_format

# ============= প্রোটো ফাইল ইম্পোর্ট =============
try:
    import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
    import GetOutfit_pb2
except ImportError as e:
    pass

RELEASEVERSION = "OB55"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 14; CPH2095 Build/RKQ1.211119.001)"

MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV = b'6oyZDr22E3ychjM%'

JWT_API_BASE = "https://jwt-wxun.vercel.app/token"

BD_CREDS = {
    "uid": "8323937347", 
    "password": "BA93AC12EBD9410B9A9D21C54D4B1C5A83324F121D5CF812397F2508EB679AD8"
}

IND_CREDS = {
    "uid": "7739182267", 
    "password": "507D3250C779A4E73A74B66998E99DD4ED95A6133A07151FC0411A225C405ADD"
}

BR_CREDS = {
    "uid": "7810756496",
    "password": "507D3250C779A4E73A74B66998E99DD4ED95A6133A07151FC0411A225C405ADD"
}

ACCOUNT_CREDENTIALS = {
    "BD": BD_CREDS,
    "IND": IND_CREDS,
    "BR": BR_CREDS
}

REGION_CONFIG = {
    "BD": {"server_url": "https://clientbp.ppmainecoonghj.com", "release_version": "OB55"},
    "IND": {"server_url": "https://client.ind.freefiremobile.com", "release_version": "OB55"},
    "BR": {"server_url": "https://client.us.freefiremobile.com", "release_version": "OB55"}
}

LOGIN_URLS = {
    "BD": "https://loginbp.ppmainecoonghj.com",
    "IND": "https://loginbp.ppmainecoonghj.com",
    "BR": "https://loginbp.ppmainecoonghj.com"
}

REGION_PRIORITY = ["BD", "IND", "BR"]

app = Flask(__name__)
CORS(app)

_token_cache = {}

async def get_jwt_token_from_api(region: str):
    cred = ACCOUNT_CREDENTIALS.get(region)
    if not cred:
        return None
    url = f"{JWT_API_BASE}?uid={cred['uid']}&password={cred['password']}"
    headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                return None
            data = response.json()
            token = data.get("token")
            if not token:
                return None
            api_region = data.get("region", region)
            server_url = REGION_CONFIG.get(api_region, REGION_CONFIG["BD"])["server_url"]
            return {
                "token": f"Bearer {token}",
                "region": api_region,
                "server_url": server_url,
                "expires_at": time.time() + 25200
            }
    except Exception:
        return None

async def get_token(region: str):
    cached = _token_cache.get(region)
    if cached and cached.get('expires_at', 0) > time.time():
        return cached
    token_info = await get_jwt_token_from_api(region)
    if token_info:
        _token_cache[region] = token_info
        return token_info
    return None

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext))

async def json_to_proto(json_data: str, proto_message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

async def GetAccountInformation(uid, region):
    try:
        token_info = await get_token(region)
        if not token_info:
            return None
        actual_region = token_info.get('region', region)
        token = token_info['token']
        server_url = token_info['server_url']
        config = REGION_CONFIG.get(actual_region, REGION_CONFIG["BD"])

        payload = await json_to_proto(json.dumps({'a': uid, 'b': '7'}), main_pb2.GetPlayerPersonalShow())
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Authorization': token,
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': config['release_version']
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(server_url + '/GetPlayerPersonalShow', data=data_enc, headers=headers)
            if resp.status_code != 200:
                return None
            account_info = AccountPersonalShow_pb2.AccountPersonalShowInfo()
            account_info.ParseFromString(resp.content)
            result = json.loads(json_format.MessageToJson(account_info))
            is_banned = result.get("isBanned", False)
            result["ban_status"] = "🔴 BANNED" if is_banned else "🟢 UNBANNED"
            result["region"] = actual_region
            return result
    except Exception as e:
        print(f"Error fetching account info: {e}")
        return None

def get_item_name(item_id):
    if not item_id or item_id == "0" or item_id == 0:
        return "N/A"
    try:
        import requests
        response = requests.get(f"https://api.danger.workers.dev/item/{item_id}", timeout=2)
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
    if rp < 600: return "Gold"
    if rp < 1200: return "Platinum"
    if rp < 1500: return "Diamond"
    if rp < 2000: return "Heroic"
    return "Master"

def ts_to_bst(ts):
    try:
        dt = datetime.fromtimestamp(int(ts)) + timedelta(hours=6)
        return dt.strftime("%d %b %Y") + " (BST)"
    except:
        return "N/A"

@app.route('/info', methods=['GET'])
def get_full_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "UID required"}), 400
    try:
        uid_int = int(uid)
    except:
        return jsonify({"error": "Invalid UID"}), 400

    async def run_fetch():
        for region in REGION_PRIORITY:
            data = await GetAccountInformation(uid_int, region)
            if data:
                return data
        return None

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        account_data = loop.run_until_complete(run_fetch())
        loop.close()
    except Exception as e:
        print(f"Async loop error: {e}")
        account_data = None

    if not account_data:
        return jsonify({"error": "Player not found"}), 404

    basic = account_data.get("basicInfo", {})
    clan = account_data.get("clanBasicInfo", {})
    social = account_data.get("socialInfo", {})
    pet = account_data.get("petInfo", {})
    captain = account_data.get("captainBasicInfo", {})
    credit = account_data.get("creditScoreInfo", {})

    response = {
        "status": "success",
        "server_used": account_data.get("region", "Unknown"),
        "BanStatus": account_data.get("ban_status", "❓ UNKNOWN"),
        "BasicInformation": {
            "Name": basic.get("nickname", "N/A"),
            "UID": uid,
            "Level": basic.get("level", "N/A"),
            "Region": account_data.get("region", "N/A"),
            "Likes": basic.get("liked", "N/A"),
            "HonorScore": credit.get("creditScore", "N/A"),
            "Title": get_item_name(basic.get("title", "0")),
            "Signature": social.get("signature", "N/A")
        },
        "ActivityInformation": {
            "BRRank": get_rank_name(basic.get("rankingPoints", 0)),
            "BRPoints": basic.get("rankingPoints", 0),
            "CreatedAt": ts_to_bst(basic.get("createAt", 0)),
            "LastLogin": ts_to_bst(basic.get("lastLoginAt", 0))
        },
        "GuildInformation": {
            "GuildName": clan.get("clanName", "No Guild"),
            "GuildID": clan.get("clanId", "N/A"),
            "GuildLevel": clan.get("clanLevel", "N/A"),
            "LiveMembers": clan.get("memberNum", "N/A")
        }
    }
    return jsonify(response)

@app.route('/')
def home():
    return jsonify({"status": "running on vercel", "endpoint": "/info?uid=UID"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5004)
