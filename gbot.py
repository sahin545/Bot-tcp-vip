import threading;import jwt;import random;import json;import requests;import google.protobuf;from datetime import datetime;import base64;import logging;import re;import socket;import os;import binascii;import sys;import psutil;import time;from important_zitado import*;from time import sleep;from google.protobuf.timestamp_pb2 import Timestamp;from google.protobuf.json_format import MessageToJson;from protobuf_decoder.protobuf_decoder import Parser;from threading import Thread;from Crypto.Cipher import AES;from Crypto.Util.Padding import pad, unpad; import httpx;import urllib3; import MajorLoginRes_pb2;import psutil;import jwt_generator_pb2;import MajorLoginRes_pb2;import psutil
####################################
#FUCK SSL BY KARTIK
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
tempid = None
sent_inv = False
start_par = False
pleaseaccept = False
nameinv = "none"
idinv = 0
senthi = False
statusinfo = False
tempdata1 = None
tempdata = None
leaveee = False
leaveee1 = False
data22 = None
isroom = False
isroom2 = False
paylod_token1 = "3a07312e3131342e32aa01026172b201203535656437353966636639346638353831336535376232656338343932663563ba010134ea0140366662376664656638363538666430333137346564353531653832623731623231646238313837666130363132633865616631623633616136383766316561659a060134a2060134ca03203734323862323533646566633136343031386336303461316562626665626466"
freefire_version = "ob50"
client_secret = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
chat_ip = "202.81.108.131"
chat_port = 39698
key2 = "projects_xxx_3ei93k_codex_xdfox" # This seems like an API key, left as is.
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def encrypt_packet(plain_text, key, iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['1']

def get_player_status(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)

    if "5" not in parsed_data or "data" not in parsed_data["5"]:
        return "OFFLINE"

    json_data = parsed_data["5"]["data"]

    if "1" not in json_data or "data" not in json_data["1"]:
        return "OFFLINE"

    data = json_data["1"]["data"]

    if "3" not in data:
        return "OFFLINE"

    status_data = data["3"]

    if "data" not in status_data:
        return "OFFLINE"

    status = status_data["data"]

    if status == 1:
        return "SOLO"
    
    if status == 2:
        if "9" in data and "data" in data["9"]:
            group_count = data["9"]["data"]
            countmax1 = data["10"]["data"]
            countmax = countmax1 + 1
            return f"INSQUAD ({group_count}/{countmax})"

        return "INSQUAD"
    
    if status in [3, 5]:
        return "INGAME"
    if status == 4:
        return "IN ROOM"
    
    if status in [6, 7]:
        return "IN SOCIAL ISLAND MODE .."

    return "NOTFOUND"
def get_idroom_by_idplayer(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    idroom = data['15']["data"]
    return idroom
def get_leader(packet):
    json_result = get_available_room(packet)
    parsed_data = json.loads(json_result)
    json_data = parsed_data["5"]["data"]
    data = json_data["1"]["data"]
    leader = data['8']["data"]
    return leader
def fix_num(num):
    fixed = ""
    count = 0
    num_str = str(num)

    for char in num_str:
        if char.isdigit():
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed


def fix_word(num):
    fixed = ""
    count = 0
    
    for char in num:
        if char:
            count += 1
        fixed += char
        if count == 3:
            fixed += "[c]"
            count = 0  
    return fixed
def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number
####################################

#Clan-info-by-clan-id
def Get_clan_info(clan_id):
    try:
        url = f"https://get-clan-info.vercel.app/get_clan_info?clan_id={clan_id}"
        res = requests.get(url)
        if res.status_code == 200:
            data = res.json()
            msg = f""" 
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
▶▶▶▶GUILD DETAILS◀◀◀◀
Achievements: {data['achievements']}\n\n
Balance : {fix_num(data['balance'])}\n\n
Clan Name : {data['clan_name']}\n\n
Expire Time : {fix_num(data['guild_details']['expire_time'])}\n\n
Members Online : {fix_num(data['guild_details']['members_online'])}\n\n
Regional : {data['guild_details']['regional']}\n\n
Reward Time : {fix_num(data['guild_details']['reward_time'])}\n\n
Total Members : {fix_num(data['guild_details']['total_members'])}\n\n
ID : {fix_num(data['id'])}\n\n
Last Active : {fix_num(data['last_active'])}\n\n
Level : {fix_num(data['level'])}\n\n
Rank : {fix_num(data['rank'])}\n\n
Region : {data['region']}\n\n
Score : {fix_num(data['score'])}\n\n
Timestamp1 : {fix_num(data['timestamp1'])}\n\n
Timestamp2 : {fix_num(data['timestamp2'])}\n\n
Welcome Message: {data['welcome_message']}\n\n
XP: {fix_num(data['xp'])}\n\n
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY KARTIK
            """
            return msg
        else:
            msg = """
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Failed to get info, please try again later!!

°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY KARTIK
            """
            return msg
    except:
        pass
#GET INFO BY PLAYER ID
def get_player_info(player_id):
    url = f"https://projects-fox-apis.vercel.app/player_info?uid={player_id}&key={key}"
    response = requests.get(url)    
    if response.status_code == 200:
        try:
            r = response.json()
            return {
                "Account Booyah Pass": f"{r.get('booyah_pass_level', 'N/A')}",
                "Account Create": f"{r.get('account_creation_date', 'N/A')}",
                "Account Level": f"{r.get('level', 'N/A')}",
                "Account Likes": f" {r.get('likes', 'N/A')}",
                "Name": f"{r.get('player_name', 'N/A')}",
                "UID": f" {r.get('player_id', 'N/A')}",
                "Account Region": f"{r.get('server', 'N/A')}",
                }
        except ValueError as e:
            pass
            return {
                "error": "Invalid JSON response"
            }
    else:
        pass
        return {
            "error": f"Failed to fetch data: {response.status_code}"
        }
#CHAT WITH AI
def talk_with_ai(question):
    url = f"https://princeaiapi.vercel.app/prince/api/v1/ask?key=prince&ask={question}"
    res = requests.get(url)
    if res.status_code == 200:
        data = res.json()
        msg = data["message"]["content"]
        return msg
    else:
        return "An error occurred while connecting to the server."
#SPAM REQUESTS
def spam_requests(player_id):
    if(player_id == "1511586336" or player_id == 1511586336):
        res.status_code == 200
        return f"Don't Try on you Dad!!!!!"
    # This URL now correctly points to the Flask app you provided
    url = f"https://spam-api-five.vercel.app/send_requests?uid={player_id}"
    try:
        res = requests.get(url, timeout=20) # Added a timeout
        if res.status_code == 200:
            data = res.json()
            # Return a more descriptive message based on the API's JSON response
            return f"API Status: Success [{data.get('success_count', 0)}] Failed [{data.get('failed_count', 0)}]"
        else:
            # Return the error status from the API
            return f"API Error: Status {res.status_code}"
    except requests.exceptions.RequestException as e:
        # Handle cases where the API isn't running or is unreachable
        print(f"Could not connect to spam API: {e}")
        return "Failed to connect to spam API."
####################################

# ** CORRECTED newinfo FUNCTION **
def newinfo(uid):
    # Base URL without parameters
    url = f"https://team-xzy-ujjaiwal.vercel.app/player-info?uid={uid}&region=ind"
    # Parameters dictionary - this is the robust way to do it
    
    # Commented this ################################
    # params = {
    #     'uid': uid,
    #     'region': 'IND'  # Hardcoded to IND as requested
    # }
    try:
        # Pass the parameters to requests.get()
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if "basic_info" in data:
                return {"status": "ok", "data": data}
            else:
                return {"status": "error", "message": "Invalid ID or data not found."}
        else:
            try:
                error_msg = response.json().get('error', f"API returned status {response.status_code}")
                return {"status": "error", "message": error_msg}
            except ValueError:
                return {"status": "error", "message": f"API returned status {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": f"Network error: {str(e)}"}
    except ValueError: 
        return {"status": "error", "message": "Invalid JSON response from API."}
	
#ADDING-100-LIKES-IN-24H
import requests

def send_likes(uid, sender_name):
    try:
        # Attempt to connect to the local likes API
        likes_api_response = requests.get(
            f"https://delicate-corly-kartik220803-87560153.koyeb.app/like?uid={uid}&server_name=IND",
            timeout=15 # Add a timeout to prevent it from hanging
        )
        
        # Check if the API request was successful
        if likes_api_response.status_code == 200:
            api_json_response = likes_api_response.json()
            
            # ^Internal like API Status
            like_api_status = api_json_response.get('status', 'N/A')

            # Use the correct key 'LikesGivenByAPI_ThisRun' to check if likes were given
            # Also use the CORRECT keys with capital 'B' and 'A' for before/after
            player_name = api_json_response.get('PlayerNickname', 0)
            likes_before = api_json_response.get('LikesbeforeCommand', 0)
            likes_after = api_json_response.get('LikesafterCommand', 0)
            likes_added = api_json_response.get('LikesGivenByAPI', 0)

            print("types of likes_added:", type(likes_added), "\n")
            print("value of likes added:", likes_added)
            
            if likes_added > 0:
                # Success! Likes were added.
                message = f"""
[C][B][11EAFD]‎━━━━━━━━━━━━
[FFFFFF]Likes Status:

[00FF00]Likes Sent Successfully!

[FFFFFF]Player Name : [00FF00]{player_name}  
[FFFFFF]Likes Added : [00FF00]{likes_added}  
[FFFFFF]Likes Before : [00FF00]{likes_before}  
[FFFFFF]Likes After : [00FF00]{likes_after}  
[FFFFFF]Command Used by : [00FF00]{sender_name}  
[C][B][11EAFD]‎━━━━━━━━━━━━
[C][B][FFB300]Credits: [FFFFFF]KARTIK [00FF00]BOT!!
                """
            # ^old one-> else:
            if like_api_status ==2 or likes_added == 0:
                # This handles cases where likes were not added (e.g., daily limit, invalid ID)
                message = f"""
[C][B][FF0000]‎━━━━━━━━━━━━
[FF0000]Could not add likes!

[FFFFFF]You have already used your Daily Likes Limit
[FFFFFF]Command Used by : [00FF00]{sender_name}

[C][B][FF0000]‎━━━━━━━━━━━━
[C][B][FFB300]Credits: [FFFFFF]KARTIK [00FF00]BOT!!
                """

        else:
            # Handle cases where the API itself gives an error (e.g., 500, 404)
            message = (f"""
[C][B][FF0000]━━━━━
[FFFFFF]Like API Error!
Status Code: {likes_api_response.status_code}
Please check if the API is running correctly.
[FF0000]━━━━━
""")
                
        return message

    except requests.exceptions.RequestException:
        # Handle network errors (e.g., API is not running at all)
        return ("""
[C][B][FF0000]━━━━━
[FFFFFF]Like API Connection Failed!
Please TRY AGAIN in 2 minutes!!
[FF0000]━━━━━
""")
#         return ("""
# [C][B][FF0000]━━━━━
# [FFFFFF]Like API Connection Failed!
# Is the API server (app.py) running?
# [FF0000]━━━━━
# """)
    except Exception as e:
        # Catch any other unexpected errors
        return f"[FF0000]An unexpected error occurred: {str(e)}"
####################################
#CHECK ACCOUNT IS BANNED
def check_banned_status(player_id):
    url = f"http://amin-team-api.vercel.app/check_banned?player_id={player_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data  
        else:
            return {"error": f"Failed to fetch data. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}
####################################
def Encrypt(number):
    try:
        number = int(number)
        encoded_bytes = []
        while True:
            byte = number & 0x7F
            number >>= 7
            if number:
                byte |= 0x80
            encoded_bytes.append(byte)
            if not number:
                break
        return bytes(encoded_bytes).hex()
    except:
        restart_program()
#############CLASS RANDOM###########
def  generate_random_word():
    word_list = [
        "XNXXX", "ZBI", "RONAK", "NIKMOK",
        "PUSSY", "FUCK YOU", "fuke_any_team", "FUCK_YOUR_MOM", "PORNO",
        "FUCK YOUR MOTHER", "FUCK_YOUR_SISTER", "MOROCCO", "kissss omkk", "YOUR_MOM_PINK_PUSSY",
        "WAAA DAK W9", "ZAMLLL", "YANA9CH", "9WAD", "YOUR_ASS_IS_BIG",
        "PUSSY", "I_FUCK_YOU", "SIT_DOWN_PIMP", "AHHH", "DIMA RAJA",
        "FAILED_STREAMER", "RONAK", "GAY", "YOUR_ASS_IS_PINK", "YOUR_PUSSY_IS_BEAUTIFUL",
        "HAHAHAHAHAHA", "YOUR_PUSSY_IS_PINK", "I_WILL_FUCK_YOU", "EAT_IT_PIMP", "HEY_BITCH",
        "MY_DICK", "STRONG_PUSSY", "PUSSY", "GO_FUCK_YOURSELF", "LOSER",
        "HEY_WHORE", "MY_BITCH", "PUSSY", "FUCK_YOU_UP", "YOUR_PUSSY",
        "LOSER", "FUCK_YOU", "FUCK_YOUR_MOM_SLANG", "FUCK_YOUR_MOM_SLANG2", "I_WILL_JERK_OFF_ON_YOU", "LICKER", " RONAK", "TELEGRAM:@S_DD_F"
    ]

    return random.choice(word_list)
def generate_random_color():
	color_list = [
    "[00FF00][b][c]", # Green
    "[FFDD00][b][c]", # Yellow
    "[3813F3][b][c]", # Blue
    "[FF0000][b][c]", # Red
    "[0000FF][b][c]", # Dark Blue
    "[FFA500][b][c]", # Orange
    "[DF07F8][b][c]", # Purple/Magenta
    "[11EAFD][b][c]", # Light Blue/Cyan
    "[DCE775][b][c]", # Light Green/Lime
    "[A8E6CF][b][c]", # Mint Green
    "[7CB342][b][c]", # Olive Green
    "[FF0000][b][c]", # Red (duplicate)
    "[FFB300][b][c]", # Amber/Orange
    "[90EE90][b][c]", # Light Green
    "[FF4500][b][c]", # Orange Red
    "[FFD700][b][c]", # Gold
    "[32CD32][b][c]", # Lime Green
    "[87CEEB][b][c]", # Sky Blue
    "[9370DB][b][c]", # Medium Purple
    "[FF69B4][b][c]", # Hot Pink
    "[8A2BE2][b][c]", # Blue Violet
    "[00BFFF][b][c]", # Deep Sky Blue
    "[1E90FF][b][c]", # Dodger Blue
    "[20B2AA][b][c]", # Light Sea Green
    "[00FA9A][b][c]", # Medium Spring Green
    "[008000][b][c]", # Green (dark)
    "[FFFF00][b][c]", # Yellow (bright)
    "[FF8C00][b][c]", # Dark Orange
    "[DC143C][b][c]", # Crimson
    "[FF6347][b][c]", # Tomato
    "[FFA07A][b][c]", # Light Salmon
    "[FFDAB9][b][c]", # Peach Puff
    "[CD853F][b][c]", # Peru
    "[D2691E][b][c]", # Chocolate
    "[BC8F8F][b][c]", # Rosy Brown
    "[F0E68C][b][c]", # Khaki
    "[556B2F][b][c]", # Dark Olive Green
    "[808000][b][c]", # Olive
    "[4682B4][b][c]", # Steel Blue
    "[6A5ACD][b][c]", # Slate Blue
    "[7B68EE][b][c]", # Medium Slate Blue
    "[8B4513][b][c]", # Saddle Brown
    "[C71585][b][c]", # Medium Violet Red
    "[4B0082][b][c]", # Indigo
    "[B22222][b][c]", # Fire Brick
    "[228B22][b][c]", # Forest Green
    "[8B008B][b][c]", # Dark Magenta
    "[483D8B][b][c]", # Dark Slate Blue
    "[556B2F][b][c]", # Dark Olive Green (duplicate)
    "[800000][b][c]", # Maroon
    "[008080][b][c]", # Teal
    "[000080][b][c]", # Navy
    "[800080][b][c]", # Purple
    "[808080][b][c]", # Gray
    "[A9A9A9][b][c]", # Dark Gray
    "[D3D3D3][b][c]", # Light Gray
    "[F0F0F0][b][c]"  # Light Gray (almost white)
]
	random_color = random.choice(color_list)
	return  random_color
def get_random_avatar():
    avatar_list = [
        '902000061', '902000060', '902000064', '902000065', '902000066', 
        '902000074', '902000075', '902000077', '902000078', '902000084', 
        '902000085', '902000087', '902000091', '902000094', '902000306','902000091','902000208','902000209','902000210','902000211','902047016','902047016','902000347'
    ]
    return random.choice(avatar_list)
def rrrrrrrrrrrrrr(number):
    if isinstance(number, str) and '***' in number:
        return number.replace('***', '106')
    return number
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))

        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break           
#GET AVAILABLE ROOM
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
#PARSE RESULTS
def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data["wire_type"] = result.wire_type
        if result.wire_type == "varint":
            field_data["data"] = result.data
        if result.wire_type == "string":
            field_data["data"] = result.data
        if result.wire_type == "bytes":
            field_data["data"] = result.data
        elif result.wire_type == "length_delimited":
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict
#DECODE TO HEX
def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
    return final_result
#ENCODE MESSAGE
def encrypt_message(plaintext):
    key = b'Yg&tc%DEuh6%Zc^8'
    iv = b'6oyZDr22E3ychjM%'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')
#ENCODE API
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
####################################
def extract_jwt_from_hex(hex):
    byte_data = binascii.unhexlify(hex)
    message = jwt_generator_pb2.Garena_420()
    message.ParseFromString(byte_data)
    json_output = MessageToJson(message)
    token_data = json.loads(json_output)
    return token_data
def format_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
####################################
def restart_program():
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = psutil.net_connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception:
            pass            
    for conn in connections:
        try:
            conn.close()
        except Exception:
            pass
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)
#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.get_tok()

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            if isinstance(key, bytes):
                key = key.hex()
            if isinstance(iv, bytes):
                iv = iv.hex()
            self.key = key
            self.iv = iv
            print(f"Key: {self.key} | IV: {self.iv}")
            return self.key, self.iv
        except Exception as e:
            print(f"{e}")
            return None, None

    def nmnmmmmn(self, data):
        key, iv = self.key, self.iv
        try:
            key = key if isinstance(key, bytes) else bytes.fromhex(key)
            iv = iv if isinstance(iv, bytes) else bytes.fromhex(iv)
            data = bytes.fromhex(data)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            cipher_text = cipher.encrypt(pad(data, AES.block_size))
            return cipher_text.hex()
        except Exception as e:
            print(f"Error in nmnmmmmn: {e}")

    def spam_room(self, idroom, idplayer):
        fields = {
        1: 78,
        2: {
            1: int(idroom),
            2: f"{generate_random_color()}{generate_random_word()}",
            4: 330,
            5: 6000,
            6: 201,
            10: int(get_random_avatar()),
            11: int(idplayer),
            12: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def send_squad(self, idplayer):
        fields = {
            1: 33,
            2: {
                1: int(idplayer),
                2: "IND",
                3: 1,
                4: 1,
                7: 330,
                8: 19459,
                9: 100,
                12: 1,
                16: 1,
                17: {
                2: 94,
                6: 11,
                8: "1.109.5",
                9: 3,
                10: 2
                },
                18: 201,
                23: {
                2: 1,
                3: 1
                },
                24: int(get_random_avatar()),
                26: {},
                28: {}
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def start_autooo(self):
        fields = {
        1: 9,
        2: {
            1: 10853443433
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def invite_skwad(self, idplayer):
        fields = {
        1: 2,
        2: {
            1: int(idplayer),
            10: int(get_random_avatar()),
            2: "IND",
            4: 1
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def request_skwad(self, idplayer):
        fields = {
        1: 33,
        2: {
            1: int(idplayer),
            2: "IND",
            3: 1,
            4: 1,
            7: 330,
            8: 19459,
            9: 100,
            12: 1,
            16: 1,
            17: {
            2: 94,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            18: 201,
            23: {
            2: 1,
            3: 1
            },
            24: int(get_random_avatar()),
            26: {},
            28: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def skwad_maker(self):
        fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def changes(self, num):
        fields = {
        1: 17,
        2: {
            1: 11516784163,
            2: 1,
            3: int(num),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
   
    def leave_s(self):
        fields = {
        1: 7,
        2: {
            1: 10853443433
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def leave_room(self, idroom):
        fields = {
        1: 6,
        2: {
            1: int(idroom)
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def stauts_infoo(self, idd):
        fields = {
        1: 7,
        2: {
            1: 10853443433
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)






    def GenResponsMsg(self, Msg):
        fields = {
        1: 1,
        2: {
            1: 13527374106,#bot account id
            2: 3086579607,#clan id
            3: 1,
            4: str(Msg),
            5: int(datetime.now().timestamp()),
            9: {
            1: "fo",
            2: int(get_random_avatar()),
            4: 330,
            8: "OK",
            10: 1,
            11: 1
            },
            10: "en",
            13: {
            1: "https://lh3.googleusercontent.com/a/ACg8ocL7eKRT-gDmquqmXjHGRbWqFBQmcNgB_nTfeicGt61c-PndxQ=s96-c",
            2: 1,
            3: 1
            },
            14: {}
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def createpacketinfo(self, idddd):
        ida = Encrypt(idddd)
        packet = f"080112090A05{ida}1005"
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0F15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0F1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0F150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0F15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

        
                
                        
                                
                                                
    def accept_sq(self, hashteam, idplayer, ownerr):
        fields = {
        1: 4,
        2: {
            1: int(ownerr),
            3: int(idplayer),
            4: "\u0001\u0007\t\n\u0012\u0019\u001a ",
            8: 1,
            9: {
            2: 1393,
            4: "wW_T",
            6: 11,
            8: "1.109.5",
            9: 3,
            10: 2
            },
            10: hashteam,
            12: 1,
            13: "en",
            16: "OR"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0515000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "051500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "05150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0515000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)
    def info_room(self, idrooom):
        fields = {
        1: 1,
        2: {
            1: int(idrooom),
            3: {},
            4: 1,
            6: "en"
        }
        }

        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "0E15000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "0E1500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "0E150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "0E15000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

        
                
                                
    def joinclanchat(self):
        fields = {
            1: 3,
            2: {
                1: 3086579607,#clan id
                2: 1,
                4: str("fzREhry0f0dxI1yfg/Q1nw"),#clan key
            }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)




    def joinclanchat1(self):
        fields = {
        1: 3,
        2: {
            2: 5,
            3: "en"
        }
        }
        packet = create_protobuf_packet(fields)
        packet = packet.hex()
        header_lenth = len(encrypt_packet(packet, key, iv))//2
        header_lenth_final = dec_to_hex(header_lenth)
        if len(header_lenth_final) == 2:
            final_packet = "1215000000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 3:
            final_packet = "121500000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 4:
            final_packet = "12150000" + header_lenth_final + self.nmnmmmmn(packet)
        elif len(header_lenth_final) == 5:
            final_packet = "1215000" + header_lenth_final + self.nmnmmmmn(packet)
        return bytes.fromhex(final_packet)

    def sockf1(self, tok, host, port, packet, key, iv):
        global socket_client
        global sent_inv
        global tempid
        global start_par
        global clients
        global pleaseaccept
        global tempdata1
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global data22
        global leaveee
        global isroom
        global isroom2
        socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)

        socket_client.connect((host,port))
        print(f" Con port {port} Host {host} ")
        print(tok)
        socket_client.send(bytes.fromhex(tok))
        while True:
            data2 = socket_client.recv(9999)
            print(data2)
            if "0500" in data2.hex()[0:4] and len(data2.hex()) > 30:
                if sent_inv == True:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    print(accept_packet)
                    print(tempid)
                    aa = gethashteam(accept_packet)
                    ownerid = getownteam(accept_packet)
                    print(ownerid)
                    print(aa)
                    ss = self.accept_sq(aa, tempid, int(ownerid))
                    socket_client.send(ss)
                    sleep(1)
                    startauto = self.start_autooo()
                    socket_client.send(startauto)
                    start_par = False
                    sent_inv = False
            if data2 == b"":                
                print("Connection closed by remote host")
#                restart_program()

            if "0600" in data2.hex()[0:4] and len(data2.hex()) > 700:
                    accept_packet = f'08{data2.hex().split("08", 1)[1]}'
                    kk = get_available_room(accept_packet)
                    parsed_data = json.loads(kk)
                    print(parsed_data)
                    idinv = parsed_data["5"]["data"]["1"]["data"]
                    nameinv = parsed_data["5"]["data"]["3"]["data"]
                    senthi = True
            if "0f00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                
                asdj = parsed_data["2"]["data"]
                tempdata = get_player_status(packett)
                if asdj == 15:
                    if tempdata == "-OFFLINE":
                        tempdata = f"-THE ID IS {tempdata}"
                    else:
                        idplayer = parsed_data["5"]["data"]["1"]["data"]["1"]["data"]
                        idplayer1 = fix_num(idplayer)
                        if tempdata == "IN ROOM":
                            idrooom = get_idroom_by_idplayer(packett)
                            idrooom1 = fix_num(idrooom)
                            
                            tempdata = f"-ID : {idplayer1}\nstatus : {tempdata}\n-ID ROOM : {idrooom1}"
                            data22 = packett
                            print(data22)
                            
                        if "INSQUAD" in tempdata:
                            idleader = get_leader(packett)
                            idleader1 = fix_num(idleader)
                            tempdata = f"-ID : {idplayer1}\n-STATUS : {tempdata}\n-LEADEER ID : {idleader1}"
                        else:
                            tempdata = f"-ID : {idplayer1}\n-STATUS : {tempdata}"
                    statusinfo = True 

                    print(data2.hex())
                    print(tempdata)
                
                    

                else:
                    pass
            if "0e00" in data2.hex()[0:4]:
                packett = f'08{data2.hex().split("08", 1)[1]}'
                print(packett)
                kk = get_available_room(packett)
                parsed_data = json.loads(kk)
                idplayer1 = fix_num(idplayer)
                asdj = parsed_data["2"]["data"]
                tempdata1 = get_player_status(packett)
                if asdj == 14:
                    nameroom = parsed_data["5"]["data"]["1"]["data"]["2"]["data"]
                    
                    maxplayer = parsed_data["5"]["data"]["1"]["data"]["7"]["data"]
                    maxplayer1 = fix_num(maxplayer)
                    nowplayer = parsed_data["5"]["data"]["1"]["data"]["6"]["data"]
                    nowplayer1 = fix_num(nowplayer)
                    tempdata1 = f"{tempdata}\nRoom name : {nameroom}\nMax player : {maxplayer1}\nLive player : {nowplayer1}"
                    print(tempdata1)
                    

                    
                
                    
            if data2 == b"":
                
                print("Connection closed by remote host")
                restart_program()
                break
#━━━━━━━━━━━━━━━━━━━
    def connect(self, tok, host, port, packet, key, iv):
        global clients
        global socket_client
        global sent_inv
        global tempid
        global leaveee
        global start_par
        global nameinv
        global idinv
        global senthi
        global statusinfo
        global tempdata
        global pleaseaccept
        global tempdata1
        global data22
        clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        port = int(port)
        clients.connect((host, port))
        clients.send(bytes.fromhex(tok))
        thread = threading.Thread(
            target=self.sockf1, args=(tok, chat_ip, chat_port, "anything", key, iv)
        )
        threads.append(thread)
        thread.start()        
        clients.send(self.joinclanchat())
        while True:
            data = clients.recv(9999)
            if data == b"":
                print("Connection closed by remote host")
                break
                print(f"Received data: {data}")
            
            if senthi == True:
                
                clients.send(
                        self.GenResponsMsg(
                            f"""[C][B]Hello, thanks for accepting the friend request. Send an emoji to know what to do."""
                        )
                )
                senthi = False            
            if "1200" in data.hex()[0:4]:               
                json_result = get_available_room(data.hex()[10:])
                print(data.hex())
                parsed_data = json.loads(json_result)
                uid = parsed_data["5"]["data"]["1"]["data"]
                if "8" in parsed_data["5"]["data"] and "data" in parsed_data["5"]["data"]["8"]:
                    uexmojiii = parsed_data["5"]["data"]["8"]["data"]
                    if uexmojiii == "DefaultMessageWithKey":
                        pass
                    else:
                        clients.send(
                            self.GenResponsMsg(
                                f"""[C][B]
Welcome to [00ff00]KARTIK'S BOT[ffffff]!

[C][B]
To see the commands, just send: [00ff00]🗿/help🗿[ffffff]

[C][B]
Enjoy the bot!
"""
                            )
                        )
                else:
                    pass
####################################
            #SEND SKWAD 5 TO ID ->> COMMAND
# ... inside the connect method ...

            #SEND SKWAD 5 TO ID ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/snd/" in data:
                try:
                    message = data.decode('utf-8', errors='ignore')
                    unwanted_chars = ["(J,", "(J@", "(", ")", "@", ","]
                    cleaned_message = message
                    for char in unwanted_chars:
                        cleaned_message = cleaned_message.replace(char, "")
                    
                    try:
                        message_parts = cleaned_message.split()
                        iddd = None
                        for part in message_parts:
                            if '/snd/' in part:
                                digits = ''.join(filter(str.isdigit, part.split('/snd/')[1]))
                                if digits:
                                    iddd = int(digits)
                                    break
                        if iddd is None:
                            iddd = 10414593349
                    except:
                        iddd = 10414593349
                    
                    packetfinal = self.changes(4)
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)
                    sleep(1)
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    iddd = fix_num(iddd)
                    
                    # --- FIX IS HERE ---
                    # Removed the extra 'uid' argument from the function call
                    clients.send(self.GenResponsMsg(f"""
                [11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
6-Man Squad opened for player:
 {iddd}
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY KARTIK
            """))
            
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee)
                except Exception as e:
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]

                        # --- FIX IS HERE ---
                        # Removed the extra 'uid' argument from this call as well
                        clients.send(self.GenResponsMsg("[FF0000][b]❗ An error occurred in the process.[/b]"))

                    except:
                        restart_program()
####################################
            #MAKE SKWAD 3 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/3s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)             
                sleep(1)
                packetfinal = self.changes(2)
                iddd=parsed_data["5"]["data"]["1"]["data"]
                socket_client.send(packetfinal)
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if iddd:
                    clients.send(
                        self.GenResponsMsg(
                            f"""
    [11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
 Accept the request quickly!!!
    
  °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
  [FFB300][b][c]BOT MADE BY KARTIK
                            """
                        )
                    )
                sleep(5)
                leavee = self.leave_s()
                socket_client.send(leavee)   
            #MAKE SKWAD 4 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/4s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)

                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)             
                sleep(1)
                packetfinal = self.changes(3)
                iddd=parsed_data["5"]["data"]["1"]["data"]
                socket_client.send(packetfinal)
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if iddd:
                    clients.send(
                        self.GenResponsMsg(
                            f"""
    [11EAFD][b][c]
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    Accept the request FAST!!!
    
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    [FFB300][b][c]BOT MADE BY KARTIK
                            """
                        )
                    )
                sleep(5)
                leavee = self.leave_s()
                socket_client.send(leavee) 
            #MAKE SKWAD 5 ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/5s" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                
                packetmaker = self.skwad_maker()
                socket_client.send(packetmaker)             
                sleep(1)
                packetfinal = self.changes(4)
                iddd=parsed_data["5"]["data"]["1"]["data"]
                socket_client.send(packetfinal)
                invitess = self.invite_skwad(iddd)
                socket_client.send(invitess)
                if iddd:
                    clients.send(
                        self.GenResponsMsg(
                            f"""
    [11EAFD][b][c]
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    Accept the request FAST!!!
    
    °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
    [FFB300][b][c]BOT MADE BY KARTIK
                            """
                        )
                    )
                sleep(5)
                leavee = self.leave_s()
                socket_client.send(leavee) 
               #MAKE SKWAD 6 ->> COMMAND
# ... inside the connect method's while True loop ...

            #MAKE SKWAD 6 ->> COMMAND (Corrected Version)
            if "1200" in data.hex()[0:4] and b"/6s" in data:
                try: # Added a try/except block for safety
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)             
                    sleep(1)
                    packetfinal = self.changes(5)
                    iddd=parsed_data["5"]["data"]["1"]["data"]
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    if iddd:
                        # --- THE FIX IS HERE ---
                        # The extra 'iddd' argument has been removed from the call.
                        clients.send(
                            self.GenResponsMsg(
                                f"""
    [11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Accept the request FAST!!!
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY KARTIK
                                """
                            )
                        )
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee)
                except Exception as e:
                    print(f"Error in /6s command handler: {e}")
####################################
            # GET PLAYER COMMAND
            if "1200" in data.hex()[0:4] and b"/inv/" in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "10414593349"
                    iddd = default_id
                    
                    try:
                        import re
                        # Search for the /inv/ pattern followed by numbers
                        id_match = re.search(r'/inv/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            iddd = id_match.group(1)
                             
                            if not (5 <= len(iddd) <= 15) or not iddd.isdigit():
                                iddd = default_id
                        else:
                             
                            temp_id = cleaned_message.split('/inv/')[1].split()[0].strip()
                            iddd = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                        
                        # Handle special characters
                        iddd = iddd.replace("***", "106") if "***" in iddd else iddd
                        
                    except Exception as e:
                        print(f"Player ID extraction error: {e}")
                        iddd = default_id
            
                    
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    numsc = 5
                    packetmaker = self.skwad_maker()
                    socket_client.send(packetmaker)
                    sleep(1)
                    packetfinal = self.changes(numsc)
                    socket_client.send(packetfinal)
                    invitess = self.invite_skwad(iddd)
                    socket_client.send(invitess)
                    invitessa = self.invite_skwad(uid)
                    socket_client.send(invitessa)
                    
                    clients.send(self.GenResponsMsg(f"""
[11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Accept the request quickly!!!
 °°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY KARTIK
                """))
                    
                    sleep(9)
                    leavee = self.leave_s()
                    socket_client.send(leavee)
            
                except Exception as e:
                    print(f"Get Player Command Error: {e}")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: {e}" if "ID" in str(e) else f"[FF0000]Error getting player: {e}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        restart_program()

            # SPAM JOIN SKWAD COMMAND
            if "1200" in data.hex()[0:4] and b"/sm/" in data:
                try:
                    
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                   
                    default_id = 10414593349
                    iddd = default_id
                    
                    try:
                        import re
                        
                        id_match = re.search(r'/sm/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            iddd = int(id_match.group(1))
                            
                            if not (5 <= len(str(iddd)) <= 15):
                                iddd = default_id
                        else:
                            
                            temp_id = cleaned_message.split('/sm/')[1].split()[0].strip()
                            iddd = int(temp_id) if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as e:
                        print(f"Spam ID extraction error: {e}")
                        iddd = default_id
            
                    
                    json_result = get_available_room(data.hex()[10:])
                    invskwad = self.request_skwad(iddd)
                    socket_client.send(invskwad)
                    parsed_data = json.loads(json_result)
                    
                   
                    for _ in range(30):
                        socket_client.send(invskwad)
                    
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    iddd_display = fix_num(iddd)
                    clients.send(self.GenResponsMsg(f"""
[11EAFD][b][c]
━━━━━
Join request spam has started for player:
{iddd_display}
━━━━━━
[808080][B][C]Credits: KARTIK
            """))
                    
                    sleep(5)
                    leavee = self.leave_s()
                    socket_client.send(leavee)
            
                except Exception as e:
                    print(f"Spam Command Error: {e}")
                    restart_program()

            # PLAYER STATUS COMMAND
            if "1200" in data.hex()[0:4] and b"/status/" in data:
                try:
                    
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    
                    default_id = "10414593349"
                    player_id = default_id
                    
                    try:
                        
                        import re
                        id_match = re.search(r'/status/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            player_id = id_match.group(1)
                            
                            if not (5 <= len(player_id) <= 15) or not player_id.isdigit():
                                player_id = default_id
                        else:
                            
                            temp_id = cleaned_message.split('/status/')[1].split()[0].strip()
                           
                            temp_id = temp_id.replace("***", "106") if "***" in temp_id else temp_id
                            player_id = temp_id if temp_id.isdigit() and len(temp_id) >= 5 else default_id
                            
                    except Exception as extract_error:
                        print(f"ID extraction error: {extract_error}")
                        player_id = default_id
            
                    
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)

                    packetmaker = self.createpacketinfo(player_id)
                    socket_client.send(packetmaker)
                    sleep(1)                
                    if statusinfo:
                        status_msg = f"[b][C][00FFFF]{tempdata}"
                        clients.send(self.GenResponsMsg(status_msg))
                        
                except Exception as e:
                    print(f"Player Status Command Error: {e}")
                    try:
                        
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error processing status request"
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        restart_program()

####################################
            #CHECK ID ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/check/" in data:
                try:
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    print(f"\nRaw Message: {raw_message}\nCleaned Message: {cleaned_message}\n")
                    import re
                    id_match = re.search(r'/check/(\d{5,15})\b', cleaned_message)                    
                    if not id_match:
                        id_match = re.search(r'/check/([0-9]+)', cleaned_message)                    
                    if id_match:
                        player_id = id_match.group(1)
                        print(f"Extracted Player ID: {player_id}")
                        if not (5 <= len(player_id) <= 15):
                            raise ValueError("Invalid ID length (5-15 digits required)")
                    else:
                        raise ValueError("No valid player ID found in message")
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)

                    clients.send(self.GenResponsMsg("Okay Sir, Please Wait.."))
                    banned_status = check_banned_status(player_id)
                    player_id_fixed = fix_num(player_id)
                    status = banned_status.get('status', 'Unknown')
                    player_name = banned_status.get('player_name', 'N/A')
                    response_message = f"""
 [11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Player Name: {player_name}
Player ID : {player_id_fixed}
Status: {status}
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY KARTIK
                """
                    clients.send(self.GenResponsMsg(response_message))
                except Exception as e:
                    print(f"\nProcessing Error: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: Failed to process command - {e}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except Exception as inner_e:
                        print(f"\nCritical Error: {inner_e}\n")
                        restart_program()
####################################
            #GET ID REGION ->> COMMAND
            if "1200" in data.hex()[0:4] and b"/region/" in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    print(f"\nRaw Message: {raw_message}\nCleaned Message: {cleaned_message}\n")
            
                    # Extract ID using regex
                    import re
                    id_match = re.search(r'/region/(\d{5,15})\b', cleaned_message)
                    
                    if not id_match:
                        # Alternative attempt if the first one fails
                        id_match = re.search(r'/region/(\d+)', cleaned_message)
                    
                    if id_match:
                        player_id = id_match.group(1)
                        print(f"Extracted Player ID: {player_id}")
                        
                        # Check ID length
                        if not (5 <= len(player_id) <= 15):
                            raise ValueError("ID length must be between 5-15 digits")
                    else:
                        raise ValueError("No valid player ID found in the message")
            
                    # Continue with the rest of the operations
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)

                    clients.send(self.GenResponsMsg("Processing..."))
                    
                    b = get_player_info(player_id)
                    player_id_fixed = fix_num(player_id)
                    response_message = f"""
                [11EAFD][b][c]
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
Player Name : {b.get('Name', 'N/A')}
Player ID : {player_id_fixed}
Player Region : {b.get('Account Region', 'N/A')}
°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°°
[FFB300][b][c]BOT MADE BY KARTIK
                """
                    clients.send(self.GenResponsMsg(response_message))
            
                except Exception as e:
                    print(f"\nError: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: {e}" if "ID" in str(e) else f"[FF0000]Processing error: {e}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except Exception as inner_e:
                        print(f"\nCritical Error: {inner_e}\n")
                        restart_program()
                        
               # SPAM FRIEND REQUESTS COMMAND (Modified with local API)
            if "1200" in data.hex()[0:4] and b"/spm/" in data:
                try:
                    # --- Robustly extract the Player ID ---
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    default_id = "10414593349"  # Default if extraction fails
                    player_id = default_id

                    # Use regex to find the ID pattern /spm/ followed by digits
                    id_match = re.search(r'/spm/(\d{5,15})\b', cleaned_message)
                    if id_match:
                        player_id = id_match.group(1)
                    else:
                        # Fallback for IDs without clear separators
                        parts = cleaned_message.split('/spm/')
                        if len(parts) > 1:
                            temp_id = parts[1].split()[0].strip()
                            if temp_id.isdigit() and 5 <= len(temp_id) <= 15:
                                player_id = temp_id

                    clients.send(self.GenResponsMsg(f"[FFB300]Contacting Spam API for UID: {player_id}..."))

                    # --- Call your local SPAM API ---
                    response_message = ""
                    try:
                        if player_id == "1511586336" or player_id == 1511586336:
                            response_message = f"[FF0000]Stay Away from your Dad!!!!"
                            clients.send(self.GenResponsMsg(response_message))
                            return
                        api_url = f"https://spam-api-five.vercel.app/send_requests?uid={player_id}"
                        response = requests.get(api_url, timeout=25) # Timeout of 25 seconds

                        if response.status_code == 200:
                            api_data = response.json()
                            success_count = api_data.get("success_count", 0)
                            failed_count = api_data.get("failed_count", 0)
                            
                            response_message = f"""
[C][B][11EAFD]‎━━━━━━
[FFFFFF]Spam Request API Response:

[00FF00]Successful Requests: {success_count}
[FF0000]Failed Requests: {failed_count}

[FFFFFF]Target UID: {fix_num(player_id)}
[C][B][11EAFD]‎━━━━━━
[C][B][FFB300]BOT BY KARTIK
"""
                        else:
                            response_message = f"[FF0000]Error: Spam API returned status code {response.status_code}."

                    except requests.exceptions.RequestException as api_error:
                        # This catches network errors if the API is offline
                        print(f"SPAM API connection error: {api_error}")
                        response_message = "[FF0000]Error: Could not connect to the local spam API. Make sure it is running on port 5002."

                    # Send the final result back to the chat
                    clients.send(self.GenResponsMsg(response_message))

                except Exception as e:
                    # This is the final catch-all for any other unexpected errors
                    print(f"\nCRITICAL Processing Error in /spm/ handler: {e}\n")
                    try:
                        # Attempt to notify the user before restarting
                        error_msg = f"[FF0000]A critical error occurred: {str(e)}. The bot will now restart."
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        # If sending the message also fails, just print and restart
                        print("Failed to send the final error message.")
                    finally:
                        # As requested, restart the program on critical failure
                        restart_program()
            # AI COMMAND
            if "1200" in data.hex()[0:4] and b"/ai" in data:
                try:
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    clients.send(self.GenResponsMsg("Connecting to AI..."))
                    
                    # Extract the question more robustly
                    try:
                        raw_message = data.decode('utf-8', errors='ignore').replace('\x00', '')
                        question_part = raw_message.split('/ai')[1]
                        
                        # Clean the question from unwanted characters
                        unwanted_chars = ["***", "\\x", "\x00"]
                        cleaned_question = question_part
                        for char in unwanted_chars:
                            cleaned_question = cleaned_question.replace(char, "")
                            
                        question = cleaned_question.strip()
                        if not question:
                            raise ValueError("No question provided")
                            
                        # Replace *** with a default value
                        question = question.replace("***", "106") if "***" in question else question
                        
                        ai_msg = talk_with_ai(question)
                        clients.send(self.GenResponsMsg(ai_msg))
                    except Exception as ai_error:
                        print(f"AI Processing Error: {ai_error}")
                        restart_program()
            
                except Exception as e:
                    print(f"AI Command Error: {e}")
                    restart_program()

            # CLAN INFO COMMAND
            if "1200" in data.hex()[0:4] and b"/clan/" in data:
                try:
                     
                    raw_message = data.decode('utf-8', errors='ignore')
                    cleaned_message = raw_message.replace('\x00', '').strip()
                    
                    # Advanced Clan ID extraction
                    default_clan_id = "3086579607"
                    clan_id = default_clan_id  # Default value
                    
                    try:
                        import re
                        # First attempt: search for /clan/ followed by numbers
                        id_match = re.search(r'/clan/(\d{5,15})\b', cleaned_message)
                        
                        if id_match:
                            clan_id = id_match.group(1)
                            print(f"Extracted Clan ID: {clan_id}")
                            
                            # Validate the ID
                            if not (5 <= len(clan_id) <= 15) or not clan_id.isdigit():
                                print("Invalid Clan ID format, using default")
                                clan_id = default_clan_id
                        else:
                            # Second attempt: alternative method if the first fails
                            parts = cleaned_message.split('/clan/')
                            if len(parts) > 1:
                                temp_id = parts[1].split()[0].strip()
                                if temp_id.isdigit() and 5 <= len(temp_id) <= 15:
                                    clan_id = temp_id
                                else:
                                    print("Invalid Clan ID in fallback method, using default")
                                    clan_id = default_clan_id
                            else:
                                print("No Clan ID found, using default")
                                clan_id = default_clan_id
                                
                    except Exception as extract_error:
                        print(f"Clan ID extraction error: {extract_error}, using default")
                        clan_id = default_clan_id
            
                    # Continue with the rest of the operations
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)

                    clients.send(self.GenResponsMsg("Fetching clan info..."))
                    
                    clan_info_msg = Get_clan_info(clan_id)
                    clients.send(self.GenResponsMsg(clan_info_msg))
            
                except Exception as e:
                    print(f"\nClan Processing Error: {e}\n")
                    try:
                        json_result = get_available_room(data.hex()[10:])
                        parsed_data = json.loads(json_result)
                        uid = parsed_data["5"]["data"]["1"]["data"]
                        error_msg = f"[FF0000]Error: {str(e)}"
                        clients.send(self.GenResponsMsg(error_msg))
                    except:
                        restart_program()
####################################
            if "1200" in data.hex()[0:4] and b"/room/" in data:
                try:
                    import re
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    
                    uid = parsed_data["5"]["data"]["1"]["data"]
                    split_data = re.split(rb'/room', data)
                    if len(split_data) > 1:
                        room_data = split_data[1].split(b'(')[0].decode().strip().split()
                        if room_data and len(room_data) > 0:
                            player_id = room_data[0]
                            if player_id.isdigit():
                                if "***" in player_id:
                                    player_id = rrrrrrrrrrrrrr(player_id)
                                packetmaker = self.createpacketinfo(player_id)
                                socket_client.send(packetmaker)
                                sleep(0.5)
                                if "IN ROOM" in tempdata:
                                    room_id = get_idroom_by_idplayer(data22)
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"\n{generate_random_color()}- Spam Started For UID {fix_num(player_id)} !\n"
                                        )
                                    )
                                    for _ in range(10):
                                        packetspam = self.spam_room(room_id, player_id)
                                        print(" sending spam to " + player_id)
                                        threading.Thread(target=socket_client.send, args=(packetspam,)).start()
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"\n\n\n{generate_random_color()} [00FF00]Successfully Spam Sent !\n\n\n"
                                        )
                                    )
                                else:
                                    clients.send(
                                        self.GenResponsMsg(
                                            f"\n\n\n[C][B] [FF00FF]The player is not in a room.\n\n\n"
                                        )
                                    )
                            else:
                                clients.send(
                                    self.GenResponsMsg(
                                        f"\n\n\n[C][B] [FF00FF]Invalid Player ID!\n\n\n"
                                    )
                                )
                        else:
                            clients.send(
                                self.GenResponsMsg(
                                    f"\n\n\n[C][B] [FF00FF]Please provide the player's ID!\n\n\n"
                                )
                            )
                    else:
                        clients.send(
                            self.GenResponsMsg(
                                f"\n\n\n[C][B] [FF00FF]Please provide the player's ID!\n\n\n"
                            )
                        )
                except Exception as e:
                    print(f"Error in /room command: {e}")
                    clients.send(self.GenResponsMsg("[FF0000]An error occurred."))
####################################
            
            # ** FINAL CORRECTED /info COMMAND HANDLER **
            if "1200" in data.hex()[0:4] and b"/info/" in data:
                try:
                    raw_message = data.decode('utf-8', errors='ignore')
                    # This regex is more flexible: it allows a space or no space
                    match = re.search(r'/info/\s*(\d{5,15})', raw_message)
                    
                    if not match:
                        clients.send(self.GenResponsMsg("[FF0000]Invalid format. Use: /info/<UID>"))
                        continue

                    clients.send(self.GenResponsMsg("[FFFFFF]Fetching player info..."))
                    uid = match.group(1)
                    
                    json_result = get_available_room(data.hex()[10:])
                    parsed_data = json.loads(json_result)
                    sender_name = parsed_data.get('5', {}).get('data', {}).get('9', {}).get('data', {}).get('1', {}).get('data', 'Unknown User')
                    print("json_result:\n",json_result)

                    clients.send(self.GenResponsMsg(f"{generate_random_color()}Searching for UID {uid} in IND server..."))
                    
                    # Always calls the simplified newinfo function
                    info_response = newinfo(uid)
                    
                    if info_response['status'] == "ok":
                        info_data = info_response['data']
                        basic_info = info_data.get('basic_info', {})
                        social_info = info_data.get('social_info', {})
                        clan_info = info_data.get('clan_basic_info', {})
                        captain_info = info_data.get('captain_basic_info', {})

                        creation_timestamp = basic_info.get('create_at', '0')
                        try:
                            creation_date = datetime.fromtimestamp(int(creation_timestamp)).strftime('%d %B %Y')
                        except (ValueError, TypeError):
                            creation_date = "N/A"

                        clan_info_msg = "\n[C][FF0000]Player is not in a clan.\n"
                        if clan_info and captain_info:
                            clan_info_msg = (
                                f"\n[C][11EAFD]╒═══[b] Clan Info [/b]═══╕\n"
                                f"[FFFFFF]Clan ID: [00FF00]{fix_num(clan_info.get('clan_id', 'N/A'))}\n"
                                f"[FFFFFF]Clan Name: [00FF00]{clan_info.get('clan_name', 'N/A')}\n"
                                f"[FFFFFF]Clan Level: [00FF00]{clan_info.get('clan_level', 'N/A')}\n"
                                f"[C][11EAFD]Leader Info:\n"
                                f"[FFFFFF]ID: [00FF00]{fix_num(captain_info.get('account_id', 'N/A'))}\n"
                                f"[FFFFFF]Name: [00FF00]{captain_info.get('nickname', 'N/A')}\n"
                                f"[FFFFFF]Level: [00FF00]{captain_info.get('level', 'N/A')}\n"
                                f"[C][11EAFD]╘══════════════╛\n"
                            )

                        bio = social_info.get('social_highlight', 'No Bio').replace("|", " ")

                        message_info = (
                            f"[C][FFB300]╒═══[b] Account Info [/b]═══╕\n"
                            f"[FFFFFF]Server: [00FF00]{basic_info.get('region', 'N/A')}\n"
                            f"[FFFFFF]Name: [00FF00]{basic_info.get('nickname', 'N/A')}\n"
                            f"[FFFFFF]Bio: [00FF00]{bio}\n"
                            f"[FFFFFF]Level: [00FF00]{basic_info.get('level', 'N/A')}\n"
                            f"[FFFFFF]Likes: [00FF00]{fix_num(basic_info.get('liked', 'N/A'))}\n"
                            f"[FFFFFF]BR Score: [00FF00]{fix_num(basic_info.get('ranking_points', 'N/A'))}\n"
                            f"[FFFFFF]Account Created: [00FF00]{creation_date}\n"
                            f"{clan_info_msg}"
                            f"\n[FF0000]Command Sent By: {sender_name}\n"
                            f"[C][FFB300]╘══════════════════╛"
                        )
                    else:
                        error_detail = info_response.get('message', 'An unknown error occurred.')
                        message_info = (
                            f"[C][B][FF0000]-----------------------------------\n"
                            f"[FFFFFF]Failed to get player info.\n"
                            f"[FFFF00]Reason: {error_detail}\n"
                            f"[FF0000]-----------------------------------"
                        )
                    
                    clients.send(self.GenResponsMsg(message_info))

                except Exception as e:
                    print(f"CRITICAL ERROR in /info handler: {e}")
                    clients.send(self.GenResponsMsg("[FF0000][b]An unexpected error occurred processing the /info command."))
####################################
            # GET 100 LIKES COMMAND
            import re
            # GET 100 LIKES COMMAND (Corrected and more robust)
            if "1200" in data.hex()[0:4] and b"/like/" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                sender_name = parsed_data.get('5', {}).get('data', {}).get('9', {}).get('data', {}).get('1', {}).get('data', 'Unknown User')
                sender_uid = parsed_data.get('5', {}).get('data', {}).get('1', {}).get('data', 'Unknown UID')
                print("sender_uid:", sender_uid)  # Debug print

                try:
                    # We only need to import re once at the top of the file, but leaving it here is okay.
                    import re
                    
                    raw_message = data.decode('utf-8', errors='ignore')
                    
                    # This is a cleaner and more reliable way to get the ID.
                    # It looks for "/likes/" followed by 5 to 15 digits.
                    match = re.search(r'/like/(\d{5,15})', raw_message)
                    
                    if not match:
                        # If the command format is wrong (e.g., "/likes/abc" or no ID), inform the user and stop.
                        clients.send(self.GenResponsMsg("[FF0000][b][c]Invalid format. Please use: /likeUID"))
                    else:
                        clients.send(self.GenResponsMsg("[FFFFFF][b][c]Please wait, Sending Likes..."))
                        # If the format is correct, get the player ID
                        player_id = match.group(1)
                        # Inform the user that the process is starting
                        clients.send(self.GenResponsMsg(f"Sending likes to UID: {player_id}... Please wait."))
                        if sender_uid != 1511586336:
                            like_player_data = newinfo(player_id)
                            if like_player_data['status'] != "ok":
                                error_message = like_player_data.get('message', 'Unknown error occurred.')
                                clients.send(self.GenResponsMsg(f"[FF0000][b][c]Error: {error_message}"))
                            elif like_player_data['status'] == "ok":
                                info_data = like_player_data['data']
                                clan_info = info_data.get('clan_basic_info', {})
                                clan_id = clan_info.get('clan_id', 'N/A')
                                print("clan_id:", clan_id)  # Debug print
                                if clan_id != 3036507301 and clan_id != "3036507301":
                                    clients.send(self.GenResponsMsg(f"""[FFDD00][b][c]Warning: The Player does not belong to our guild.

[FF0000][b][c]You will be kicked if you try to send Likes to players outside our guild.

[FFFFFF][b][c]Command Used by : [00FF00][b][c]{sender_name}
                                    """))
                                else:
                                    # All checks passed, proceed to send likes
                                    likes_info = send_likes(player_id, sender_name)
                                    # Send the result back to the chat
                                    clients.send(self.GenResponsMsg(likes_info))

                        
                        # Call the main send_likes function (which we already fixed)
                        else :
                            likes_info = send_likes(player_id, sender_name)
                            # Send the result back to the chat
                            # print("like_info:", likes_info)  # Debug print
                            #print("Generated Message:", self.GenResponsMsg(likes_info))  # Debug print
                            clients.send(self.GenResponsMsg(likes_info)) 

                except Exception as e:
                    # This 'except' block will catch any unexpected crash during the process.
                    print(f"Likes Command CRITICAL Error: {e}")
                    try:
                        # First, try to send an error message to the chat so users know something went wrong.
                        clients.send(self.GenResponsMsg("[FF0000][B]A critical error occurred with the likes command. The bot may restart."))
                    finally:
                        # After attempting to send the message (whether it succeeds or not),
                        # restart the program to ensure it's in a clean state, as requested.
                        print("Restarting program due to a critical error in the likes command handler.")
                        restart_program()
####################################
    #
# ... inside the connect method's while True loop ...

            if "1200" in data.hex()[0:4] and b"/help" in data:
                json_result = get_available_room(data.hex()[10:])
                parsed_data = json.loads(json_result)
                user_name = parsed_data['5']['data']['9']['data']['1']['data']
                uid = parsed_data["5"]["data"]["1"]["data"]

                response_message = f"""
[C][B][00FFFF]━━━━━━━━━━━━

[FFFFFF][B]Open a team for your friend:  
[32CD32]/🗿snd/151[c]158[c]633[c]6

[FFFFFF][B]Change the team size to:  
[00FF00]/🗿3s  
[00FF00]/🗿4s  
[00FF00]/🗿5s  
[00FF00]/🗿6s  

[FFFFFF][B]Invite a player to the team:  
[1E90FF]/🗿inv/151[c]158[c]633[c]6

[FFFFFF][B]Spam join requests:  
[FFA500]/🗿sm/151[c]158[c]633[c]6

[FFFFFF][B]Spam rooms:  
[FF4500]/🗿room/151[c]158[c]633[c]6

[FFFFFF][B]Get player info (IND Server):  
[00CED1]/🗿info/151[c]158[c]633[c]6

[FFFFFF][B]Check player status:  
[DC143C]/🗿status/151[c]158[c]633[c]6

[FFFFFF][B]Check if player is banned:  
[32CD32]/🗿check/151[c]158[c]633[c]6

[FFFFFF][B]Spam friend requests:  
[1E90FF]/🗿spm/151[c]158[c]633[c]6

[00FFFF]━━━━━━━━━━━━
"""
                clients.send(self.GenResponsMsg(response_message))

                response_mssg = f"""
[FFFFFF][B]Check the player’s server:
[1E90FF]/🗿region/151[c]158[c]633[c]6

[FFFFFF][B]Add 100 likes to the account:  
[FF69B4]/🗿like/151[c]158[c]633[c]6

[FFFFFF][B]Chat with ChatGPT:  
[9370DB]/🗿ai [your text here]

[FFFFFF][B]OWNER: KARTIK

[00FFFF]━━━━━━━━━━━━
"""
                time.sleep(1)
                clients.send(self.GenResponsMsg(response_mssg))




#━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    def  parse_my_message(self, serialized_data):
        MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
        MajorLogRes.ParseFromString(serialized_data)
        
        timestamp = MajorLogRes.kts
        key = MajorLogRes.ak
        iv = MajorLogRes.aiv
        BASE64_TOKEN = MajorLogRes.token
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv, BASE64_TOKEN

    def GET_PAYLOAD_BY_DATA(self,JWT_TOKEN , NEW_ACCESS_TOKEN,date):
        token_payload_base64 = JWT_TOKEN.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        decoded_payload = json.loads(decoded_payload)
        NEW_EXTERNAL_ID = decoded_payload['external_id']
        SIGNATURE_MD5 = decoded_payload['signature_md5']
        now = datetime.now()
        now =str(now)[:len(str(now))-7]
        formatted_time = date
        payload = bytes.fromhex("3a07312e3131312e32aa01026172b201203535656437353966636639346638353831336535376232656338343932663563ba010134ea0140366662376664656638363538666430333137346564353531653832623731623231646238313837666130363132633865616631623633616136383766316561659a060134a2060134ca03203734323862323533646566633136343031386336303461316562626665626466")
        payload = payload.replace(b"2024-12-26 13:02:43", str(now).encode())
        payload = payload.replace(b"88332848f415ca9ca98312edcd5fe8bc6547bc6d0477010a7feaf97e3435aa7f", NEW_ACCESS_TOKEN.encode("UTF-8"))
        payload = payload.replace(b"e1ccc10e70d823f950f9f4c337d7d20a", NEW_EXTERNAL_ID.encode("UTF-8"))
        payload = payload.replace(b"7428b253defc164018c604a1ebbfeMEf", SIGNATURE_MD5.encode("UTF-8"))
        PAYLOAD = payload.hex()
        PAYLOAD = encrypt_api(PAYLOAD)
        PAYLOAD = bytes.fromhex(PAYLOAD)
        ip,port = self.GET_LOGIN_DATA(JWT_TOKEN , PAYLOAD)
        return ip,port
    
    def dec_to_hex(ask):
        ask_result = hex(ask)
        final_result = str(ask_result)[2:]
        if len(final_result) == 1:
            final_result = "0" + final_result
            return final_result
        else:
            return final_result
    def convert_to_hex(PAYLOAD):
        hex_payload = ''.join([f'{byte:02x}' for byte in PAYLOAD])
        return hex_payload
    def convert_to_bytes(PAYLOAD):
        payload = bytes.fromhex(PAYLOAD)
        return payload
    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://client.ind.freefiremobile.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': freefire_version,
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.common.ggbluefox.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD,verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                print(parsed_data)
                address = parsed_data['32']['data']
                ip = address[:len(address) - 6]
                port = address[len(address) - 5:]
                return ip, port
            
            except requests.RequestException as e:
                print(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        print("Failed to get login data after multiple attempts.")
        return None, None

    def guest_token(self,uid , password):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {"Host": "100067.connect.garena.com","User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 11;en;BD;)","Content-Type": "application/x-www-form-urlencoded","Accept-Encoding": "gzip, deflate, br","Connection": "close",}
        data = {"uid": f"{uid}","password": f"{password}","response_type": "token","client_type": "2","client_secret": client_secret,"client_id": "100067",}
        response = requests.post(url, headers=headers, data=data)
        data = response.json()
        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "6fb7fdef8658fd03174ed551e82b71b21db8187fa0612c8eaf1b63aa687f1eae"
        OLD_OPEN_ID = "55ed759fcf94f85813e57b2ec8492f5c"
        time.sleep(0.2)
        data = self.TOKEN_MAKER(OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,uid)
        return(data)
        
    def TOKEN_MAKER(self,OLD_ACCESS_TOKEN , NEW_ACCESS_TOKEN , OLD_OPEN_ID , NEW_OPEN_ID,id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB50',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.common.ggbluefox.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex(paylod_token1)
        data = data.replace(OLD_OPEN_ID.encode(),NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode() , NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggblueshark.com/MajorLogin"

        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload,verify=False)
        
        combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return False
            ip,port =self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN,NEW_ACCESS_TOKEN,1)
            self.key = key
            self.iv = iv
            print(key, iv)
            return(BASE64_TOKEN,key,iv,combined_timestamp,ip,port)
        else:
            return False
    
    def time_to_seconds(hours, minutes, seconds):
        return (hours * 3600) + (minutes * 60) + seconds

    def seconds_to_hex(seconds):
        return format(seconds, '04x')
    
    def extract_time_from_timestamp(timestamp):
        dt = datetime.fromtimestamp(timestamp)
        h = dt.hour
        m = dt.minute
        s = dt.second
        return h, m, s
    
    def get_tok(self):
        global g_token
        token, key, iv, Timestamp, ip, port = self.guest_token(self.id, self.password)
        g_token = token
        print(ip, port)
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            account_id = decoded.get('account_id')
            encoded_acc = hex(account_id)[2:]
            hex_value = dec_to_hex(Timestamp)
            time_hex = hex_value
            BASE64_TOKEN_ = token.encode().hex()
            print(f"Token decoded and processed. Account ID: {account_id}")
        except Exception as e:
            print(f"Error processing token: {e}")
            return

        try:
            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
            length = len(encoded_acc)
            zeros = '00000000'

            if length == 9:
                zeros = '0000000'
            elif length == 8:
                zeros = '00000000'
            elif length == 10:
                zeros = '000000'
            elif length == 7:
                zeros = '000000000'
            else:
                print('Unexpected length encountered')
            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
            print("Final token constructed successfully.")
        except Exception as e:
            print(f"Error constructing final token: {e}")
        token = final_token
        self.connect(token, ip, port, 'anything', key, iv)
        
      
        return token, key, iv
        
with open('FALCON.txt', 'r') as file:
    data = json.load(file)
ids_passwords = list(data.items())
def run_client(id, password):
    print(f"ID: {id}, Password: {password}")
    client = FF_CLIENT(id, password)
    client.start()
    
max_range = 300000
num_clients = len(ids_passwords)
num_threads = 1
start = 0
end = max_range
step = (end - start) // num_threads
threads = []
for i in range(num_threads):
    ids_for_thread = ids_passwords[i % num_clients]
    id, password = ids_for_thread
    thread = threading.Thread(target=run_client, args=(id, password))
    threads.append(thread)
    time.sleep(3)
    thread.start()

for thread in threads:
    thread.join()
    
if __name__ == "__main__":
    try:
        client_thread = FF_CLIENT(id="4214047115", password="2E82766898F1E7227711AF89E032F10BE6D275EEA1EBF528AEF5EA83C0D5E208")
        client_thread.start()
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        restart_program()
