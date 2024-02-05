import socket
import random
import traceback
import time
import threading
from threading import Lock
import json
from email.message import EmailMessage
import ssl
import smtplib
import os
import bcrypt
from datetime import datetime, timedelta
import rsa
import struct

all_to_die = False  
len_field = 4     
ceaser_shift = 5
users_file = f"{os.path.dirname(os.path.abspath(__file__))}\\users.json"
gmail = "idancyber3102@gmail.com"
gmail_password = "nkjg eaom gzne nyfa"
pepper = b"VerYGOdPePPEr"
clients = {}

class Client:
    def __init__(self, id, user, c_public_key):
        self.id = id
        self.user = user
        self.c_public_key = c_public_key

class User:
    def __init__(self, email, username, tz, password):
        self.email = email
        self.username = username
        self.tz = tz
        self.password = password
        self.salt = bcrypt.gensalt()
        self.last_code = -1
        self.valid_until = str(datetime.now())
        self.verified = False

    def to_dict(self):
        class_dict = {}
        class_variables = vars(self)
        for var_name, var_value in class_variables.items():
            if(var_name == "password" or var_name == "salt"):
                var_value = var_value.decode()
            class_dict[var_name] = var_value
        return class_dict
        

    def to_json(self):
        return json.dumps(self.to_dict())

    def from_dict(self, user_dict):
        for key, value in user_dict.items():
            if key == "password" or key == "salt":
                setattr(self, key, value.encode())
            else:
                setattr(self, key, value)

    def from_json(self, json_string):
        user_dict = json.loads(json_string)
        return self.from_dict(user_dict)


def read_users():
    if(not os.path.isfile(users_file)):
        with open(users_file, 'w') as file:
            file.write("{}")

    with open(users_file, 'r') as file:
        if (file.read() == ""):
            with open(users_file, 'w') as f:
                f.write("{}")
    with open(users_file, 'r') as file:
        existing_users = json.load(file)
    
    return existing_users

def update_users():
    with open(users_file, 'w') as file:
        json.dump(users, file, indent=2)

def is_login_valid(username, password):

    for user in users:
        if (users[user]["username"] == username and users[user]["password"].encode() == bcrypt.hashpw(password.encode('utf-8') + pepper, users[user]["salt"].encode())):
            return True
    return False


def user_exists(username):
    if isinstance(users, dict):
        return username in users
    else:
        return False

def email_registered(email):
    for user in users:
        if(users[user]["email"] == email):
            return True
    return False

def get_username_from_email(email):
    for user in users:
        if(users[user]["email"] == email):
            return users[user]["username"]

def send_reset_mail(email):
    code = random.randint(100000, 999999)
    username = get_username_from_email(email)
    users[username]['last_code'] = code
    users[username]["valid_until"] = str(timedelta(minutes=10) + datetime.now())
    update_users()
    em = EmailMessage()
    em["From"] = gmail
    em["To"] = email
    em["Subject"] = "Password reset code"
    body = f"Your password reset code is: {code}"
    em.set_content(body)
    send_mail(em, email)

def send_mail(em, send_to):
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp_server:
        smtp_server.login(gmail, gmail_password)
        smtp_server.sendmail(gmail, send_to, em.as_string())

def check_code(email, code):
    username = get_username_from_email(email)
    print(str_to_date(users[username]["valid_until"]))
    if(str_to_date(users[username]["valid_until"]) < datetime.now()):
        return "time"
    elif (int(users[username]['last_code']) != int(code)):
        return "code"
    else:
        return "ok"

def str_to_date(str):
    format = "%Y-%m-%d %H:%M:%S.%f"
    return datetime.strptime(str, format)

def signup_user(user):
    user.password = bcrypt.hashpw(user.password.encode('utf-8') + pepper, user.salt)
    user_dict = user.to_dict()
    users[user.username] = user_dict
    update_users()

def send_verification(email):
    code = random.randint(100000, 999999)

    em = EmailMessage()
    em["From"] = gmail
    em["To"] = email
    em["Subject"] = "Account Verification"
    body = f"Your account verification code is: {code}"
    em.set_content(body)
    send_mail(em, email)

    username = get_username_from_email(email)
    users[username]["last_code"] = code
    users[username]["valid_until"] = str(timedelta(minutes=30) + datetime.now())
    update_users()

def verify_user(username):
    users[username]["verified"] = True
    update_users()

def delete_user(username):
    del users[username]
    logout(id)
    update_users()

def encrypt_pwd(text, shift = ceaser_shift):
    encrypt_pwded_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypt_pwded_text += chr((ord(char) -ord('a') + shift) % 26 + ord('a'))
            else:
                encrypt_pwded_text += chr((ord(char) -ord('A') + shift) % 26 + ord('A'))
        else:
            encrypt_pwded_text += char
    return encrypt_pwded_text

def decrypt_pwd(text):
    return encrypt_pwd(text, -ceaser_shift)

def change_password(email, new_password):
    username = get_username_from_email(email)
    new_salt = bcrypt.gensalt()
    users[username]["salt"] = new_salt.decode()
    new_password_hash = bcrypt.hashpw(new_password.encode('utf-8') + pepper, new_salt)
    users[username]['password'] = new_password_hash.decode()

    update_users()
    
    for user in clients.keys():
        if clients[user].user == users[username]["username"]:
            logout(user)

def logout(id):
    clients[id].user = "guest"

def login(id, username):
    clients[id].user = username

def dead(id):
    clients[id].user = "dead"

def logtcp(dir, tid, byte_data):
    if dir == 'sent':
        print(f'{tid} S LOG:Sent     >>> {byte_data}\n')
    else:
        print(f'{tid} S LOG:Recieved <<< {byte_data}\n')


def send_data(sock, tid, bdata):
    encrypted_data = rsa.encrypt(bdata, clients[tid].c_public_key)
    data_len = struct.pack('!l', len(encrypted_data))

    to_send_encrypted = data_len + b'|' + encrypted_data
    to_send_decrypted = str(len(bdata)).encode() + b'|' + bdata

    sock.send(to_send_encrypted)
    logtcp('sent', tid, to_send_encrypted)
    logtcp('sent', tid, to_send_decrypted)



def protocol_build_reply(request, id):

    fields = request.decode()
    fields = fields.split('|')
    fields.pop(0)
    code = fields[0]

    if code == 'EXIT':
        reply = 'EXTR'
        dead(id)
    elif (code == "LOGN"):
        username = fields[1]
        enc_pwd = fields[2]
        dec_pwd = decrypt_pwd(enc_pwd)
        if (is_login_valid(username, dec_pwd)):
            if(not users[username]["verified"]):
                reply = "ERRR|010|User not verified"
            else:
                email = users[username]["email"]
                tz = users[username]["tz"]
                login(id, username)
                reply = f"LOGS|{email}|{username}|{tz}|{enc_pwd}"
        else:
            reply = "ERRR|004|Invalid credentials"
    elif (code == "SIGU"):
        email = fields[1]
        username = fields[2]
        tz = fields[3]
        enc_pwd = fields[4]
        dec_pwd = decrypt_pwd(enc_pwd)
        if (user_exists(username)):
            reply = "ERRR|005|Username already registered"
        elif(email_registered(email)):
            reply = "ERRR|006|Email address already registered"
        else:
            user = User(email, username, tz, dec_pwd)
            signup_user(user)
            reply = f"SIGS|{email}|{username}|{tz}|{enc_pwd}"

    elif (code == "FOPS"):
        email = fields[1]
        if (email_registered(email)):
            if(not users[get_username_from_email(email)]["verified"]):
                reply = "ERRR|010|User not verified"
            else:
                send_reset_mail(email)
                reply = f"FOPR|{email}"
        else:
            reply = "ERRR|007|Email is not registered"
    elif (code == "PASR"):
        email = fields[1]
        code = fields[2]
        enc_new_pwd = fields[3]
        dec_new_pwd = decrypt_pwd(enc_new_pwd)
        res = check_code(email, code)
        if (res == "ok"):
            change_password(email, dec_new_pwd)
            reply = f"PASS|{email}|{enc_new_pwd}"
        elif(res == "code"):
            reply = "ERRR|008|Code not matching try again"
        else:
            reply = "ERRR|009|Code validation time ran out"
    elif(code == "LOGU"):
        logout(id)
        reply = "LUGR"
    elif(code == "SVER"):
        email = fields[1]
        
        if (email_registered(email)):
            username = get_username_from_email(email)
            if(users[username]["verified"]):
                reply = "ERRR|011|Already verified"
            else:
                send_verification(email)
                reply = f"VERS|{email}"
        else:
            reply = "ERRR|007|Email is not registered"
    elif(code == "VERC"):
        email = fields[1]
        code = fields[2]
        if (email_registered(email)):
            username = get_username_from_email(email)
            res = check_code(email, code)
            if (res == "ok"):
                verify_user(username)
                reply = f"VERR|{username}"
            elif(res == "code"):
                reply = "ERRR|008|Code not matching try again"
            else:
                reply = "ERRR|009|Code validation time ran out"
        else:
            reply = "ERRR|007|Email is not registered"
    elif(code == "DELU"):
        username = fields[1]
        if(user_exists(username)):
            delete_user(username)

            reply = f"DELR|{username}"
        else:
            reply = "ERRR|004|Invalid credentials"
    else:
        reply = 'ERRR|002|Code not supported'
        fields = ''
    return reply.encode()


def handle_request(request, id):
    try:
        to_send = protocol_build_reply(request, id)
    except Exception as err:
        print(traceback.format_exc())
        to_send = b'ERRR|001|General error'
    return to_send, False


def recv_data(sock, tid):
    try:
        b_len = b''
        while (len(b_len) < len_field):
            b_len += sock.recv(len_field - len(b_len))
        dump = sock.recv(1)
        msg_len = struct.unpack("!l", b_len)[0]
        entire_data = str(msg_len).encode() + dump
        if msg_len == b'':
            print('Seems client disconnected')
        msg = b''
        while (len(msg) < msg_len):
            chunk = sock.recv(msg_len - len(msg))
            if not chunk:
                print('Server disconnected abnormally.')
                break
            msg += chunk
        logtcp('recv', tid, b_len + b"|" + msg)
        msg = decode_data(msg)
        entire_data += msg
        return entire_data
    except Exception as err:
        print(traceback.format_exc())

def decode_data(data):
    return rsa.decrypt(data, private_key)


def send_key(sock, tid):
    key_to_send = public_key.save_pkcs1()
    key_len = struct.pack("!l", len(key_to_send))

    to_send = key_len + key_to_send
    logtcp('sent', tid, to_send)
    sock.send(to_send)
    

def recv_key(sock, tid):
    key_len_b = b""
    while(len(key_len_b)<4):
        key_len_b += sock.recv(4 - len(key_len_b))
    key_len = int(struct.unpack("!l", key_len_b)[0])

    key_binary = b""
    while(len(key_binary) < key_len):
        key_binary += sock.recv(key_len - len(key_binary))
    
    logtcp('recv', tid, key_len_b + key_binary)
    return rsa.PublicKey.load_pkcs1(key_binary)


def handle_client(sock, tid, addr):
    global all_to_die

    finish = False
    print(f'New Client number {tid} from {addr}')
    c_public_key = recv_key(sock, tid)
    send_key(sock, tid)
    clients[tid] = Client(tid, "guest", c_public_key)
    
    while not finish:
        if all_to_die:
            print('will close due to main server issue')
            break
        try:
            entire_data = recv_data(sock, tid)
            logtcp('recv', tid, entire_data)
            lock.acquire()
            to_send, finish = handle_request(entire_data, tid)
            lock.release()
            if to_send != '':
                send_data(sock, tid, to_send)
            if finish:
                time.sleep(1)
                break
        except socket.error as err:
            print(f'Socket Error exit client loop: err:  {err}')
            break
        except Exception as err:
            print(f'General Error %s exit client loop: {err}')
            print(traceback.format_exc())
            break
    print(f'Client {tid} Exit')
    dead(tid)
    sock.close()

def create_keys():
    public_key, private_key = rsa.newkeys(1024)
    if(not os.path.isfile(f"{os.path.dirname(os.path.abspath(__file__))}/keys/public.pem")):
        with open(f"{os.path.dirname(os.path.abspath(__file__))}/keys/public.pem", "wb") as f:
            f.write(public_key.save_pkcs1("PEM"))
    if(not os.path.isfile(f"{os.path.dirname(os.path.abspath(__file__))}/keys/private.pem")):
        with open(f"{os.path.dirname(os.path.abspath(__file__))}/keys/private.pem", "wb") as f:
            f.write(private_key.save_pkcs1("PEM"))

def load_keys():
    global public_key, private_key
    with open(f"{os.path.dirname(os.path.abspath(__file__))}/keys/public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open(f"{os.path.dirname(os.path.abspath(__file__))}/keys/private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

def main(addr):
    global all_to_die
    global lock
    global users

    threads = []
    srv_sock = socket.socket()

    srv_sock.bind(addr)
    srv_sock.listen(20)
    print(f"Server listening on {addr}")

    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    i = 1
    lock = Lock()
    users = read_users()
    create_keys()
    load_keys()
    print('Main thread: before accepting ...\n')
    while True:
        cli_sock, addr = srv_sock.accept()
        t = threading.Thread(target=handle_client, args=(cli_sock, str(i), addr))
        t.start()
        i += 1
        threads.append(t)
        if i > 100000000:
            print('\nMain thread: going down for maintenance')
            break

    all_to_die = True
    print('Main thread: waiting to all clints to die')
    for t in threads:
        t.join()
    srv_sock.close()
    print('Bye ..')


if __name__ == '__main__':
    main(("0.0.0.0", 31026))
