# 2024 © Idan Hazay
# Import libraries

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
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import struct
import secrets

# Announce global vars
all_to_die = False  
len_field = 4    
sep = "|" 
users_file = f"{os.path.dirname(os.path.abspath(__file__))}\\DataBase\\users.json"
pepper_file = f"{os.path.dirname(os.path.abspath(__file__))}\\pepper.txt"
gmail = "idancyber3102@gmail.com"
gmail_password = "nkjg eaom gzne nyfa"
clients = {}

# User handling classes

class Client:
    """
    Client class for handling a client
    """
    def __init__(self, id, user, shared_secret):
        self.id = id
        self.user = user
        self.shared_secret = shared_secret

class User:
    """
    User class for building database
    Used to transfer between user instance and json data
    """
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
            if (var_name == "password" or var_name == "salt"):
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



# Begin client requests related functions

def read_users():
    """
    Reading user database
    Saving it to users dictionary
    """
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

def get_pepper():
    if(not os.path.isfile(pepper_file)):
        new_pepper = secrets.token_hex(2000)
        with open(pepper_file, 'w') as file:
            file.write(new_pepper)
    with open(pepper_file, 'r') as file:
        pepper = file.read()
    return pepper.encode()

def update_users():
    """
    Updating user database with new users information
    """
    with open(users_file, 'w') as file:
        json.dump(users, file, indent=2)

def user_exists(username):
    """
    Checking if username is already registered
    """
    if isinstance(users, dict):
        return username in users
    else:
        return False


def email_registered(email):
    """
    Checking if email address is already registered under an account 
    """
    for user in users:
        if (users[user]["email"] == email):
            return True
    return False

def login_validation(username, password):
    """
    Checking if login details match user in database
    """
    for user in users:
        if (users[user]["username"] == username and users[user]["password"].encode() == bcrypt.hashpw(password.encode('utf-8') + pepper, users[user]["salt"].encode())):
            return True
    return False

def logout(id):
    """
    Updating the client to be guest (not logged in)
    """
    clients[id].user = "guest"

def login(id, username):
    """
    Updating the client to be logged in to certain user
    """
    clients[id].user = username

def dead(id):
    """
    Updating the client to dead state
    If client is not connected anymore
    """
    clients[id].user = "dead"

def signup_user(user):
    """
    Creating new user in database
    From user instance
    """
    user.password = bcrypt.hashpw(user.password.encode('utf-8') + pepper, user.salt)
    user_dict = user.to_dict()
    users[user.username] = user_dict
    update_users()

def verify_user(username):
    """
    Verifying user
    """
    users[username]["verified"] = True
    update_users()

def delete_user(username, id):
    """
    Deleting user from database
    """
    del users[username]
    logout(id)
    update_users()

def get_username_from_email(email):
    """
    Getting the username of related email
    Helper function
    """
    for user in users:
        if (users[user]["email"] == email):
            return users[user]["username"]


def send_reset_mail(email):
    """
    Sending password reset email
    Generating random 6 digit code
    Assigning it to user 
    Add expiry time
    """
    code = random.randint(100000, 999999)   # Setting new code and updating user
    username = get_username_from_email(email)
    users[username]['last_code'] = code
    users[username]["valid_until"] = str(
        timedelta(minutes=10) + datetime.now())
    update_users()
    
    em = EmailMessage()   # Building mail and sending it
    em["From"] = gmail
    em["To"] = email
    em["Subject"] = "Password reset code"
    body = f"Your password reset code is: {code}\nCode is valid for 10 minutes"
    em.set_content(body)
    send_mail(em, email)

def send_verification(email):
    """
    Sending account verification email
    Generating random 6 digit code
    Assigning it to user 
    Add expiry time
    """
    code = random.randint(100000, 999999)   # Setting new code and updating user
    username = get_username_from_email(email)
    users[username]["last_code"] = code   
    users[username]["valid_until"] = str(timedelta(minutes=30) + datetime.now())
    update_users()
    
    em = EmailMessage()   # Building mail and sending it
    em["From"] = gmail
    em["To"] = email
    em["Subject"] = "Account Verification"
    body = f"Your account verification code is: {code}\nCode is valid for 30 minutes"
    em.set_content(body)
    send_mail(em, email)


def send_mail(em, send_to):
    """
    Sending email to email address
    Using SMTP secure connection
    """
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp_server:
        smtp_server.login(gmail, gmail_password)
        smtp_server.sendmail(gmail, send_to, em.as_string())


def check_code(email, code):
    """
    Check the code provided by user
    Works for user verification and password recovery
    """
    username = get_username_from_email(email)
    if(str_to_date(users[username]["valid_until"]) < datetime.now()):
        return "time"
    elif (int(users[username]['last_code']) != int(code)):
        return "code"
    else:
        return "ok"


def str_to_date(str):
    """
    Transfer string of date to date
    Helper function
    """
    format = "%Y-%m-%d %H:%M:%S.%f"
    return datetime.strptime(str, format)

def change_password(email, new_password):
    
    """
    Changing user password
    Hashing the password with salf and pepper for security
    Updating the users database
    """
    username = get_username_from_email(email)
    new_salt = bcrypt.gensalt()
    users[username]["salt"] = new_salt.decode()
    new_password_hash = bcrypt.hashpw(
        new_password.encode('utf-8') + pepper, new_salt)
    users[username]['password'] = new_password_hash.decode()

    update_users()
    for user in clients.keys():   # Logging out logged clients of same user
        if clients[user].user == users[username]["username"]:
            logout(user)



# Begin encryption related functions

class AESCipher(object):
    def __init__(self, key):
        """
        Definitation of the class
        Decryption/encryption key and AES block size
        """
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()

    def encrypt(self, plain_text):
        """
        Encryption function
        Adds necessary padding to match block size
        """
        plain_text = self.__pad(plain_text)
        iv = Random.new().read(self.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_text = cipher.encrypt(plain_text)
        return b64encode(iv + encrypted_text).decode("utf-8")

    def decrypt(self, encrypted_text):
        """
        Decryption function
        Remove added padding to match block size
        """
        encrypted_text = b64decode(encrypted_text)
        iv = encrypted_text[:self.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(encrypted_text[self.block_size:]).decode("utf-8")
        return self.__unpad(plain_text)

    def __pad(self, plain_text):
        """
        Adds padding to test to match AES block size
        """
        number_of_bytes_to_pad = self.block_size - len(plain_text) % self.block_size
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str.encode()
        return padded_plain_text

    @staticmethod
    def __unpad(plain_text):
        """
        Removes padding to test to match AES block size
        """
        last_character = plain_text[len(plain_text) - 1:]
        return plain_text[:-ord(last_character)]

def create_keys():
    """
    Creating RSA private and public keys
    For use to transfer shared secret
    Saving keys to file for future use
    """
    public_key, private_key = rsa.newkeys(1024)   # Gen new keys
    if(not os.path.isfile(f"{os.path.dirname(os.path.abspath(__file__))}/keys/public.pem")):
        with open(f"{os.path.dirname(os.path.abspath(__file__))}/keys/public.pem", "wb") as f:
            f.write(public_key.save_pkcs1("PEM"))
    if(not os.path.isfile(f"{os.path.dirname(os.path.abspath(__file__))}/keys/private.pem")):
        with open(f"{os.path.dirname(os.path.abspath(__file__))}/keys/private.pem", "wb") as f:
            f.write(private_key.save_pkcs1("PEM"))

def load_keys():
    """
    Loading RSA keys from file
    Global vars for use
    """
    global public_key, private_key
    with open(f"{os.path.dirname(os.path.abspath(__file__))}/keys/public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    with open(f"{os.path.dirname(os.path.abspath(__file__))}/keys/private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

def send_rsa_key(sock, tid):
    """
    Send public RSA key to client
    """
    key_to_send = public_key.save_pkcs1()
    key_len = struct.pack("!l", len(key_to_send))

    to_send = key_len + key_to_send
    logtcp('sent', tid, to_send)
    sock.send(to_send)

def recv_shared_secret(sock, tid):
    """
    Receiving shared secret from client
    Getting the length
    Decrypting with RSA key
    """
    key_len_b = b""
    while(len(key_len_b) < len_field):   # Recieve len of key loop
        key_len_b += sock.recv(len_field - len(key_len_b))
    key_len = int(struct.unpack("!l", key_len_b)[0])

    key_binary = b""
    while(len(key_binary) < key_len):   # Recieve rest of key according to length
        key_binary += sock.recv(key_len - len(key_binary))
    logtcp('recv', tid, key_len_b + key_binary)
    shared_secret = rsa.decrypt(key_binary, private_key)
    return shared_secret



# Begin client replies building functions

def protocol_build_reply(request, id):
    """
    Client request parsing and handling
    Getting the input fields
    Checking the action code
    Performing actions for each different code
    Returning the reply to the client
    """
    fields = request.decode()   # Parse the reply and aplit it according to the protocol seperator
    fields = fields.split(sep)
    fields.pop(0)
    code = fields[0]

    # Checking each indevidual code
    if code == 'EXIT':   # Client requests disconnection
        reply = 'EXTR'
        dead(id)
    
    elif (code == "LOGN"):   # Client requests login
        username = fields[1]
        pwd = fields[2]
        if (login_validation(username, pwd)):
            if(not users[username]["verified"]):
                reply = f"ERRR{sep}010{sep}User not verified"
            else:
                email = users[username]["email"]
                tz = users[username]["tz"]
                login(id, username)
                reply = f"LOGS{sep}{email}{sep}{username}{sep}{tz}{sep}{pwd}"
        else:
            reply = f"ERRR{sep}004{sep}Invalid credentials"
    
    elif (code == "SIGU"):   # Client requests signup
        email = fields[1]
        username = fields[2]
        tz = fields[3]
        pwd = fields[4]
        if (user_exists(username)):
            reply = f"ERRR{sep}005{sep}Username already registered"
        elif(email_registered(email)):
            reply = f"ERRR{sep}006{sep}Email address already registered"
        else:
            user = User(email, username, tz, pwd)
            signup_user(user)
            reply = f"SIGS{sep}{email}{sep}{username}{sep}{tz}{sep}{pwd}"
    
    elif (code == "FOPS"):   # Client requests password reset code
        email = fields[1]
        if (email_registered(email)):
            if(not users[get_username_from_email(email)]["verified"]):
                reply = f"ERRR{sep}010{sep}User not verified"
            else:
                send_reset_mail(email)
                reply = f"FOPR{sep}{email}"
        else:
            reply = f"ERRR{sep}007{sep}Email is not registered"
    
    elif (code == "PASR"):   # Client requests password reset
        email = fields[1]
        code = fields[2]
        new_pwd = fields[3]
        res = check_code(email, code)
        if (res == "ok"):
            change_password(email, new_pwd)
            reply = f"PASS{sep}{email}{sep}{new_pwd}"
        elif(res == "code"):
            reply = f"ERRR{sep}008{sep}Code not matching try again"
        else:
            reply = f"ERRR{sep}009{sep}Code validation time ran out"
    
    elif(code == "LOGU"):   # Client requests logout
        logout(id)
        reply = "LUGR"
    
    elif(code == "SVER"):   # Client requests account verification code
        email = fields[1]
        if (email_registered(email)):
            username = get_username_from_email(email)
            if(users[username]["verified"]):
                reply = f"ERRR{sep}011{sep}Already verified"
            else:
                send_verification(email)
                reply = f"VERS{sep}{email}"
        else:
            reply = f"ERRR{sep}007{sep}Email is not registered"
    
    elif(code == "VERC"):   # Client requests account verification
        email = fields[1]
        code = fields[2]
        if (email_registered(email)):
            username = get_username_from_email(email)
            res = check_code(email, code)
            if (res == "ok"):
                verify_user(username)
                reply = f"VERR{sep}{username}"
            elif(res == "code"):
                reply = f"ERRR{sep}008{sep}Code not matching try again"
            else:
                reply = f"ERRR{sep}009{sep}Code validation time ran out"
        else:
            reply = f"ERRR{sep}007{sep}Email is not registered"
    
    elif(code == "DELU"):   # Client requests user deletion
        username = fields[1]
        if(user_exists(username)):
            delete_user(username, id)
            reply = f"DELR{sep}{username}"
        else:
            reply = f"ERRR{sep}004{sep}Invalid credentials"
    else:
        reply = f"ERRR{sep}002{sep}Code not supported"
        fields = ''
    
    return reply.encode()

def handle_request(request, id):
    """
    Getting client request and parsing it
    If some error occured or no response return general error
    """
    try:
        to_send = protocol_build_reply(request, id)
    except Exception as err:
        print(traceback.format_exc())
        to_send = f"ERRR{sep}001{sep}General error"
        to_send = to_send.encode()
    return to_send, False



# Begin data handling and processing functions 

def logtcp(dir, tid, byte_data):
    """
    Loggs the recieved data to console
    """
    if dir == 'sent':
        print(f'{tid} S LOG:Sent     >>> {byte_data}')
    else:
        print(f'{tid} S LOG:Recieved <<< {byte_data}')
    print("\n")

def send_data(sock, tid, bdata):
    """
    Send data to server
    Adds data encryption
    Adds length
    Loggs the encrypted and decrtpted data for readablity
    """
    encrypted_data = AESCipher(clients[tid].shared_secret).encrypt(bdata)
    data_len = struct.pack('!l', len(encrypted_data))

    to_send_encrypted = data_len + sep.encode() + encrypted_data.encode()
    to_send_decrypted = str(len(bdata)).encode() + sep.encode() + bdata

    sock.send(to_send_encrypted)
    logtcp('sent', tid, to_send_encrypted)
    logtcp('sent', tid, to_send_decrypted)

def recv_data(sock, tid):
    """
    Data recieve function
    Gets length of response and then the response
    Makes sure its gotten everything
    """
    try:
        b_len = b''
        while (len(b_len) < len_field):   # Loop to get length in bytes
            b_len += sock.recv(len_field - len(b_len))
        
        dump = sock.recv(1)   # Additional seperator not needed
        msg_len = struct.unpack("!l", b_len)[0]
        entire_data = str(msg_len).encode() + dump   # Save entire data for logging
        
        if msg_len == b'':
            print('Seems client disconnected')
        msg = b''
        
        while (len(msg) < msg_len):   # Loop to recieve the rest of the response
            chunk = sock.recv(msg_len - len(msg))
            if not chunk:
                print('Server disconnected abnormally.')
                break
            msg += chunk
        
        logtcp('recv', tid, b_len + sep.encode() + msg)   # Log encrypted data
        msg = AESCipher(clients[tid].shared_secret).decrypt(msg).encode()
        entire_data += msg
        return entire_data
    
    except Exception as err:
        print(traceback.format_exc())



# Main function and client handling, start of code

def handle_client(sock, tid, addr):
    """
    Client handling function
    Sends RSA public key and recieves shared secret for secure connection
    """
    global all_to_die

    finish = False
    print(f'New Client number {tid} from {addr}')
    send_rsa_key(sock, tid)
    shared_secret = recv_shared_secret(sock, tid)
    clients[tid] = Client(tid, "guest", shared_secret)   # Setting client state
    
    while not finish:   # Main client loop
        if all_to_die:
            print('will close due to main server issue')
            break
        try:
            entire_data = recv_data(sock, tid)   # Recieving data and locking recourses while handling client
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
    print(f'Client {tid} Exit')   # Releasing clienk and closing socket
    dead(tid)
    sock.close()

def main(addr):
    """
    Main function
    Listens for clients from any addr
    Creates threads to handle each user
    Handles every user seperately
    """
    global all_to_die
    global lock
    global users
    global pepper

    threads = []
    srv_sock = socket.socket()
    srv_sock.bind(addr)
    srv_sock.listen(20)
    
    print(f"Server listening on {addr}")
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    i = 1
    lock = Lock()
    users = read_users()
    pepper = get_pepper()
    create_keys()
    load_keys()
    
    print('Main thread: before accepting ...\n')
    while True:
        cli_sock, addr = srv_sock.accept()
        t = threading.Thread(target=handle_client, args=(cli_sock, str(i), addr))   # Accepting client and assigning id
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

if __name__ == '__main__':   # Run main
    main(("0.0.0.0", 31026))
