# 2024 © Idan Hazay
# Import libraries
from modules.server import client_requests as cr
from modules import encrypting


import socket
import traceback
import time
import threading
import os
import rsa
import struct
import random

# Announce global vars
all_to_die = False  
len_field = 4    
sep = "|" 
clients = {}

# User handling classes

class Client:
    """
    Client class for handling a client
    """
    def __init__(self, id, user, shared_secret, encryption):
        self.id = id
        self.user = user
        self.shared_secret = shared_secret
        self.encryption = encryption

# Key exchange 
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

def rsa_exchange(sock, tid):
    send_rsa_key(sock, tid)
    return recv_shared_secret(sock, tid)

def diffie_hellman(sock, tid, g, p):
    private_key = random.randint(10, 25)
    public_key = pow(g, private_key) % p
    send_data(sock, tid, b"DIFA")
    
    client_pub_key_data = recv_data(sock, tid)
    params = client_pub_key_data.split(b"|")
    if(params[1] != b"DIFP" or len(params) != 3):
        return
    client_pub_key = int(params[2].decode())
    dh_key = pow(client_pub_key, private_key) % p
    dh_key = dh_key.to_bytes(16, byteorder='big')
    print(dh_key)
    clients[tid].shared_secret = dh_key
    
    to_send = f"DIFR{sep}{public_key}"
    send_data(sock, tid, to_send.encode())
    
    return dh_key


# Begin client replies building functions

def protocol_build_reply(request, id):
    """
    Client request parsing and handling
    Getting the input fields
    Checking the action code
    Performing actions for each different code
    Returning the reply to the client
    """
    global clients
    fields = request.decode()   # Parse the reply and aplit it according to the protocol seperator
    fields = fields.split(sep)
    fields.pop(0)
    code = fields[0]

    # Checking each indevidual code
    if code == 'EXIT':   # Client requests disconnection
        reply = 'EXTR'
        clients[id].user = "dead"
    
    elif (code == "LOGN"):   # Client requests login
        cred = fields[1]
        pwd = fields[2]
        if (cr.login_validation(cred, pwd)):
            if(not cr.verified(cred)):
                reply = f"ERRR{sep}010{sep}User not verified"
            else:
                user_dict = cr.get_user_data(cred)
                username = user_dict["username"]
                email = user_dict["email"]
                tz = user_dict["tz"]
                clients[id].user = username
                reply = f"LOGS{sep}{email}{sep}{username}{sep}{tz}{sep}{pwd}"
        else:
            reply = f"ERRR{sep}004{sep}Invalid credentials"
    
    elif (code == "SIGU"):   # Client requests signup
        email = fields[1]
        username = fields[2]
        tz = fields[3]
        pwd = fields[4]
        if (cr.user_exists(username)):
            reply = f"ERRR{sep}005{sep}Username already registered"
        elif(cr.email_registered(email)):
            reply = f"ERRR{sep}006{sep}Email address already registered"
        else:
            user_details = [email, username, tz, pwd]
            cr.signup_user(user_details)
            reply = f"SIGS{sep}{email}{sep}{username}{sep}{tz}{sep}{pwd}"
    
    elif (code == "FOPS"):   # Client requests password reset code
        email = fields[1]
        if (cr.email_registered(email)):
            if(not cr.verified(email)):
                reply = f"ERRR{sep}010{sep}User not verified"
            else:
                cr.send_reset_mail(email)
                reply = f"FOPR{sep}{email}"
        else:
            reply = f"ERRR{sep}007{sep}Email is not registered"
    
    elif (code == "PASR"):   # Client requests password reset
        email = fields[1]
        code = fields[2]
        new_pwd = fields[3]
        res = cr.check_code(email, code)
        if (res == "ok"):
            cr.change_password(email, new_pwd)
            clients[id].user = "guest"
            reply = f"PASS{sep}{email}{sep}{new_pwd}"
        elif(res == "code"):
            reply = f"ERRR{sep}008{sep}Code not matching try again"
        else:
            reply = f"ERRR{sep}009{sep}Code validation time ran out"
    
    elif(code == "LOGU"):   # Client requests logout
        clients[id].user = "guest"
        reply = "LUGR"
    
    elif(code == "SVER"):   # Client requests account verification code
        email = fields[1]
        if (cr.email_registered(email)):
            if(cr.verified(email)):
                reply = f"ERRR{sep}011{sep}Already verified"
            else:
                cr.send_verification(email)
                reply = f"VERS{sep}{email}"
        else:
            reply = f"ERRR{sep}007{sep}Email is not registered"
    
    elif(code == "VERC"):   # Client requests account verification
        email = fields[1]
        code = fields[2]
        if (cr.email_registered(email)):
            res = cr.check_code(email, code)
            if (res == "ok"):
                cr.verify_user(email)
                reply = f"VERR{sep}{email}"
            elif(res == "code"):
                reply = f"ERRR{sep}008{sep}Code not matching try again"
            else:
                reply = f"ERRR{sep}009{sep}Code validation time ran out"
        else:
            reply = f"ERRR{sep}007{sep}Email is not registered"
    
    elif(code == "DELU"):   # Client requests user deletion
        username = fields[1]
        if(cr.user_exists(username)):
            cr.delete_user(username)
            clients[id].user = "guest"
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
    try:
        if (str(byte_data[0]) == "0"):
            print("")
    except AttributeError:
        return
    if dir == 'sent':
        print(f'{tid} S LOG:Sent     >>> {byte_data}')
    else:
        print(f'{tid} S LOG:Recieved <<< {byte_data}')

def send_data(sock, tid, bdata):
    """
    Send data to server
    Adds data encryption
    Adds length
    Loggs the encrypted and decrtpted data for readablity
    Checks if encryption is used
    """
    if(clients[tid].encryption):
        encrypted_data = encrypting.encrypt(bdata, clients[tid].shared_secret)
        data_len = struct.pack('!l', len(encrypted_data))
        to_send = data_len + sep.encode() + encrypted_data.encode()
        to_send_decrypted = str(len(bdata)).encode() + sep.encode() + bdata
        logtcp('sent', tid, to_send)
        logtcp('sent', tid, to_send_decrypted)
    else:
        data_len = struct.pack('!l', len(bdata))
        to_send = data_len + sep.encode() + bdata
        logtcp('sent', tid, to_send)
    
    sock.send(to_send)

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
        
        if(tid in clients and clients[tid].encryption): # If encryption is enabled decrypt and log encrypted
            logtcp('recv', tid, b_len + sep.encode() + msg)   # Log encrypted data
            msg = encrypting.decrypt(msg, clients[tid].shared_secret).encode()
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
    global clients
    try:
        finish = False
        print(f'New Client number {tid} from {addr}')
        start = recv_data(sock, tid)
        code = start.split(b"|")[1]
        clients[tid] = Client(tid, "guest", None, False)   # Setting client state
        if (code == b"RSAR"):
            shared_secret = rsa_exchange(sock, tid)
        elif(code == b"DIFG"):
            shared_secret = diffie_hellman(sock, tid, int(start.split(b"|")[2].decode()), int(start.split(b"|")[3].decode()))
        if(shared_secret == ""):
            return

        print(shared_secret)
        clients[tid].shared_secret = shared_secret
        clients[tid].encryption = True
    except Exception:
        print(traceback.format_exc())
        print(f'Client {tid} connection error')   # Releasing clienk and closing socket
        if (tid in clients):
            clients[tid].user = "dead"
        sock.close()
        return
    while not finish:   # Main client loop
        if all_to_die:
            print('will close due to main server issue')
            break
        try:
            entire_data = recv_data(sock, tid)   # Recieving data and  handling client
            logtcp('recv', tid, entire_data)
            to_send, finish = handle_request(entire_data, tid)
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
    clients[tid].user = "dead"
    sock.close()


def main(addr):
    """
    Main function
    Listens for clients from any addr
    Creates threads to handle each user
    Handles every user seperately
    """
    global all_to_die

    threads = []
    srv_sock = socket.socket()
    srv_sock.bind(addr)
    srv_sock.listen(20)
    
    print(f"Server listening on {addr}")
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    i = 1

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
    cr.main()
    main(("0.0.0.0", 31026))
