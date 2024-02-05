# 2024 © Idan Hazay
import socket
import sys
import traceback
import tkinter as tk
from tkinter.messagebox import askyesno
from tkinter import messagebox
from tkinter import ttk
from ttkthemes import ThemedTk
from tkinter.ttk import *
import re
import rsa
import struct

len_field = 4    
illegal_chars = {'\'', '"', '>', '<', '~', '`', '|', '\\','/', '}', '{', '[', ']', '+', '=', ';', '(', ')'}
ceaser_shift = 5
user = {}

def create_style():
    global styles
    styles = []
    
    main_btn_style = Style()
    main_btn_style.configure('main.TButton', background="#363636",  font =('calibri', 16),  padding=4)
    styles.append(main_btn_style)

    reg_btn_style = Style()
    reg_btn_style.configure('reg.TButton', background="#363636", font =('calibri', 13), padding=3)
    styles.append(reg_btn_style)

    entry_style = Style()
    entry_style.configure('field.TEntry')
    styles.append(entry_style)

    sub_label_style = Style()
    sub_label_style.configure('sub.TLabel', font =('calibri', 18))
    styles.append(sub_label_style)

    main_label_style = Style()
    main_label_style.configure('main.TLabel', font =('calibri', 30, 'bold'))
    styles.append(main_label_style)

    checkbox_style = Style()
    checkbox_style.configure('check.TCheckbutton', font =('calibri', 12))
    styles.append(checkbox_style)


def show_main_page():
    destroy_widgets()

    root.title("Authentication System")

    width, height = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{int(width/1.5)}x{int(height/1.5)}")
    ttk.Label(root, text="Idan's Login Server and Client", style="main.TLabel").pack(pady=30)
    ttk.Button(root, text="Login", style="main.TButton" ,command=lambda: login_page()).pack(pady=15)
    ttk.Button(root, text="Signup",style="main.TButton", command=lambda: signup_page()).pack(pady=15)
    ttk.Button(root, text="Forgot Password",style="main.TButton", command=lambda: forgot_password_page()).pack(pady=15)
    ttk.Button(root, text="Verify",style="main.TButton", command=lambda: show_verification_page()).pack(pady=15)
    ttk.Button(root, text="Exit",style="main.TButton", command=lambda: exit_program()).pack(pady=15)


def login_page():
    destroy_widgets()
    username = tk.StringVar()
    password = tk.StringVar()
    show_hide_var = tk.BooleanVar()

    ttk.Label(root, text="Login Page", style="main.TLabel").pack(pady=30)
    ttk.Label(root, text="Username:", style="sub.TLabel").pack()
    ttk.Entry(root, textvariable=username, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=6)
    ttk.Label(root, text="Password:", style="sub.TLabel").pack()
    password_entry = ttk.Entry(root, textvariable=password, show="*",style="field.TEntry", width=30, font=("calibri", 12))
    password_entry.pack(ipady=3, pady=2)
    ttk.Checkbutton(root, text="Show Password", variable=show_hide_var, style="check.TCheckbutton" ,command=lambda: toggle_password_visibility(password_entry, show_hide_var)).pack(pady=5)
    ttk.Label(root, text="").pack(pady=12)
    ttk.Button(root, text="Login", style="reg.TButton", command=lambda: login(username.get(), password.get())).pack()
    ttk.Label(root, text="").pack(pady=8)
    ttk.Button(root, text="Back to Main Page",style="reg.TButton", command=lambda: show_main_page()).pack()


def signup_page():
    destroy_widgets()
    email = tk.StringVar()
    username = tk.StringVar()
    password = tk.StringVar()
    tz = tk.StringVar()
    show_hide_var = tk.BooleanVar()

    ttk.Label(root, text="Signup Page", style="main.TLabel").pack(pady=20)
    ttk.Label(root, text="Email:", style="sub.TLabel").pack()
    ttk.Entry(root, textvariable=email, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=2, pady=1)
    ttk.Label(root, text="").pack(pady=3)
    ttk.Label(root, text="Username:", style="sub.TLabel").pack()
    ttk.Entry(root, textvariable=username, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=2, pady=1)
    ttk.Label(root, text="").pack(pady=3)
    ttk.Label(root, text="ID:", style="sub.TLabel").pack()
    ttk.Entry(root, textvariable=tz, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=2, pady=1)
    ttk.Label(root, text="").pack(pady=3)
    ttk.Label(root, text="Password:", style="sub.TLabel").pack()
    password_entry = ttk.Entry(root, textvariable=password, show="*",style="field.TEntry", width=30, font=("calibri", 12))
    password_entry.pack(ipady=2, pady=2)
    ttk.Checkbutton(root, text="Show Password", variable=show_hide_var, style="check.TCheckbutton", command=lambda: toggle_password_visibility(password_entry, show_hide_var)).pack(pady=1)
    ttk.Label(root, text="").pack(pady=4)
    ttk.Button(root, text="Signup", command=lambda: signup(email.get(), username.get(), tz.get(), password.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=4)
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()


def forgot_password_page():
    destroy_widgets()

    email = tk.StringVar()
    ttk.Label(root, text="Forgot Password Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="Email:", style="sub.TLabel").pack()
    ttk.Entry(root, textvariable=email, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=10)
    ttk.Button(root, text="Send Reset Code", command=lambda: reset_password(email.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()


def show_logged_in_page():
    destroy_widgets()
    ttk.Label(root, text=f"Welcome, {user["username"]}", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text=f"Email: {user["email"]}", style="sub.TLabel").pack(pady=10)
    ttk.Label(root, text=f"ID: {user["tz"]}", style="sub.TLabel").pack(pady=10)
    ttk.Label(root, text=f"Password: {user["password"]}", style="sub.TLabel").pack(pady=10)
    ttk.Button(root, text="Logout", command=lambda: logout(), style="reg.TButton").pack(pady=10)
    ttk.Button(root, text="Delete User", command=lambda: delete_user(user["username"]), style="reg.TButton").pack()


def show_recovery_page(email):
    destroy_widgets()

    code = tk.StringVar()
    new_password = tk.StringVar()
    show_hide_var = tk.BooleanVar()

    ttk.Label(root, text="Recovery Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="Code:", style="sub.TLabel").pack()
    ttk.Entry(root, textvariable=code, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=5)
    ttk.Label(root, text="New Password:", style="sub.TLabel").pack()
    password_entry = ttk.Entry(root, textvariable=new_password, show="*",style="field.TEntry", width=30, font=("calibri", 12))
    password_entry.pack(ipady=3, pady=2)
    ttk.Checkbutton(root, text="Show Password", variable=show_hide_var , style="check.TCheckbutton", command=lambda: toggle_password_visibility(password_entry, show_hide_var)).pack(pady=5)

    ttk.Label(root, text="").pack(pady=8)
    ttk.Button(root, text="Reset Password", command=lambda: password_recovery(email, code.get(), new_password.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()

def show_verification_page():
    destroy_widgets()

    email = tk.StringVar()
    

    ttk.Label(root, text="Verification Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="Email:", style="sub.TLabel").pack()
    ttk.Entry(root, textvariable=email, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=5)


    ttk.Label(root, text="").pack(pady=8)
    ttk.Button(root, text="Verify", command=lambda: send_verification(email.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()

def show_verifycode_page(email):
    destroy_widgets()

    code = tk.StringVar()
    
    ttk.Label(root, text="Verification Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="").pack(pady=5)
    ttk.Label(root, text="Code:", style="sub.TLabel").pack()
    ttk.Entry(root, textvariable=code,style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)

    ttk.Label(root, text="").pack(pady=8)
    ttk.Button(root, text="Verify", command=lambda: send_verify_code(email, code.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()

def destroy_widgets():
    for widget in root.winfo_children():
        widget.destroy()

def toggle_password_visibility(pwd_widget, checkbox_var):
    if checkbox_var.get():
        pwd_widget["show"] = ""
    else:
        pwd_widget["show"] = "*"


def login(username, password):
    items = [username, password]
    if (is_empty(items) or check_illegal_chars(items)):
        return
    password = encrypt_pwd(password)
    send_string = b"LOGN|" + username.encode() + b"|" + password.encode()
    send_data(send_string)
    handle_reply()


def signup(email, username, tz, password):
    items = [email, username, password]
    if (is_empty(items) or check_illegal_chars(items) or not is_valid_email(email) or not is_valid_tz(tz) or not is_valid_password(password) or not is_valid_username(username)):
        return
    password = encrypt_pwd(password)
    send_string = b"SIGU|" + email.encode() + b"|" + username.encode() + b"|" + tz.encode()+ b"|" + password.encode()
    send_data(send_string)
    handle_reply()


def reset_password(email):
    items = [email]
    if (is_empty(items) or check_illegal_chars(items)):
        return
    send_string = b"FOPS|" + email.encode()
    send_data(send_string)
    handle_reply()


def password_recovery(email, code, new_password):
    items = [email, code, new_password]
    if (is_empty(items) or check_illegal_chars(items) or not is_valid_password(new_password)):
        return
    new_password = encrypt_pwd(new_password)
    send_string = b"PASR|" + email.encode() + b"|" + code.encode() + b"|" + new_password.encode()
    send_data(send_string)
    handle_reply()

def send_verification(email):
    items = [email]
    if (is_empty(items) or check_illegal_chars(items) or not is_valid_email(email)):
        return
    send_string = b"SVER|" + email.encode()
    send_data(send_string)
    handle_reply()

def send_verify_code(email, code):
    items = [email]
    if (is_empty(items) or check_illegal_chars(items) or not is_valid_email(email)):
        return
    send_string = b"VERC|" + email.encode() + b"|" + code.encode()
    send_data(send_string)
    handle_reply()


def logout():
    global logged_in_user
    logged_in_user = {}
    send_string = b"LOGU"
    send_data(send_string)
    handle_reply()

def delete_user(username):
    if(askyesno("Double Check", "Are you sure you want to delete your user?")):
        items = [username]
        if (is_empty(items) or check_illegal_chars(items) or not is_valid_username(username)):
            return
        send_string = b"DELU|" + username.encode()
        send_data(send_string)
        handle_reply()



def exit_program():
    send_string = b"EXIT"
    send_data(send_string)
    handle_reply()

def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if(re.match(email_regex, email) is not None):
        return True
    else:
        messagebox.showinfo("Invalid Email", "Invalid email address, please try again")
        return False

def is_valid_tz(tz):
    if(len(tz)==9 and tz.isnumeric()):
        return True
    else:
        messagebox.showinfo("Invalid ID", "Entered ID is invalid, please try again")
        return False
    
def is_valid_username(username):
    if(len(username) >= 4 and username.isalnum()):
        return True
    else:
        messagebox.showinfo("Invalid Username", "Username does not meet requirements\nhas to be at least 4 long and contain only chars and numbers")
        return False



def is_valid_password(password):
    if(len(password) >= 8 and any(char.isupper() for char in password) and any(char.isdigit() for char in password)):
        return True
    else:
        messagebox.showinfo("Invalid Password", "Password does not meet requirements\nhas to be at least 8 long and contain at least 1 upper case and number")
        return False


def is_empty(list):
    for item in list:
        if item == "":
            messagebox.showinfo("Invalid Input", f"Cannot have an empty field")
            return True
    return False


def has_illegal_chars(input_str):
    if(any(char in illegal_chars for char in input_str)):
        messagebox.showinfo("Invalid Input", f"No use of following chars:\n{illegal_chars}")
        return True
    return False


def check_illegal_chars(string_list):
    return any(has_illegal_chars(s) for s in string_list)



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



def logtcp(dir, byte_data):
    if dir == 'sent':
        print(f'C LOG:Sent     >>>{byte_data}\n')
    else:
        print(f'C LOG:Recieved <<<{byte_data}\n')


def send_data(bdata):
    encrypted_data = rsa.encrypt(bdata, s_public_key)
    data_len = struct.pack('!l', len(encrypted_data))

    to_send_encrypted = data_len + b'|' + encrypted_data

    to_send_decrypted = str(len(bdata)).encode() + b'|' + bdata

    sock.send(to_send_encrypted)
    logtcp('sent', to_send_encrypted)
    logtcp('sent', to_send_decrypted)


def protocol_parse_reply(reply):
    try:
        to_show = 'Invalid reply from server'
        reply = reply.decode()
        fields = reply.split('|')
        fields.pop(0)
        code = fields[0]
        if code == 'ERRR':
            err_code = int(fields[1])
            if (err_code == 4):
                messagebox.showinfo("Invalid Login", "Login details not matching any user, please try again")
            elif (err_code == 5):
                messagebox.showinfo("Already registered", "Username already registered, please try a different one")
            elif (err_code == 6):
                messagebox.showinfo("Already registered", "Email address already registered, please try a different one")
            elif (err_code == 7):
                messagebox.showinfo("Please register", "Email address not registered")
            elif (err_code == 8):
                messagebox.showinfo("Invalid Code", "Code is not matching")
            elif (err_code == 9):
                messagebox.showinfo("Expired", "Code time has exipred\nPlease send again")
            elif (err_code == 10):
                messagebox.showinfo("Not Verified", "Account is not verified, please verify")
            elif (err_code == 11):
                messagebox.showinfo("Verified", "Account is already verified")
            else:
                messagebox.showinfo("Error", "General server error")
            to_show = 'Server return an error: ' + fields[1] + ' ' + fields[2]
        elif code == 'EXTR':
            to_show = 'Server acknowledged the exit message'
        elif code == 'LOGS':
            email = fields[1]
            username = fields[2]
            tz = fields[3]
            enc_pwd = fields[4]
            dec_pwd = decrypt_pwd(enc_pwd)
            to_show = f'Login was succesfull for user: {username}, password:{dec_pwd}'
            user["email"] = email
            user["username"] = username
            user["tz"] = tz
            user["password"] = dec_pwd
            show_logged_in_page()
        elif code == 'SIGS':
            email = fields[1]
            username = fields[2]
            tz = fields[3]
            enc_pwd = fields[4]
            dec_pwd = decrypt_pwd(enc_pwd)
            to_show = f'Signup was successful for user: {username}, password:{dec_pwd}'
            show_main_page()
            messagebox.showinfo("Signup successful", f"Signup for user {username} completed.\nPlease verify your account")
        elif code == 'FOPR':
            to_show = f'Recovery email sent to: {fields[1]}'
            show_recovery_page(fields[1])
        elif code == 'PASS':
            enc_new_pwd = fields[2]
            dec_new_pwd = decrypt_pwd(enc_new_pwd)
            to_show = f'Password was reset for user: {fields[1]}, new password: {dec_new_pwd}'
            show_main_page()
        elif code == 'LUGR':
            to_show = f'Logout succesfull'
            show_main_page()
        elif code == 'VERS':
            email = fields[1]
            to_show = f'Verification sent to email {email}'
            show_verifycode_page(email)
        elif code == 'VERR':
            username = fields[1]
            to_show = f'Verification for user {username} was succesfull'
            show_main_page()
        elif code == 'DELR':
            username = fields[1]
            to_show = f'User {username} was deleted'
            show_main_page()
    except Exception as e:
        print('Server replay bad format ' + str(e))
        print(traceback.format_exc())
    return to_show


def handle_reply():
    try:
        reply = recv_data()
        logtcp('recv', reply)
        to_show = protocol_parse_reply(reply)
        if to_show != '':
            print('\n==========================================================')
            print(f'  SERVER Reply: {to_show}')
            print('==========================================================')
        if to_show == "Server acknowledged the exit message":
            print('Will exit ...')
            sock.close()
            print("Bye...")
            sys.exit(0)

    except socket.error as err:
        print(f'Got socket error: {err}')
        return
    except Exception as err:
        print(f'General error: {err}')
        print(traceback.format_exc())
        return


def recv_data():
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
        logtcp('recv', b_len + b"|" + msg)
        msg = decode_data(msg)
        entire_data += msg
        return entire_data
    except Exception as err:
        print(traceback.format_exc())

def decode_data(data):
    return rsa.decrypt(data, private_key)


def send_key():
    key_to_send = public_key.save_pkcs1()
    key_len = struct.pack("!l", len(key_to_send))
    to_send = key_len + key_to_send
    logtcp('sent', to_send)
    sock.send(to_send)
    

def recv_key():
    global s_public_key

    key_len_b = b""
    while(len(key_len_b)<4):
        key_len_b += sock.recv(4 - len(key_len_b))


    key_len = int(struct.unpack("!l", key_len_b)[0])

    key_binary = b""
    while(len(key_binary) < key_len):
        key_binary += sock.recv(key_len - len(key_binary))
    
    logtcp('recv', key_len_b + key_binary)
    s_public_key = rsa.PublicKey.load_pkcs1(key_binary)

def create_keys():
    global public_key
    global private_key
    public_key, private_key = rsa.newkeys(1024)
    
def create_root():
    global root
    root = ThemedTk(theme="equilux")
    root.tk.call('tk', 'scaling', 1.5)
    root.configure(bg="#464646")

def main(addr):
    global sock

    sock = socket.socket()
    try:
        sock.connect(addr)
        print(f'Connect succeeded {addr}')
    except:
        print(
            f'Error while trying to connect.  Check ip or port -- {addr}')
        return
    try:
        create_keys()
        send_key()
        recv_key()
        create_root()
        create_style()
        show_main_page()
        root.mainloop()
    except Exception as e:
        print("Error:" + str(e))
        print(traceback.format_exc())


if __name__ == "__main__":
    main(("127.0.0.1", 31026))
