# 2024 © Idan Hazay
# Import libraries

from modules import encrypting

import tkinter as tk
from tkinter import ttk
from ttkthemes import ThemedTk
from tkinter.ttk import *
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

import socket
import sys
import traceback
from tkinter.messagebox import askyesno
from tkinter import messagebox
import re
import rsa
import struct
import os


# Announce global vars
len_field = 4    
sep = "|"
illegal_chars = {'\'', '"', '>', '<', '~', '`', '|', '\\','/', '}', '{', '[', ']', '+', '=', ';', '(', ')'}
user = {}


# Begin gui related functions

def create_root():
    """
    Create the root of the tkinter gui
    Global var to use in code
    """
    global root
    root = ttk.Window(themename="cyborg")
    root.tk.call('tk', 'scaling', 4)
    #root.configure(bg="#464646")

def create_style():
    """
    Create global styles for tkinter gui
    """
    global styles
    styles = []
    
    main_btn_style = Style()
    main_btn_style.configure('main.TButton',   font =('calibri', 20),  padding=4)
    styles.append(main_btn_style)

    reg_btn_style = Style()
    reg_btn_style.configure('reg.TButton',  font =('calibri', 13), padding=3)
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
    """
    Show the main page of the gui
    Destroying all previous widgets
    """
    destroy_widgets()
    root.title("Authentication System")
    width, height = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{int(width/1.5)}x{int(height/1.5)}")
    
    ttk.Label(root, text="Idan's Login Server and Client", style="main.TLabel").pack(pady=30)   # Buttons for each page
    ttk.Button(root, text="Login", style="main.TButton" ,command=lambda: login_page()).pack(pady=15)
    ttk.Button(root, text="Signup",style="main.TButton", command=lambda: signup_page()).pack(pady=15)
    ttk.Button(root, text="Forgot Password",style="main.TButton", command=lambda: forgot_password_page()).pack(pady=15)
    ttk.Button(root, text="Verify",style="main.TButton", command=lambda: show_send_verification_code_page()).pack(pady=15)
    ttk.Button(root, text="Exit",style="main.TButton", command=lambda: exit_program()).pack(pady=15)


def login_page():
    """
    Show the login page of the gui
    Destroying all previous widgets
    """
    destroy_widgets()
    username = tk.StringVar()   # Creating tkinter string vars for inputs
    password = tk.StringVar()
    show_hide_var = tk.BooleanVar()
    
    ttk.Label(root, text="Login Page", style="main.TLabel").pack(pady=30)
    ttk.Label(root, text="Username/Email:", style="sub.TLabel").pack()   # Username field and label
    ttk.Entry(root, textvariable=username, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=6)
    
    ttk.Label(root, text="Password:", style="sub.TLabel").pack()   # Password field and show/hide password switch
    password_entry = ttk.Entry(root, textvariable=password, show="*",style="field.TEntry", width=30, font=("calibri", 12))
    password_entry.pack(ipady=3, pady=2)
    ttk.Checkbutton(root, text="Show Password", variable=show_hide_var, style="check.TCheckbutton" ,command=lambda: toggle_password_visibility(password_entry, show_hide_var)).pack(pady=5)
    ttk.Label(root, text="").pack(pady=12)
    
    ttk.Button(root, text="Login", style="reg.TButton", command=lambda: login(username.get(), password.get())).pack()   
    ttk.Label(root, text="").pack(pady=8)   # Login and back buttons
    ttk.Button(root, text="Back to Main Page",style="reg.TButton", command=lambda: show_main_page()).pack()

def signup_page():
    """
    Show the signup page of the gui
    Destroying all previous widgets
    """
    destroy_widgets() 
    email = tk.StringVar()   # Creating tkinter string vars for inputs
    username = tk.StringVar()
    password = tk.StringVar()
    tz = tk.StringVar()
    show_hide_var = tk.BooleanVar()
    
    ttk.Label(root, text="Signup Page", style="main.TLabel").pack(pady=20)
    ttk.Label(root, text="Email:", style="sub.TLabel").pack()   # Email field and label
    ttk.Entry(root, textvariable=email, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=2, pady=1)
    ttk.Label(root, text="").pack(pady=3)
    
    ttk.Label(root, text="Username:", style="sub.TLabel").pack()   # Username field and label
    ttk.Entry(root, textvariable=username, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=2, pady=1)
    ttk.Label(root, text="").pack(pady=3)
    
    ttk.Label(root, text="ID:", style="sub.TLabel").pack()   # ID field
    ttk.Entry(root, textvariable=tz, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=2, pady=1)
    ttk.Label(root, text="").pack(pady=3)
    
    ttk.Label(root, text="Password:", style="sub.TLabel").pack()   # Password field and show/hide password switch
    password_entry = ttk.Entry(root, textvariable=password, show="*",style="field.TEntry", width=30, font=("calibri", 12))
    password_entry.pack(ipady=2, pady=2)
    ttk.Checkbutton(root, text="Show Password", variable=show_hide_var, style="check.TCheckbutton", command=lambda: toggle_password_visibility(password_entry, show_hide_var)).pack(pady=1)
    ttk.Label(root, text="").pack(pady=4)
    
    ttk.Button(root, text="Signup", command=lambda: signup(email.get(), username.get(), tz.get(), password.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=4)   # Signup and back buttons
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()

def forgot_password_page():
    """
    Show the forgot password page of the gui
    Destroying all previous widgets
    """
    destroy_widgets()
    email = tk.StringVar()   # Creating tkinter string vars for inputs
    
    ttk.Label(root, text="Forgot Password Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="Email:", style="sub.TLabel").pack()   # Email field and label
    ttk.Entry(root, textvariable=email, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=10)
    
    ttk.Button(root, text="Send Reset Code", command=lambda: reset_password(email.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)   # Send reset code and back buttons 
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()

def show_logged_in_page():
    """
    Show the logged in page of the gui
    Destroying all previous widgets
    Showing user details
    """
    destroy_widgets()
    ttk.Label(root, text=f"Welcome, {user["username"]}", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text=f"Email: {user["email"]}", style="sub.TLabel").pack(pady=10)
    ttk.Label(root, text=f"ID: {user["tz"]}", style="sub.TLabel").pack(pady=10)
    ttk.Label(root, text=f"Password: {user["password"]}", style="sub.TLabel").pack(pady=10)
    ttk.Button(root, text="Logout", command=lambda: logout(), style="reg.TButton").pack(pady=10)
    ttk.Button(root, text="Delete User", command=lambda: delete_user(user["username"]), style="reg.TButton").pack(pady = 10)
    ttk.Button(root, text="Exit", command=lambda: exit_program(), style="reg.TButton").pack(pady = 10)

def show_recovery_page(email):
    """
    Show the password recovery page of the gui
    Destroying all previous widgets
    """
    destroy_widgets()
    code = tk.StringVar()   # Creating tkinter string vars for inputs
    new_password = tk.StringVar()
    show_hide_var = tk.BooleanVar()
    
    ttk.Label(root, text="Recovery Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="Code:", style="sub.TLabel").pack()   # Recovery code field and label
    ttk.Entry(root, textvariable=code, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=5)
    
    ttk.Label(root, text="New Password:", style="sub.TLabel").pack()   # Password field and show/hide password switch
    password_entry = ttk.Entry(root, textvariable=new_password, show="*",style="field.TEntry", width=30, font=("calibri", 12))
    password_entry.pack(ipady=3, pady=2)
    ttk.Checkbutton(root, text="Show Password", variable=show_hide_var , style="check.TCheckbutton", command=lambda: toggle_password_visibility(password_entry, show_hide_var)).pack(pady=5)
    ttk.Label(root, text="").pack(pady=8)
    
    ttk.Button(root, text="Reset Password", command=lambda: password_recovery(email, code.get(), new_password.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)   # Reset password and back buttons 
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()

def show_send_verification_code_page():
    """
    Show the send account verification code page of the gui
    Destroying all previous widgets
    """
    destroy_widgets()
    email = tk.StringVar()   # Creating tkinter string vars for inputs
    
    ttk.Label(root, text="Verification Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="Email:", style="sub.TLabel").pack()   # Email field and label
    ttk.Entry(root, textvariable=email, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=5)
    
    ttk.Label(root, text="").pack(pady=8)
    ttk.Button(root, text="Verify", command=lambda: send_verification(email.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)   # Send verification code and back buttons 
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()

def show_account_verification_page(email):
    """
    Show the account verification page of the gui
    Destroying all previous widgets
    """
    destroy_widgets()
    code = tk.StringVar()   # Creating tkinter string vars for inputs
    
    ttk.Label(root, text="Verification Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="").pack(pady=5)
    ttk.Label(root, text="Code:", style="sub.TLabel").pack()   # Verification code field and label
    ttk.Entry(root, textvariable=code,style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)

    ttk.Label(root, text="").pack(pady=8)
    ttk.Button(root, text="Verify", command=lambda: send_verify_code(email, code.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)   # Send verification code and back buttons 
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(), style="reg.TButton").pack()

def destroy_widgets():
    """
    Destroying all current widgets
    Resetting the screen
    """
    for widget in root.winfo_children():
        widget.destroy()

def toggle_password_visibility(pwd_widget, checkbox_var):
    """
    Change password field visibility on/off
    """
    if checkbox_var.get():
        pwd_widget["show"] = ""
    else:
        pwd_widget["show"] = "*"

# Begin server requests related functions

def login(cred, password):
    """
    Send login request to server
    """
    items = [cred, password]
    if (is_empty(items) or check_illegal_chars(items)):
        return
    send_string = build_req_string("LOGN", items)
    send_data(send_string)
    handle_reply()

def logout():
    """
    Send logout request to server
    """
    global logged_in_user
    logged_in_user = {}
    send_string = build_req_string("LOGU")
    send_data(send_string)
    handle_reply()

def signup(email, username, tz, password):
    """
    Send signup request to server
    """
    items = [email, username, tz, password]
    if (is_empty(items) or check_illegal_chars(items) or not is_valid_email(email) or not is_valid_tz(tz) or not is_valid_password(password) or not is_valid_username(username)):
        return
    send_string = build_req_string("SIGU", items)
    send_data(send_string)
    handle_reply()

def reset_password(email):
    """
    Send password reset request to server
    """
    items = [email]
    if (is_empty(items) or check_illegal_chars(items)):
        return
    send_string = build_req_string("FOPS", items)
    send_data(send_string)
    handle_reply()

def password_recovery(email, code, new_password):
    """
    Send password recovery code and new password to server
    """
    items = [email, code, new_password]
    if (is_empty(items) or check_illegal_chars(items) or not is_valid_password(new_password)):
        return
    send_string = build_req_string("PASR", items)
    send_data(send_string)
    handle_reply()

def send_verification(email):
    """
    Send verification request to server
    """
    items = [email]
    if (is_empty(items) or check_illegal_chars(items) or not is_valid_email(email)):
        return
    send_string = build_req_string("SVER", items)
    send_data(send_string)
    handle_reply()

def send_verify_code(email, code):
    """
    Send verification code to server for confirmation
    """
    items = [email, code]
    if (is_empty(items) or check_illegal_chars(items) or not is_valid_email(email)):
        return
    send_string = build_req_string("VERC", items)
    send_data(send_string)
    handle_reply()

def delete_user(username):
    """
    Send delete user request to server
    """
    if(askyesno("Double Check", "Are you sure you want to delete your user?")):
        items = [username]
        if (is_empty(items) or check_illegal_chars(items) or not is_valid_username(username)):
            return
        send_string = build_req_string("DELU", items)
        send_data(send_string)
        handle_reply()

def exit_program():
    """
    Send exit request to server
    """
    send_string = build_req_string("EXIT")
    send_data(send_string)
    handle_reply()

def build_req_string(code, values = []):
    """
    Builds a request string
    Gets string code and list of string values
    """
    send_string = code
    for value in values:
        send_string += sep
        send_string += value
    return send_string.encode()

# Begin validation checking related functions 

def is_valid_email(email):
    """
    Check if email is valid with regex
    """
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if(re.match(email_regex, email) is not None):
        return True
    else:
        messagebox.showinfo("Invalid Email", "Invalid email address, please try again")
        return False

def is_valid_tz(tz):
    """
    Check if tz is valid
    """
    if(len(tz)==9 and tz.isnumeric()):
        mult = 1
        check_sum = 0
        for num in tz:   # Check if tz is valid
            check_sum += sum_digits(int(num) * mult)
            if(mult == 1): mult += 1
            else: mult -= 1
        if check_sum % 10 == 0:
            return True

    messagebox.showinfo("Invalid ID", "Entered ID is invalid, please try again")
    return False

def sum_digits(n):
    """
    Digit sum helper function
    """
    s = 0
    while n:
        s += n % 10
        n //= 10
    return s

def is_valid_username(username):
    """
    Check if username is valid
    Has to be at least 4 long
    Only letters and numbers
    """
    if(len(username) >= 4 and username.isalnum()):
        return True
    else:
        messagebox.showinfo("Invalid Username", "Username does not meet requirements\nhas to be at least 4 long and contain only chars and numbers")
        return False

def is_valid_password(password):
    """
    Check if username is valid
    Has to be at least 8 long
    Has to contain upper letter
    Has to contain numbers
    """
    if(len(password) >= 8 and any(char.isupper() for char in password) and any(char.isdigit() for char in password)):
        return True
    else:
        messagebox.showinfo("Invalid Password", "Password does not meet requirements\nhas to be at least 8 long and contain at least 1 upper case and number")
        return False

def is_empty(list):
    """
    Checking list of strings for empty string
    """
    for item in list:
        if item == "":
            messagebox.showinfo("Invalid Input", f"Cannot have an empty field")
            return True
    return False

def has_illegal_chars(input_str):
    """
    Check if string has any of the illegal chars
    Illegal chars listed above in global vars
    """
    if(any(char in illegal_chars for char in input_str)):
        messagebox.showinfo("Invalid Input", f"No use of following chars:\n{illegal_chars}")
        return True
    return False

def check_illegal_chars(string_list):
    """
    Check if list of strings contains any illegal char
    Uses the has_illegal_chars function
    """
    return any(has_illegal_chars(s) for s in string_list)



def recv_rsa_key():
    """
    RSA key recieve from server
    Gets the length of the key in binary
    Gets the useable key and saves it as global var for future use
    """
    global s_public_key

    key_len_b = b""
    while(len(key_len_b) < len_field):   # Recieve the length of the key
        key_len_b += sock.recv(len_field - len(key_len_b))
    key_len = int(struct.unpack("!l", key_len_b)[0])

    key_binary = b""
    while(len(key_binary) < key_len):   # Recieve the key according to its length
        key_binary += sock.recv(key_len - len(key_binary))
    
    logtcp('recv', key_len_b + key_binary)
    s_public_key = rsa.PublicKey.load_pkcs1(key_binary)   # Save the key

def send_shared_secret():
    """
    Create and send the shared secret
    to server via secure rsa connection
    """
    global shared_secret
    shared_secret = os.urandom(16)
    key_to_send = rsa.encrypt(shared_secret, s_public_key)
    key_len = struct.pack("!l", len(key_to_send))
    to_send = key_len + key_to_send
    logtcp('sent', to_send)
    sock.send(to_send)



# Begin server replies handling functions

def protocol_parse_reply(reply):
    """
    Server reply parsing and handeling
    Checking error codes and respective answers to user
    Performing action according to response from server
    """
    try:
        to_show = 'Invalid reply from server'
        reply = reply.decode()   # Parse the reply and aplit it according to the protocol seperator
        fields = reply.split(sep)
        fields.pop(0)
        code = fields[0]
        if code == 'ERRR':   # If server returned error show to user the error
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
        

        # Handle each response accordingly
        elif code == 'EXTR':   # Server exit success
            to_show = 'Server acknowledged the exit message'
        
        elif code == 'LOGS':   # Login succeeded
            email = fields[1]
            username = fields[2]
            tz = fields[3]
            pwd = fields[4]
            to_show = f'Login was succesfull for user: {username}, password:{pwd}'
            user["email"] = email
            user["username"] = username
            user["tz"] = tz
            user["password"] = pwd
            show_logged_in_page()
        
        elif code == 'SIGS':   # Signup was performed
            email = fields[1]
            username = fields[2]
            tz = fields[3]
            pwd = fields[4]
            to_show = f'Signup was successful for user: {username}, password:{pwd}'
            show_main_page()
            messagebox.showinfo("Signup successful", f"Signup for user {username} completed.\nPlease verify your account")
        
        elif code == 'FOPR':   # Recovery mail sent
            to_show = f'Recovery email sent to: {fields[1]}'
            show_recovery_page(fields[1])
        
        elif code == 'PASS':   # Password was reset
            new_pwd = fields[2]
            to_show = f'Password was reset for user: {fields[1]}, new password: {new_pwd}'
            show_main_page()
        
        elif code == 'LUGR':   # Logout was performed
            to_show = f'Logout succesfull'
            show_main_page()
        
        elif code == 'VERS':   # Account verification mail sent
            email = fields[1]
            to_show = f'Verification sent to email {email}'
            show_account_verification_page(email)
        
        elif code == 'VERR':   # Verification succeeded
            username = fields[1]
            to_show = f'Verification for user {username} was succesfull'
            messagebox.showinfo("Verification successful", f"Verification for user {username} completed.\n You may now log in to your account")
            show_main_page()
        
        elif code == 'DELR':   # User deletion succeeded
            username = fields[1]
            to_show = f'User {username} was deleted'
            show_main_page()
        
    except Exception as e:   # Error
        print('Server replay bad format ' + str(e))
        print(traceback.format_exc())
    return to_show

def handle_reply():
    """
    Getting server reply and parsing it
    If some error occured or no response disconnect
    """
    try:
        reply = recv_data()
        logtcp('recv', reply)

        to_show = protocol_parse_reply(reply)
        if to_show != '':   # If got a reply, show it in console
            print('\n==========================================================')
            print(f'  SERVER Reply: {to_show}')
            print('==========================================================')
        if to_show == "Server acknowledged the exit message":   # If exit request succeded, dissconnect
            print('Will exit ...')
            sock.close()
            print("Bye...")
            sys.exit(0)
    except socket.error as err:   # General error handling
        print(f'Got socket error: {err}')
        return
    except Exception as err:
        print(f'General error: {err}')
        print(traceback.format_exc())
        return



# Begin data handling and processing functions 

def logtcp(dir, byte_data):
    """
    Loggs the recieved data to console
    """
    try:
        if (str(byte_data[0]) == "0"):
            print("")
    except AttributeError:
        return
    if dir == 'sent':   # Sen/recieved labels
        print(f'C LOG:Sent     >>>{byte_data}')
    else:
        print(f'C LOG:Recieved <<<{byte_data}')
        


def send_data(bdata):
    """
    Send data to server
    Adds data encryption
    Adds length
    Loggs the encrypted and decrtpted data for readablity
    """
    encrypted_data = encrypting.encrypt(bdata, shared_secret)
    data_len = struct.pack('!l', len(encrypted_data))

    to_send_encrypted = data_len + sep.encode() + encrypted_data.encode()
    to_send_decrypted = str(len(bdata)).encode() + sep.encode() + bdata

    sock.send(to_send_encrypted)
    logtcp('sent', to_send_encrypted)
    logtcp('sent', to_send_decrypted)

def recv_data():
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
        
        logtcp('recv', b_len + sep.encode() + msg)   # Log encrypted data
        msg = encrypting.decrypt(msg, shared_secret).encode()
        entire_data += msg
        return entire_data
    
    except Exception as err:
        print(traceback.format_exc())



# Main function and start of code

def main(addr):
    """
    Main function
    Create tkinter root and start secure connection to server
    Connect to server via addr param
    """
    global sock
    global root
    sock = socket.socket()
    try:
        sock.connect(addr)
        print(f'Connect succeeded {addr}')
    except:
        print(
            f'Error while trying to connect.  Check ip or port -- {addr}')
        return
    try:
        recv_rsa_key()
        send_shared_secret()
        create_root()
        create_style()
        show_main_page()
        root.mainloop()
    except Exception as e:
        print("Error:" + str(e))
        print(traceback.format_exc())

if __name__ == "__main__":   # Run main
    main(("127.0.0.1", 31026))
