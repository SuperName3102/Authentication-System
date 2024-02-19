# 2024 © Idan Hazay
# Import libraries
import tkinter as tk
from tkinter import ttk
from ttkthemes import ThemedTk
from tkinter.ttk import *
from modules import client as c

# Begin gui related functions

def create_root():
    """
    Create the root of the tkinter gui
    Global var to use in code
    """
    root = ThemedTk(theme="equilux")
    root.tk.call('tk', 'scaling', 1.5)
    root.configure(bg="#464646")
    return root

def create_style(root):
    """
    Create global styles for tkinter gui
    """
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

def show_main_page(root):
    """
    Show the main page of the gui
    Destroying all previous widgets
    """
    destroy_widgets(root)
    root.title("Authentication System")
    width, height = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{int(width/1.5)}x{int(height/1.5)}")
    
    ttk.Label(root, text="Idan's Login Server and Client", style="main.TLabel").pack(pady=30)   # Buttons for each page
    ttk.Button(root, text="Login", style="main.TButton" ,command=lambda: login_page(root)).pack(pady=15)
    ttk.Button(root, text="Signup",style="main.TButton", command=lambda: signup_page(root)).pack(pady=15)
    ttk.Button(root, text="Forgot Password",style="main.TButton", command=lambda: forgot_password_page(root)).pack(pady=15)
    ttk.Button(root, text="Verify",style="main.TButton", command=lambda: show_send_verification_code_page(root)).pack(pady=15)
    ttk.Button(root, text="Exit",style="main.TButton", command=lambda: c.exit_program()).pack(pady=15)


def login_page(root):
    """
    Show the login page of the gui
    Destroying all previous widgets
    """
    destroy_widgets(root)
    username = tk.StringVar()   # Creating tkinter string vars for inputs
    password = tk.StringVar()
    show_hide_var = tk.BooleanVar()
    
    ttk.Label(root, text="Login Page", style="main.TLabel").pack(pady=30)
    ttk.Label(root, text="Username:", style="sub.TLabel").pack()   # Username field and label
    ttk.Entry(root, textvariable=username, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=6)
    
    ttk.Label(root, text="Password:", style="sub.TLabel").pack()   # Password field and show/hide password switch
    password_entry = ttk.Entry(root, textvariable=password, show="*",style="field.TEntry", width=30, font=("calibri", 12))
    password_entry.pack(ipady=3, pady=2)
    ttk.Checkbutton(root, text="Show Password", variable=show_hide_var, style="check.TCheckbutton" ,command=lambda: toggle_password_visibility(password_entry, show_hide_var)).pack(pady=5)
    ttk.Label(root, text="").pack(pady=12)
    
    ttk.Button(root, text="Login", style="reg.TButton", command=lambda: c.login(username.get(), password.get())).pack()   
    ttk.Label(root, text="").pack(pady=8)   # Login and back buttons
    ttk.Button(root, text="Back to Main Page",style="reg.TButton", command=lambda: show_main_page(root)).pack()

def signup_page(root):
    """
    Show the signup page of the gui
    Destroying all previous widgets
    """
    destroy_widgets(root) 
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
    
    ttk.Button(root, text="Signup", command=lambda: c.signup(email.get(), username.get(), tz.get(), password.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=4)   # Signup and back buttons
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(root), style="reg.TButton").pack()

def forgot_password_page(root):
    """
    Show the forgot password page of the gui
    Destroying all previous widgets
    """
    destroy_widgets(root)
    email = tk.StringVar()   # Creating tkinter string vars for inputs
    
    ttk.Label(root, text="Forgot Password Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="Email:", style="sub.TLabel").pack()   # Email field and label
    ttk.Entry(root, textvariable=email, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=10)
    
    ttk.Button(root, text="Send Reset Code", command=lambda: c.reset_password(email.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)   # Send reset code and back buttons 
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(root), style="reg.TButton").pack()

def show_logged_in_page(root):
    """
    Show the logged in page of the gui
    Destroying all previous widgets
    Showing user details
    """
    destroy_widgets(root)
    ttk.Label(root, text=f"Welcome, {user["username"]}", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text=f"Email: {user["email"]}", style="sub.TLabel").pack(pady=10)
    ttk.Label(root, text=f"ID: {user["tz"]}", style="sub.TLabel").pack(pady=10)
    ttk.Label(root, text=f"Password: {user["password"]}", style="sub.TLabel").pack(pady=10)
    ttk.Button(root, text="Logout", command=lambda: c.logout(), style="reg.TButton").pack(pady=10)
    ttk.Button(root, text="Delete User", command=lambda: c.delete_user(user["username"]), style="reg.TButton").pack()

def show_recovery_page(root, email):
    """
    Show the password recovery page of the gui
    Destroying all previous widgets
    """
    destroy_widgets(root)
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
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(root), style="reg.TButton").pack()

def show_send_verification_code_page(root):
    """
    Show the send account verification code page of the gui
    Destroying all previous widgets
    """
    destroy_widgets(root)
    email = tk.StringVar()   # Creating tkinter string vars for inputs
    
    ttk.Label(root, text="Verification Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="Email:", style="sub.TLabel").pack()   # Email field and label
    ttk.Entry(root, textvariable=email, style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)
    ttk.Label(root, text="").pack(pady=5)
    
    ttk.Label(root, text="").pack(pady=8)
    ttk.Button(root, text="Verify", command=lambda: send_verification(email.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)   # Send verification code and back buttons 
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(root), style="reg.TButton").pack()

def show_account_verification_page(root, email):
    """
    Show the account verification page of the gui
    Destroying all previous widgets
    """
    destroy_widgets(root)
    code = tk.StringVar()   # Creating tkinter string vars for inputs
    
    ttk.Label(root, text="Verification Page", style="main.TLabel").pack(pady=35)
    ttk.Label(root, text="").pack(pady=5)
    ttk.Label(root, text="Code:", style="sub.TLabel").pack()   # Verification code field and label
    ttk.Entry(root, textvariable=code,style="field.TEntry", width=30, font=("calibri", 12)).pack(ipady=3, pady=2)

    ttk.Label(root, text="").pack(pady=8)
    ttk.Button(root, text="Verify", command=lambda: send_verify_code(email, code.get()), style="reg.TButton").pack()
    ttk.Label(root, text="").pack(pady=5)   # Send verification code and back buttons 
    ttk.Button(root, text="Back to Main Page", command=lambda: show_main_page(root), style="reg.TButton").pack()

def destroy_widgets(root):
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