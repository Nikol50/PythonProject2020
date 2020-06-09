from tkinter import *
from tkinter import filedialog
from client_class import client_file

class Windows():
   def __init__(self):
        self.name = "None"
        self.save_path = "None"
        self.send = "all"
        self.main_screen = Tk()
        self.main_screen.geometry("550x650")
        self.main_screen.title("Account Login")
        self.main_screen.configure(bg='MediumOrchid2')
        self.main_screen.iconbitmap(r'MY_LOCK.ico')
        self.main_screen.resizable(0, 0)
        logo = PhotoImage(file='logo3.png')
        label = Label(self.main_screen, image=logo, bg='MediumOrchid2')
        label.pack()
        Button(text="Login", bg="palevioletred1", height="2", width="30", fg="white", command=self.login,
               font=("Helvetica", 11, "bold italic")).pack()
        Label(text="", bg='MediumOrchid2').pack()
        Button(text="Register", bg="DarkOrchid4", height="2", width="30", fg="white",
               command=self.register, font=("Helvetica", 11, "bold italic")).pack()
        self.create_client()
        self.main_screen.mainloop()

   def gui_main2(self):
        self.name = "None"
        self.save_path = "None"
        self.send = "all"
        self.main_screen.geometry("550x650")
        self.main_screen.title("Account Login")
        self.main_screen.configure(bg='MediumOrchid2')
        self.main_screen.iconbitmap(r'MY_LOCK.ico')
        self.main_screen.resizable(0, 0)
        logo = PhotoImage(file='logo3.png')
        label = Label(self.main_screen, image=logo, bg='MediumOrchid2')
        label.pack()
        Button(text="Login", bg="palevioletred1", height="2", width="30", fg="white", command=self.login,
               font=("Helvetica", 11, "bold italic")).pack()
        Label(text="", bg='MediumOrchid2').pack()
        Button(text="Register", bg="DarkOrchid4", height="2", width="30", fg="white",
               command=self.register, font=("Helvetica", 11, "bold italic")).pack()
        self.main_screen.mainloop()

   def new_screen(self):
       self.main_screen.destroy()
       self.main_screen = Tk()

   def register(self):
       self.new_screen()
       # register_screen = Toplevel(self.main_screen)
       self.main_screen.title("Register")
       self.main_screen.configure(bg='MediumOrchid2')
       self.main_screen.geometry("400x400")
       self.main_screen.resizable(0, 0)
       self.main_screen.iconbitmap(r'MY_LOCK.ico')

       global userId
       global username
       global password
       global username_entry
       global password_entry
       global userId_entry
       userId = StringVar()
       username = StringVar()
       password = StringVar()

       Label(self.main_screen, text="Please enter details below", font=('Calibri', 20), bg="MediumOrchid2",
             fg="white").pack()
       Label(self.main_screen, text="", bg="MediumOrchid2").pack()

       userId_lable = Label(self.main_screen, text="UserId", font=('Calibri', 15), bg="MediumOrchid2", fg="white")
       userId_lable.pack()
       userId_entry = Entry(self.main_screen, textvariable=userId, font=('Calibri', 15), bg="DarkOrchid4", fg="white")
       userId_entry.pack()

       username_lable = Label(self.main_screen, text="Username", font=('Calibri', 15), bg="MediumOrchid2", fg="white")
       username_lable.pack()
       username_entry = Entry(self.main_screen, textvariable=username, font=('Calibri', 15), bg="DarkOrchid4",
                              fg="white")
       username_entry.pack()

       password_lable = Label(self.main_screen, text="Password", font=('Calibri', 15), bg="MediumOrchid2", fg="white")
       password_lable.pack()
       password_entry = Entry(self.main_screen, textvariable=password, font=('Calibri', 15), show='*', bg="DarkOrchid4",
                              fg="white")
       password_entry.pack()

       Label(self.main_screen, text="", bg="MediumOrchid2").pack()
       Button(self.main_screen, text="Register", width=8, height=1, bg="palevioletred1", fg="white",
              font=('Calibri', 17), command=self.register_user).pack()

       Label(self.main_screen, text="", height=2, bg='MediumOrchid2').pack()
       Label(self.main_screen, text=" ", bg='MediumOrchid2', width=2).pack(side=LEFT)

       Label(self.main_screen, text=" ", bg='MediumOrchid2', width=2).pack(side=RIGHT)
       Button(self.main_screen, text='Login', bg='palevioletred1', font=('Calibri', 14), fg="white", width=5,
              command=self.login).pack(side=RIGHT)
   # Designing window for login

   def back1(self):
       self.main_screen.destroy()
       self.__init__()

   def login(self):
       self.new_screen()
       self.main_screen.title("Login")
       self.main_screen.geometry("500x540")
       self.main_screen.configure(bg='MediumOrchid3')
       self.main_screen.resizable(0, 0)
       self.main_screen.iconbitmap(r'MY_LOCK.ico')

       Label(self.main_screen, text="Please enter details below to login", font=('Calibri', 18), bg="MediumOrchid3",
             fg="white").pack()
       Label(self.main_screen, text="", bg="MediumOrchid3").pack()

       global username_verify
       global password_verify
       global userId_verify

       username_verify = StringVar()
       password_verify = StringVar()
       userId_verify= StringVar()

       global username_login_entry
       global password_login_entry
       global userId_login_entry

       Label(self.main_screen, text="UserId", font=('Calibri', 15), bg="MediumOrchid3", fg="white").pack()
       userId_login_entry = Entry(self.main_screen, textvariable=userId_verify, font=('Calibri', 15), bg="DarkOrchid4",
                                  fg="white")
       userId_login_entry.pack()
       Label(self.main_screen, text="", bg="MediumOrchid3").pack()

       Label(self.main_screen, text="Username", bg="MediumOrchid3", font=('Calibri', 15), fg="white").pack()
       username_login_entry = Entry(self.main_screen, textvariable=username_verify, font=('Calibri', 15),
                                    bg="DarkOrchid4", fg="white")
       username_login_entry.pack()
       Label(self.main_screen, text="", bg="MediumOrchid3").pack()

       Label(self.main_screen, text="Password", bg="MediumOrchid3", font=('Calibri', 15), fg="white").pack()
       password_login_entry = Entry(self.main_screen, textvariable=password_verify, font=('Calibri', 15), show='*',
                                    bg="DarkOrchid4", fg="white")
       password_login_entry.pack()
       Label(self.main_screen, text="", bg="MediumOrchid3").pack()

       Label(self.main_screen, text="Location of saving files: ", font=('Calibri', 15), bg="MediumOrchid3", fg="white").pack()
       self.lable = Label(self.main_screen, text=self.save_path, font=('Calibri', 15), bg="MediumOrchid3", fg="white")
       Button(self.main_screen, text="Location", font=('Calibri', 15), width=10, height=1, command=self.pick_save_path,
              bg="palevioletred1", fg="white").pack()
       self.lable.pack()
       Label(self.main_screen, text="", bg="MediumOrchid3").pack()
       Button(self.main_screen, text="Login", width=10, height=1, font=('Calibri', 16), command=self.login_verify,
              bg="palevioletred1", fg="white").pack()
       self.lable2 = Label(self.main_screen, text="", bg="MediumOrchid3")
       self.lable2.pack()
       Label(self.main_screen, text=" ", bg='MediumOrchid3', width=2).pack(side=LEFT)
       Button(self.main_screen, text='Register', bg='palevioletred1', font=('Calibri', 14), fg="white", width=10,
              command=self.register).pack(side=LEFT)

   def register_user(self):
       # Implementing event on register button
       username_info = username.get()
       password_info = password.get()
       userId_info = userId.get()
       if username_info and password_info and userId_info and userId_info:
           check = self.client1.file_to_server("register", "", "", userId_info, username_info, password_info)
           if check==False:
               self.server_error()
           if self.client1.answer_login_register():
               username_entry.delete(0, END)
               password_entry.delete(0, END)
               userId_entry.delete(0, END)
               Label(self.main_screen, text="Registration Success", fg="green", font=("calibri", 11)).pack()
           else:
               self.user_not_found()
       else:
           self.user_not_found()

   # Implementing event on login button
   def login_verify(self):
       name = username_verify.get()
       password1 = password_verify.get()
       userId = userId_verify.get()
       if name and password1 and userId and self.save_path != "None":
           check = self.client1.file_to_server("login", "", "", userId, name, password1)
           if check==False:
               self.server_error()

           if self.client1.answer_login_register():
               self.lable2.configure(text="success", fg="green", font=('Calibri', 14))
               userId_login_entry.delete(0, END)
               username_login_entry.delete(0, END)
               password_login_entry.delete(0, END)
               # self.main_screen.destroy()
               #check = self.create_client()
               # self.main_screen.destroy()  -- newscreen
               self.name = name
               self.userId = userId
               self.login_sucess()
               self.main_menu()
           else:
               self.user_not_found()

       elif self.save_path == "None":
           self.lable2.configure(text="please pick a location to save your files", fg="red", font=('Calibri', 13))

       elif self.save_path != "None":
               self.lable2.configure(text="")

   def pick_save_path(self):
        self.main_screen.directory = filedialog.askdirectory()
        if self.main_screen.directory != "":
            self.save_path = self.main_screen.directory
            self.save_path = self.save_path.replace("/", "\\")
            self.lable.configure(text=str(self.save_path))
        try:
            self.client1.set_directory(self.save_path)
        except:
            print("wait")

   def main_menu(self):
       self.new_screen()
       self.main_screen.title("Menu")
       self.main_screen.geometry("400x700")
       self.main_screen.configure(bg='MediumPurple1')
       self.main_screen.resizable(0, 0)
       self.main_screen.iconbitmap(r'MY_LOCK.ico')
       Label(self.main_screen, bg='MediumPurple1', text="Hi "+str(self.name), fg="white", font=('Calibri', 40)).pack()
       label = Label(self.main_screen, text="Your Menu", bg='MediumPurple1', fg="white", font=('Calibri', 60))
       label.pack()
       Label(self.main_screen, bg='MediumPurple1', text="").pack()
       Button(self.main_screen, text="Connected Members", width=18, font=('Calibri', 14), height=2, bg="palevioletred1",
              fg="white", command=self.get_list).pack()
       Label(self.main_screen, bg='MediumPurple1', text="").pack()
       Button(self.main_screen, text="Send File Chat", width=18, height=2, bg="medium orchid", fg="white",
              font=('Calibri', 14), command=self.chat_message_screen).pack()
       Label(self.main_screen, bg='MediumPurple1', text="").pack()
       Button(self.main_screen, text="Send to...", width=18, height=2, bg="dark orchid", fg="white",
              font=('Calibri', 14), command=self.choose_send).pack()
       Label(self.main_screen, bg='MediumPurple1', text="").pack()
       Button(self.main_screen, text="Save...", width=18, height=2, bg='blue violet', fg="white", font=('Calibri', 14),
              command=self.files_new_path).pack()
       Label(self.main_screen, bg='MediumPurple1', text="").pack()
       Button(self.main_screen, text="Log Out", width=18, height=2, bg='purple4', fg="white", font=('Calibri', 14),
              command=self.log_out).pack()
       Label(self.main_screen, bg='MediumPurple1', text="").pack()
       Button(self.main_screen, text="Help", width=18, height=2, bg='magenta4', fg="white", font=('Calibri', 14),
              command=self.help).pack()

   def log_out(self):
       #self.new_screen()
       #check = self.client1.file_to_server("log out")
       self.client1.client_log_out()
       #if check==False:
       #    self.server_error()
       #else:
       self.back1()

   def help(self):
       self.new_screen()
       self.main_screen.title("Help")
       self.main_screen.geometry("1050x300")
       self.main_screen.resizable(0, 0)
       self.main_screen.iconbitmap(r'MY_LOCK.ico')
       logo = PhotoImage(file='instructions.png')
       label = Label(self.main_screen, image=logo, bg='MediumOrchid2')
       label.pack()
       mypathSaveButton = Button(self.main_screen, text="BACK", bg="DarkOrchid4", fg="white", font=('Calibri', 16),
                                 command=self.chat_message_screen)
       mypathSaveButton.pack(side=BOTTOM, fill=X)
       self.main_screen.mainloop()

   def get_list(self):
       check=self.client1.file_to_server("list")
       if check==False:
           self.server_error()
       list = self.client1.receive_list_connected()
       if list== False:
           self.server_error()
           pass
       global all_connected_screen
       all_connected_screen = Toplevel(self.main_screen)
       all_connected_screen.title("Friends")
       all_connected_screen.geometry("250x250")
       all_connected_screen.resizable(0, 0)
       all_connected_screen.iconbitmap(r'MY_LOCK.ico')
       scroll = Scrollbar(all_connected_screen)
       scroll.pack(side=RIGHT, fill=Y)
       text2 = Text(all_connected_screen, height=27, bg='DarkOrchid1', fg='white', yscrollcommand=scroll.set,
                    font=('Calibri', 15))
       text2.config(state=DISABLED)
       text2.pack(side=BOTTOM, fill=X)
       zero_connected = "No connected employs"
       connected = "Connected Employs:"
       if len(list) == int(0):
           text2.configure(state='normal')
           text2.insert(INSERT, '%s\n' % str(zero_connected))
           text2.configure(state='disabled')
           text2.see('end')
       else:
           text2.configure(state='normal')
           text2.insert(INSERT, '%s\n' % str(connected))
           text2.configure(state='disabled')
           text2.see('end')
           for member in list:
               print('got new message')
               text2.configure(state='normal')
               if member != self.name:
                   text2.insert(INSERT, '%s\n' % str(member))
                   text2.configure(state='disabled')
                   text2.see('end')

   def chat_message_screen(self):
       self.new_screen()
       global message_screen
       global mypathEntry
       global text
       self.main_screen.geometry("500x500")
       self.main_screen.title("File Chat")
       self.main_screen.resizable(0, 0)
       self.main_screen.iconbitmap(r'MY_LOCK.ico')
       menubar = Menu(self.main_screen)

       filemenu = Menu(menubar, tearoff=0)
       filemenu.add_command(label="Connected Members", command=self.get_list)
       filemenu.add_command(label="Send to...", command=self.choose_send)
       filemenu.add_command(label="Save...", command=self.files_new_path)
       filemenu.add_command(label="Log out", command=self.log_out)
       filemenu.add_separator()
       filemenu.add_command(label="Back", command=self.main_menu)
       menubar.add_cascade(label="Menu", menu=filemenu)

       helpmenu = Menu(menubar, tearoff=0)
       helpmenu.add_command(label="Instructions", command=self.help)
       menubar.add_cascade(label="Help", menu=helpmenu)

       self.main_screen.config(menu=menubar)

       mypathLabel = Label(self.main_screen, text="Hi "+str(self.name) + ':) Welcome to the chat', font=('Calibri', 16),
                           bg='DarkOrchid1', fg="white").pack()
       mypathSaveButton = Button(self.main_screen, text="Pick File", bg="DarkOrchid4", fg="white", font=('Calibri', 16),
                                 command=self.Choosefile)

       scroll = Scrollbar(self.main_screen)
       scroll.pack(side=RIGHT, fill=Y)

       text = Text(self.main_screen, height=27, bg='DarkOrchid1', fg='white', yscrollcommand=scroll.set, font=('Calibri',16))
       text.config(state=DISABLED)

       mypathSaveButton.pack(side=BOTTOM, fill=X)
       text.pack(side=BOTTOM, fill=X)

       self.main_screen.after(1000, self.refresh)

   def files_new_path(self):
       global files_screen
       files_screen = Toplevel(self.main_screen)
       files_screen.resizable(0, 0)
       files_screen.iconbitmap(r'MY_LOCK.ico')
       self.lable = Label(files_screen, text=self.save_path, font=('Calibri', 15), bg="red", fg="white")
       self.lable.pack(padx=5, pady=10, side=LEFT)
       Button(files_screen, text="change", bg="black", fg="white"
              , command=self.pick_save_path).pack(padx=5, pady=10, side=LEFT)

   def login_sucess(self):
       #Designing popup for login success
       global login_success_screen
       login_success_screen = Toplevel(self.main_screen)
       login_success_screen.title("Success")
       login_success_screen.geometry("150x100")
       login_success_screen.resizable(0, 0)
       login_success_screen.iconbitmap(r'MY_LOCK.ico')

       Label(login_success_screen, text="Login Success").pack()
       Button(login_success_screen, text="OK", command=self.delete_login_success).pack()

   def password_not_recognised(self):
       # Designing popup for login invalid password
       global password_not_recog_screen
       password_not_recog_screen = Toplevel(self.main_screen)
       password_not_recog_screen.title("Success")
       password_not_recog_screen.geometry("150x100")
       Label(password_not_recog_screen, text="Invalid Password ").pack()
       Button(password_not_recog_screen, text="OK", command=self.delete_password_not_recognised).pack()

   def user_not_found(self):
       # Designing popup for user not found
       global user_not_found_screen
       user_not_found_screen = Toplevel(self.main_screen)
       user_not_found_screen.title("Success")
       user_not_found_screen.geometry("150x100")
       user_not_found_screen.resizable(0, 0)
       user_not_found_screen.iconbitmap(r'MY_LOCK.ico')
       Label(user_not_found_screen, text="User Not Found").pack()
       Button(user_not_found_screen, text="OK", command=self.delete_user_not_found_screen).pack()

   def server_error(self):
       global server_error_screen
       server_error_screen = Toplevel(self.main_screen)
       server_error_screen.title("ERROR")
       server_error_screen.geometry("150x100")
       server_error_screen.resizable(0, 0)
       server_error_screen.iconbitmap(r'MY_LOCK.ico')
       Label(server_error_screen, text="Server not responding").pack()
       Button(server_error_screen, text="OK", command=self.delete_server_error_screen).pack()

   def create_client(self):
       try:
           self.client1 = client_file("None")
       except:
           self.server_error()

   def refresh(self):
       while True:
           try:
               u, msg = self.client1.recieve_files()
               self.get_message(u, msg)
           except:
               break

       self.main_screen.after(500, self.refresh)

   def get_message(self, user, new_message):
       print('got new message')
       text.configure(state='normal')
       on_screen = str(user) + "< " + str(new_message)
       text.insert(INSERT, '%s\n' % on_screen)
       text.configure(state='disabled')
       mypathEntry.delete('0', 'end')
       text.see('end')

   def get_file(self, new_file):
       print('SEND')
       text.configure(state='normal')
       on_screen = str(self.name) + "< " + str(new_file)
       text.insert(INSERT, '%s\n' % on_screen)
       text.configure(state='disabled')
       #mypathEntry.delete('0', 'end')
       text.see('end')
       file_name = new_file.replace("/", "\\")
       check=self.client1.file_to_server("new file", file_name, self.send)
       if check==False:
           self.server_error()
       self.refresh()

   def Choosefile(self):
       self.main_screen.filename = filedialog.askopenfilename(initialdir="/", title="Select file",
                                                              filetypes=(("all files", ".*"), ("all files", ".*")))
       if self.main_screen.filename:
           self.get_file(self.main_screen.filename)

   def delete_login_success(self):
       login_success_screen.destroy()

   def delete_server_error_screen(self):
       server_error_screen.destroy()

   def delete_user_not_found_screen(self):
       user_not_found_screen.destroy()

   def delete_password_not_recognised(self):
       password_not_recog_screen.destroy()

   def sel(self):
       selection = "You selected the option " + str(self.var.get())
       self.pick_label.config(text=selection)
       self.send = self.var.get()
       print(self.send)

   def choose_send(self):
       root = Toplevel(self.main_screen)
       root.resizable(0, 0)
       root.iconbitmap(r'MY_LOCK.ico')
       root.title("Send to...")
       scroll = Scrollbar(root)
       scroll.pack(side=RIGHT, fill=Y)
       root.configure(bg='DarkOrchid1')
       check=self.client1.file_to_server("list", "", "", "", "", "")
       if check==False:
           self.server_error()
           pass
       list = self.client1.receive_list_connected()
       if list==False:
           self.server_error()
           pass
       self.var = StringVar()
       list.append("all")
       self.var.set(list[list.index(self.send)])
       for item in list:
           if self.name != item:
               button = Radiobutton(root, text=item, variable=self.var, bg='DarkOrchid1', value=item, command=self.sel, font=('Calibri', 13))
               button.pack(anchor=W)

       self.pick_label = Label(root, font=('Calibri', 15), bg='DarkOrchid1')
       self.pick_label.pack()

x = Windows()
