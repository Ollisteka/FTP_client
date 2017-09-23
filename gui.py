import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
from tkinter import messagebox
from ftp import FTP
from errors import *
import threading
import queue
import time


class LoginWindow:
    def __init__(self, con):
        self.main = tk.Tk()
        self.con = con

    def login(self, username, password):
        self.con.user(username)
        self.con.password(password)
        FolderWindow(self.con).run()

    def make_first_window(self):
        username = tk.Entry(self.main)
        username.insert(0, 'anonymous')
        username.pack()
        password = tk.Entry(self.main, show="*")
        password.insert(0, 'password')
        password.pack()
        login = tk.Button(self.main, text="LOGIN",
                          command=lambda: self.login(username.get(), password.get()))
        login.pack()

    def run(self):
        self.make_first_window()
        self.main.mainloop()


class DownloadWindow:
    def __init__(self, con, filepath, filename):
        self.main = tk.Tk()
        self.con = con
        self.filename = filename
        self.filepath = filepath

    # Define your Progress Bar function,
    def task(self):
        pb_hD = ttk.Progressbar(self.main, orient='horizontal', mode='indeterminate')
        pb_hD.pack(expand=True, fill=tk.BOTH, side=tk.TOP)
        pb_hD.start(50)
        self.main.mainloop()

    def download_file(self):
        self.con.retr(self.filepath, self.filename)
        messagebox.showinfo(message="Download of {0} is complete".format(self.filepath))
        self.main.destroy()

    def run(self):
        t1 = threading.Thread(target=self.download_file, args=())
        t1.start()
        self.task()  # This will block while the mainloop runs
        t1.join()


class FolderWindow:
    def __init__(self, con):
        self.main = tk.Tk()
        self.con = con

    def move(self, path):
        try:
            self.con.cwd(path[1:] if len(path) > 1 else '..')
        except PermanentError as err:
            filename = filedialog.asksaveasfilename(initialfile=path[1:])
            if filename:
                DownloadWindow(self.con, path[1:], filename).run()

        self.main.destroy()
        self.main = tk.Tk()
        self.run()

    def list_dir(self):
        for line in self.con.list().split('\n'):
            btn = tk.Button(self.main, text=line,
                            command=lambda x=line: self.move('/'+x.split(' ')[-1].strip('\r')))
            btn.pack()

    def run(self):
        self.list_dir()
        self.main.mainloop()


class Window:
    con = None
    main = tk.Tk()

    def run_connection(self):
        while not self.con.closed:
            list = self.con.list()
            list_text = tk.Label(self.main, text=list)
            list_text.pack()

    def make_connection(self, address, port):
        self.con = FTP(address, int(port))
        self.con.connect()
        LoginWindow(self.con).run()

    def make_first_window(self):
        address = tk.Entry(self.main)
        address.insert(0, '212.193.68.227')
        address.pack()
        port = tk.Entry(self.main)
        port.insert(0, '21')
        port.pack()
        login = tk.Button(self.main, text="LOGIN",
                          command=lambda: self.make_connection(address.get(), port.get()))
        login.pack()

    def run(self):
        self.main.mainloop()

window = Window()
window.make_first_window()
window.run()
