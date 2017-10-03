#!/usr/bin/env python3

import socket
import os
from socket import _GLOBAL_DEFAULT_TIMEOUT
import re
import getpass
import click
from errors import PermanentError, ProtectedError, TransientError


FTP_PORT = 21
MAXLENGTH = 8192

CRLF = '\r\n'
B_CRLF = b'\r\n'

TIMEOUT = _GLOBAL_DEFAULT_TIMEOUT

ENCODING = "utf8"


class FTP:
    welcome = None
    data_socket = None
    closed = False
    binary = False

    def quit(self):
        rep = self.send("QUIT" + CRLF)
        self.closed = True
        print(rep)

    def pasv(self):
        self.passive = True
        rep = self.send("PASV" + CRLF)
        print(rep)
        res = re.findall(r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', rep)[0]
        ip_address = '.'.join(res[:4])
        port_number = int(res[4]) * 256 + int(res[5])
        self.data_socket = socket.socket()
        self.data_socket.settimeout(TIMEOUT)
        self.data_socket.connect((ip_address, port_number))

    def port(self):
        ip_address = self.control_socket.getsockname()[0].split('.')
        self.data_socket = socket.socket()
        self.data_socket.bind(('', 0))
        self.data_socket.listen()
        port = self.data_socket.getsockname()[1]
        splited_port = [str(port // 256), str(port % 256)]
        reply = self.send("PORT " + ','.join(ip_address + splited_port) + CRLF)
        print(reply)

    def cwd(self, directory):
        rep = self.send("CWD " + directory + CRLF)
        print(rep)

    def type(self, con_type):
        rep = self.send("TYPE " + con_type + CRLF)
        print(rep)
        self.binary = True

    @staticmethod
    def __get_filename(file_path):
        split = os.path.split(file_path)
        return split[len(split) - 1]

    def retr(self, file_path, new_path=None):
        if self.passive:
            self.pasv()
        else:
            self.port()
        if not new_path:
            new_path = self.__get_filename(file_path)
        if os.path.isdir(new_path):
            new_path = os.path.join(new_path, self.__get_filename(file_path))
        size = self.size(file_path, silent=True)
        rep = self.send("RETR " + file_path + CRLF)
        print(rep)
        if not self.passive:
            self.data_socket = self.data_socket.accept()[0]
        with click.progressbar(length=int(size), label="Downloading file ") as bar:
            with open(new_path, 'wb') as file:
                for part in self.get_binary_data():
                    file.write(part)
                    bar.update(len(part))
        self.data_socket.close()
        rep = self.get_reply()
        print(rep)

    def list(self):
        if self.passive:
            self.pasv()
        else:
            self.port()
        rep = self.send("LIST" + CRLF)
        print(rep)
        if not self.passive:
            self.data_socket = self.data_socket.accept()[0]
        data = ''.join([part.decode(ENCODING)
                        for part in self.get_binary_data()])
        self.data_socket.close()
        print(data)
        rep = self.get_reply()
        print(rep)
        return data

    def user(self, name):
        rep = self.send("USER " + name + CRLF)
        print(rep)

    def password(self, password=None):
        if not password:
            password = getpass.getpass("Enter password: ")
            print()
        rep = self.send("PASS " + password + CRLF)
        print(rep)

    def size(self, file_path, silent=False):
        if not self.binary:
            self.type("I")
        rep, size = self.send("SIZE " + file_path + CRLF).split(' ')
        if not silent:
            print(rep + ' ' + size + 'bytes')
        return size

    def help(self):
        rep = self.send("HELP" + CRLF)
        print(rep)

    def send(self, command):
        self.control_socket.sendall(command.encode(ENCODING))
        return self.get_reply()

    def get_binary_data(self):
        while True:
            try:
                tmp = self.data_socket.recv(MAXLENGTH)
                if not tmp:
                    break
                yield tmp
            except TimeoutError:
                print("Timeout!")
                break

    def get_reply(self):
        reply = self.__get_full_reply()
        c = reply[:1]
        if c in {'1', '2', '3'}:
            return reply
        if c == '4':
            raise TransientError(reply)
        if c == '5':
            raise PermanentError(reply)
        raise ProtectedError(reply)

    def __get_full_reply(self):
        reply = ''
        tmp = self.control_socket.recv(MAXLENGTH).decode(ENCODING)
        reply += tmp
        reply_reg = re.compile(r'^\d\d\d .*$', re.MULTILINE)
        while not re.findall(reply_reg, tmp):
            try:
                tmp = self.control_socket.recv(MAXLENGTH).decode(ENCODING)
                reply += tmp
            except TimeoutError:
                print("Timeout!")
                break
        return reply

    def __init__(self, address, port, passive=True):
        self.address = (address, port)
        self.control_socket = socket.socket()
        self.passive = passive
        self.commands = {"QUIT": self.quit,
                         "LIST": self.list,
                         # "ABOR" : self.abor,
                         # "CDUP" : self.cdup,
                         "CWD": self.cwd,
                         # "DELE" : self.dele,
                         # "EPSV" : self.epsv,
                         "HELP": self.help,
                         # "MDTM" : self.mdtm,
                         # "MKD" : self.mkd,
                         # "NLST" : self.nlst,
                         # "NOOP" : self.noop,
                         "PASS": self.password,
                         "PASV": self.pasv,
                         # "PWD" : self.pwd,
                         # "REIN" : self.rein,
                         "RETR": self.retr,
                         "PORT": self.port,
                         # "RMD" : self.rmd,
                         # "RNFR" : self.rnfr,
                         # "RNTO" : self.rnto,
                         "SIZE": self.size,
                         # "STOR" : self.stor,
                         # "SYST" : self.syst,
                         "TYPE": self.type,
                         "USER": self.user,
                         }

    def connect(self):
        self.control_socket.connect(self.address)
        self.welcome = self.get_reply()
        print("WELCOME: ", self.welcome)

    def run(self):
        while not self.closed:
            print("Type a command:")
            inp = input().split(' ')
            command = inp[0]
            arguments = inp[1:]
            if command in self.commands:
                if arguments:
                    if len(arguments) == 1:
                        self.commands[command](arguments[0])
                    if len(arguments) == 2:
                        self.commands[command](arguments[0], arguments[1])
                else:
                    self.commands[command]()
            else:
                print("UNKNOWN COMMAND")
