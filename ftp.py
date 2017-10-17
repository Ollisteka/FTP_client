#!/usr/bin/env python3

import getpass
import os
import re
import socket
import tempfile
import threading
from sys import platform

from errors import PermanentError, ProtectedError, TransientError, Error

if platform.startswith("linux"):
    pass
elif platform == "win32":
    pass

FTP_PORT = 21
MAXLENGTH = 8192

CRLF = '\r\n'
B_CRLF = b'\r\n'

ENCODING = "utf8"


class FTP:
    welcome = None
    data_socket = None
    closed = False
    binary = False

    def quit(self, **kwargs):
        """
        End the session
        :return:
        """
        rep = self.send("QUIT" + CRLF)
        self.closed = True
        if self.data_socket:
            self.data_socket.close()
        self.control_socket.shutdown(socket.SHUT_RDWR)
        self.control_socket.close()
        return rep

    def pasv(self, output_func=None):
        """
        Enters passive mode (server sends the IP)
        :return:
        """
        self.passive = True
        rep = self.send("PASV" + CRLF)
        if output_func:
            output_func(rep)
        res = re.findall(r'(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)', rep)[0]
        ip_address = '.'.join(res[:4])
        port_number = int(res[4]) * 256 + int(res[5])
        self.data_socket = socket.socket()
        self.data_socket.settimeout(2)
        self.data_socket.connect((ip_address, port_number))
        return rep

    def port(self, output_func=None):
        """
        Enters active mode (client sends the IP)
        :return:
        """
        ip_address = self.control_socket.getsockname()[0].split('.')
        self.data_socket = socket.socket()
        self.data_socket.bind(('', 0))
        self.data_socket.listen()
        port = self.data_socket.getsockname()[1]
        splited_port = [str(port // 256), str(port % 256)]
        reply = self.send("PORT " + ','.join(ip_address + splited_port) + CRLF)
        if output_func:
            output_func(reply)
        return reply

    def cwd(self, directory, **kwargs):
        """
        Change directory
        :param directory:
        :return:
        """
        rep = self.send("CWD " + directory + CRLF)
        return rep

    def type(self, con_type, **kwargs):
        """
        Set type of data transfer
        :param con_type:
        :return:
        """
        rep = self.send("TYPE " + con_type + CRLF)
        if con_type == "I":
            self.binary = True
        elif con_type == "A":
            self.binary = False
        else:
            raise Exception("Only I or A arguments are approved")
        return rep

    @staticmethod
    def __get_filename(file_path):
        """
        Extract file name from a path
        :param file_path:
        :return:
        """
        if os.path.isdir(file_path):
            raise Exception("Name cannot be extracted, it's a directory")
        split = os.path.split(file_path)
        return split[len(split) - 1]

    def retr(self, file_path, new_path=None, output_func=None,
             download_func=None):
        """
        Download file from server file path to a new one
        (or current working directory)
        :param file_path:
        :param new_path:
        :return:
        """
        if not download_func:
            raise Exception("Specify how to download file")
        if self.passive:
            self.pasv()
        else:
            self.port()
        if not new_path:
            new_path = self.__get_filename(file_path)

        if isinstance(new_path ,tempfile._TemporaryFileWrapper):
            pass
        elif os.path.isdir(new_path):
            new_path = os.path.join(new_path, self.__get_filename(file_path))
        size = self.size(file_path, silent=True)
        rep = self.send("RETR " + file_path + CRLF)
        if output_func:
            output_func(rep)
        if not self.passive:
            self.data_socket = self.data_socket.accept()[0]
        # if self.verbose:
        #     with click.progressbar(length=int(size),
        #                            label="Downloading file ") as bar:
        #         with open(new_path, 'wb') as file:
        #             for part in self.get_binary_data():
        #                 file.write(part)
        #                 bar.update(len(part))
        # else:
        #     with open(new_path, 'wb') as file:
        #         for part in self.get_binary_data():
        #             file.write(part)
        download_func(size, new_path, self)
        self.data_socket.close()
        rep = self.get_reply()
        return rep

    def list(self, output_func=None):
        """
        List of items in a current folder
        :return:
        """
        if self.passive:
            self.pasv()
        else:
            self.port()
        rep = self.send("LIST" + CRLF)
        if output_func:
            output_func(rep)
        if not self.passive:
            self.data_socket = self.data_socket.accept()[0]
        data = ''.join([part.decode(ENCODING)
                        for part in self.get_binary_data()])
        self.data_socket.close()
        rep = self.get_reply()
        if output_func:
            output_func(data)
            output_func(rep)
        return data

    def user(self, name, **kwargs):
        """
        Send user's login
        :param name:
        :return:
        """
        rep = self.send("USER " + name + CRLF)
        return rep

    def password(self, password=None, **kwargs):
        """
        Send user's password. To enter secure mode you must type PASS and
        press enter.
        :param password:
        :return:
        """
        if not password:
            password = getpass.getpass("Enter password: ")
            print()
        rep = self.send("PASS " + password + CRLF)
        return rep

    def login(self, login, password):
        """
        Enters login and password simultaneously
        :param login:
        :param password:
        :return:
        """
        try:
            first_rep = self.user(login)
            second_rep = self.password(password)
            return first_rep + second_rep
        except Error as e:
            return "Login or password is incorrect"

    def size(self, file_path, silent=False, output_func=None):
        """
        Learn a size of a file
        :param file_path:
        :param silent:
        :return:
        """
        if not self.binary:
            self.type("I")
        rep, size = self.send("SIZE " + file_path + CRLF).split(' ')
        if not silent and output_func:
            output_func(rep + ' ' + size + 'bytes')
        return size

    def pwd(self, **kwargs):
        """
        Get a current working directory
        :return:
        """
        rep = self.send("PWD" + CRLF)
        return rep

    def help(self, **kwargs):
        """
        Get a help message
        :return:
        """
        rep = self.send("HELP" + CRLF)
        return rep

    def send(self, command):
        """
        Send a command to server
        :param command:
        :return:
        """
        with threading.Lock():
            self.control_socket.sendall(command.encode(ENCODING))
        return self.get_reply()

    def get_binary_data(self):
        """
        Get binary data piece by piece
        :return:
        """
        with threading.Lock():
            while True:
                try:
                    tmp = self.data_socket.recv(MAXLENGTH)
                    if not tmp:
                        break
                    yield tmp
                except TimeoutError:
                    break

    def get_reply(self):
        """
        Get a reply from server
        :return:
        """
        with threading.Lock():
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
        """
        Get a long reply
        :return:
        """
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

    def __init__(self, address=None, port=None, passive=True):
        if not address and not port:
            self.address = None
        else:
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
                         "PWD": self.pwd,
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

    def connect(self, address=None, port=None):
        """
        Connect to the server and print welcome message
        :return:
        """
        if not self.address:
            self.address = (address, port)
        elif not address and not port and not self.address:
            raise Exception("Address and port must be specified in "
                            "constructor or in connect()")
        self.control_socket.connect(self.address)
        self.welcome = self.get_reply()
        return self.welcome

    def run_batch(self, download_func):
        """
        Runs an ftp client in console mode
        :return:
        """
        while not self.closed:
            print("Type a command:")
            inp = input().split(' ')
            command = inp[0]
            arguments = inp[1:]
            if command in self.commands:
                if arguments:
                    if len(arguments) == 1:
                        print(self.commands[command](arguments[0],
                                                     output_func=print,
                                                     download_func=download_func))
                    if len(arguments) == 2:
                        print(self.commands[command](arguments[0],
                                                     arguments[1],
                                                     output_func=print,
                                                     download_func=download_func))
                else:
                    print(self.commands[command]())
            else:
                print("UNKNOWN COMMAND")

