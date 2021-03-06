#!/usr/bin/env python3

import getpass
import os
import re
import socket
import tempfile
import threading
import types
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

ENCODING = "cp1251"
LOCK = threading.Lock()


class FTP:
    welcome = None
    data_socket = None
    closed = False
    binary = False

    def ftp_quit(self, **kwargs):
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

    def ftp_pasv(self, output_func=None):
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

    def ftp_port(self, output_func=None):
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

    def ftp_cdup(self, **kwargs):
        """
        Change to parent directory
        :return:
        """
        rep = self.send("CDUP" + CRLF)
        return rep

    def ftp_cwd(self, directory, **kwargs):
        """
        Change directory
        :param directory:
        :return:
        """
        rep = self.send("CWD " + directory + CRLF)
        return rep

    def ftp_type(self, con_type, **kwargs):
        """
        Set ftp_type of data transfer
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

    def extract_path_from_pwd_reply(self):
        path = re.findall(r'.*\"/?\\?(.*)\".*', self.ftp_pwd())
        return path[0]

    def ftp_stor(self, local_path, server_path=None, load_func=None,
                 output_func=None, **kwargs):
        """
        Load file to server
        :param local_path:
        :param server_path:
        :param output_func:
        :return:
        """
        if not load_func:
            raise Exception("Specify how to load file")
        if self.passive:
            self.ftp_pasv()
        else:
            self.ftp_port()
        if not server_path:
            server_path = self.extract_path_from_pwd_reply()

        if isinstance(server_path, tempfile._TemporaryFileWrapper):
            pass
        elif os.path.isdir(server_path):
            server_path = os.path.join(server_path,
                                       self.__get_filename(local_path))

        size = os.path.getsize(local_path)
        rep = self.send("STOR " + server_path + CRLF)
        if output_func:
            output_func(rep)
        if not self.passive:
            self.data_socket = self.data_socket.accept()[0]
        load_func(size, local_path, self)
        self.data_socket.close()
        rep = self.get_reply()
        return rep

    def ftp_retr(self, server_path, local_path=None, output_func=None,
                 download_func=None, **kwargs):
        """
        Download file from server file path to a new one
        (or current working directory)
        :param download_func: how the file will be downloaded
        :param output_func: where some output will go
        :param server_path:
        :param local_path:
        :return:
        """
        if not download_func:
            raise Exception("Specify how to download_from_server file")
        if self.passive:
            self.ftp_pasv()
        else:
            self.ftp_port()
        if not local_path:
            local_path = self.__get_filename(server_path)

        if isinstance(local_path, tempfile._TemporaryFileWrapper):
            pass
        elif os.path.isdir(local_path):
            local_path = os.path.join(local_path,
                                      self.__get_filename(server_path))
        size = self.ftp_size(server_path, silent=True)
        rep = self.send("RETR " + server_path + CRLF)
        if output_func:
            output_func(rep)
        if not self.passive:
            self.data_socket = self.data_socket.accept()[0]
        download_func(size, local_path, self)
        self.data_socket.close()
        rep = self.get_reply()
        return rep

    def ftp_nlst(self, output_func=None):
        """
        List of items in shorter form
        :param output_func:
        :return:
        """
        return self._retr_lines("NLST", output_func)

    def ftp_list(self, output_func=None):
        """
        List directories in lon format
        :param output_func:
        :return:
        """
        return self._retr_lines("LIST", output_func)

    def _retr_lines(self, command, output_func=None):
        """
        List of items in a current folder
        :return:
        """
        if self.passive:
            self.ftp_pasv()
        else:
            self.ftp_port()
        rep = self.send(command + CRLF)
        if output_func:
            output_func(rep)
        if not self.passive:
            self.data_socket = self.data_socket.accept()[0]
        data = ''.join([part.decode(ENCODING, errors='strict')
                        for part in self.get_binary_data()])
        self.data_socket.close()
        rep = self.get_reply()
        if output_func:
            output_func(data)
            output_func(rep)
        return data

    def ftp_user(self, name, **kwargs):
        """
        Send ftp_user's login
        :param name:
        :return:
        """
        rep = self.send("USER " + name + CRLF)
        return rep

    def ftp_pass(self, password=None, **kwargs):
        """
        Send ftp_user's ftp_pass. To enter secure mode you must ftp_type PASS and
        press enter.
        :param password:
        :return:
        """
        if not password:
            password = getpass.getpass("Enter ftp_pass: ")
            print()
        rep = self.send("PASS " + password + CRLF)
        return rep

    def login(self, login, password):
        """
        Enters login and ftp_pass simultaneously
        :param login:
        :param password:
        :return:
        """
        try:
            first_rep = self.ftp_user(login)
            second_rep = self.ftp_pass(password)
            return first_rep + second_rep
        except Error as e:
            return "Login or ftp_pass is incorrect"

    def ftp_size(self, file_path, silent=False, output_func=None, **kwargs):
        """
        Learn a ftp_size of a file
        :param file_path:
        :param silent: don't show the ftp_size directly
        :param output_func: where some output will go
        :return:
        """
        if not self.binary:
            self.ftp_type("I")
        rep, size = self.send("SIZE " + file_path + CRLF).split(' ')
        if not silent and output_func:
            output_func(rep + ' ' + size + 'bytes')
        return size

    def ftp_pwd(self, **kwargs):
        """
        Get a current working directory
        :return:
        """
        rep = self.send("PWD" + CRLF)
        return rep

    def ftp_feat(self, **kwargs):
        """
        Get the feature ftp_list implemented by the server.
        :param kwargs:
        :return:
        """
        rep = self.send("FEAT" + CRLF)
        return rep

    def ftp_mkd(self, directory, **kwargs):
        """
        Make new directory
        :param directory:
        :param kwargs:
        :return:
        """
        rep = self.send("MKD " + directory + CRLF)
        return rep

    def ftp_mdtm(self, filename, **kwargs):
        """
        Return the last-modified time of a specified file.
        :param filename:
        :param kwargs:
        :return:
        """
        rep = self.send("MDTM " + filename + CRLF)
        return rep

    def ftp_rmd(self, directory, **kwargs):
        """
        Remove directory
        :param directory:
        :param kwargs:
        :return:
        """
        rep = self.send("RMD " + directory + CRLF)
        return rep

    def ftp_dele(self, file, **kwargs):
        """
        Delete file
        :param file:
        :param kwargs:
        :return:
        """
        rep = self.send("DELE " + file + CRLF)
        return rep

    def ftp_rnfr(self, old_name, **kwargs):
        """
        Rename file or folder. Must be called immediately before RNTO command
        :param old_name:
        :param kwargs:
        :return:
        """
        rep = self.send("RNFR " + old_name + CRLF)
        return rep

    def ftp_rnto(self, new_name, **kwargs):
        """
        Rename file or folder. Must be called immediately after RNFR command
        :param new_name:
        :param kwargs:
        :return:
        """
        rep = self.send("RNTO " + new_name + CRLF)
        return rep

    def ftp_noop(self, **kwargs):
        """
        Send empty command, to keep connection alive
        :return:
        """
        rep = self.send("NOOP" + CRLF)
        return rep

    def ftp_opts(self, feature, cmd, **kwargs):
        """
        Select options for a feature
        :param cmd:
        :param feature:
        :param kwargs:
        :return:
        """
        rep = self.send(" ".join(["OPTS", feature, cmd]) + CRLF)
        return rep

    def ftp_syst(self, **kwargs):
        """
        Return system ftp_type.
        :return:
        """
        rep = self.send("SYST" + CRLF)
        return rep

    def ftp_help(self, **kwargs):
        """
        Get a ftp_help message
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
        with LOCK:
            self.control_socket.sendall(command.encode(ENCODING))
        return self.get_reply()

    def get_binary_data(self):
        """
        Get binary data piece by piece
        :return:
        """
        with LOCK:
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
        with LOCK:
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
        self.commands = self.__fill_commands()

    @staticmethod
    def __fill_commands():
        """
        Adds all FTP commands to a dict :Name -> function:.
        :return:
        # """
        commands = {}
        all_methods = [obj for obj in FTP.__dict__
                       if isinstance(FTP.__dict__.get(obj), types.FunctionType)
                       and obj.startswith("ftp_")]

        for method in all_methods:
            command = method[4:].upper()
            commands[command] = FTP.__dict__.get(method)
        return commands

    def connect(self, address=None, port=None):
        """
        Connect to the server and print welcome message
        :return:
        """
        if not self.address:
            self.address = (address, port)
        elif not address and not port and not self.address:
            raise Exception("Address and ftp_port must be specified in "
                            "constructor or in connect()")
        self.control_socket.connect(self.address)
        self.welcome = self.get_reply()
        return self.welcome

    def run_batch(self, download_func, load_func):
        """
        Runs an ftp client in console mode
        :return:
        """
        while not self.closed:
            print("Type a command:")
            inp = input().split(' ')
            command = inp[0].upper()
            arguments = inp[1:]
            if command in self.commands:
                if arguments:
                    if len(arguments) == 1:
                        print(
                            self.commands[command](self,
                                                   arguments[0],
                                                   output_func=print,
                                                   download_func=download_func,
                                                   load_func=load_func))
                    if len(arguments) == 2:
                        print(
                            self.commands[command](self,
                                                   arguments[0],
                                                   arguments[1],
                                                   output_func=print,
                                                   download_func=download_func,
                                                   load_func=load_func))
                else:
                    print(self.commands[command](self))
            else:
                print("UNKNOWN COMMAND")
