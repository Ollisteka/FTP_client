# !/usr/bin/env python3
import os
import tempfile
import unittest
import unittest.mock as mock

from stubserver import FTPStubServer

from client import download_batch
from ftp import FTP


class TestWithStubServer(unittest.TestCase):
    def setUp(self):
        self.server = FTPStubServer(0)
        self.server.run()
        self.port = self.server.server.server_address[1]
        self.ftp = FTP()
        self.ftp.connect('localhost', self.port)

    def tearDown(self):
        self.ftp.ftp_quit()
        self.server.stop()

    def test_list(self):
        fileA = "A.png"
        fileB = "B.png"
        self.server.add_file(fileA, "")
        self.server.add_file(fileB, "asd")
        listing = self.ftp.ftp_list()
        self.assertEqual(listing, fileA + '\n' + fileB)

    # Sockets unclosed
    def test_retr(self):
        fileB = "B.png"
        self.server.add_file(fileB, "asd")
        temp = tempfile.NamedTemporaryFile(delete=False)
        with mock.patch.object(self.ftp, 'ftp_size', return_value=12345):
            self.ftp.ftp_retr(fileB, temp.name, download_func=download_batch)
        with open(temp.name, 'r') as file:
            data = file.read()
        self.assertEqual(data, "asd")
        temp.close()

    def test_pasv(self):
        reply = self.ftp.ftp_pasv()
        self.assertEqual(reply.startswith('227 Entering Passive Mode'), True)

    def test_cwd_pwd(self):

        dir_name = "new_dir"
        expected = '257 "' + dir_name + '" is your current location' + '\r\n'
        self.ftp.ftp_cwd(dir_name)
        self.assertEqual(self.ftp.ftp_pwd(), expected)

    def test_welcome(self):
        value = '220 (FtpStubServer 0.1a)\r\n'
        self.assertEqual(self.ftp.welcome, value)

    # def test_error(self):
    #     text = '530 Please login with USER and PASS'
    #     with mock.patch.object(self.ftp, '_FTP__get_full_reply',
    #                            return_value=text):
    #         with self.assertRaises(PermanentError):
    #             self.ftp.ftp_list()

    def test_extract_file_name(self):
        fn = self.ftp._FTP__get_filename(os.path.join("C", "test.txt"))
        self.assertEqual("test.txt", fn)
        with self.assertRaises(Exception):
            path = self.ftp._FTP__get_filename(os.getcwd())

    def test_size(self):
        size = "123"
        response = "213 " + size
        with mock.patch.object(self.ftp, 'send', return_value=response):
            self.assertEqual(size, self.ftp.ftp_size("asd"))

    def test_type(self):
        self.ftp.ftp_type("A")
        self.assertFalse(self.ftp.binary)
        self.ftp.ftp_type("I")
        self.assertTrue(self.ftp.binary)
        with self.assertRaises(Exception):
            self.ftp.ftp_type("E")


if __name__ == '__main__':
    unittest.main()
