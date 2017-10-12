# !/usr/bin/env python3
import threading

from ftp import FTP, FTP_PORT
import sys
from PyQt5 import QtWidgets, QtNetwork, QtCore, QtGui
from errors import PermanentError

class LoginWindow(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._login = QtWidgets.QLineEdit("anonymous")
        self._password = QtWidgets.QLineEdit("password")
        self._password.setEchoMode(QtWidgets.QLineEdit.Password)
        self._buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Cancel | QtWidgets.QDialogButtonBox.Ok
        )

        layout2 = QtWidgets.QGridLayout()
        layout2.setSpacing(5)
        layout2.addWidget(QtWidgets.QLabel("Login: "), 0, 0)
        layout2.addWidget(self._login, 0, 1)
        layout2.addWidget(QtWidgets.QLabel("Password: "), 1, 0)
        layout2.addWidget(self._password, 1, 1)

        layout = QtWidgets.QVBoxLayout()
        layout.setSpacing(5)
        layout.addLayout(layout2)
        layout.addWidget(self._buttons)

        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)

        self.setLayout(layout)


class ConnectionWindow(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._ip = QtWidgets.QLineEdit("212.193.68.227")
        self._port = QtWidgets.QLineEdit("21")
        self._buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Cancel | QtWidgets.QDialogButtonBox.Ok
        )

        layout2 = QtWidgets.QGridLayout()
        layout2.setSpacing(5)
        layout2.addWidget(QtWidgets.QLabel("Server IP: "), 0, 0)
        layout2.addWidget(self._ip, 0, 1)
        layout2.addWidget(QtWidgets.QLabel("Port: "), 1, 0)
        layout2.addWidget(self._port, 1, 1)

        layout = QtWidgets.QVBoxLayout()
        layout.setSpacing(5)
        layout.addLayout(layout2)
        layout.addWidget(self._buttons)

        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)

        self.setLayout(layout)


class FTPWindow(QtWidgets.QMainWindow):
    thread = None

    def __init__(self, parent=None):
        super().__init__(parent)

        """
             0  1
            +----+
          0 |  : |
            +--|-+
          1 |  | |
            +--|-+
        """
        _layout = QtWidgets.QGridLayout()
        _layout.setSpacing(5)
        # _layout.addWidget(self._messages, 0, 0, 1, 2)
        # _layout.addWidget(self._input, 1, 0)
        # _layout.addWidget(self._send_button, 1, 1)
        _window = QtWidgets.QWidget()
        _window.setLayout(_layout)

        self.setCentralWidget(_window)

        self.resize(400, 300)
        self.setWindowTitle("FTP client")

        self._con_dialog = ConnectionWindow(parent=self)
        self._con_dialog.setModal(True)
        self._con_dialog.accepted.connect(self._connect)
        self._con_dialog.rejected.connect(self.close)

        self._login_dialog = LoginWindow(parent=self)
        self._login_dialog.setModal(True)
        self._login_dialog.accepted.connect(self._login)
        self._login_dialog.rejected.connect(self.close)

        self.statusBar().showMessage("Waiting for params...")

        self._ftp = FTP()

    def closeEvent(self, event):
        if self.thread and self.thread.is_alive():
            text = "File is being downloaded. Please, wait for it to complete"
            msg = QtWidgets.QMessageBox()
            msg.setInformativeText(text)
            msg.setWindowTitle("Please, wait")
            msg.exec_()
            event.ignore()
            return

        result = QtWidgets.QMessageBox.question(
            self, "Confirm Exit...", "Are you sure you want to exit ?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        event.ignore()

        if result == QtWidgets.QMessageBox.Yes:
            event.accept()

    def _print_list(self):
        if self.thread and self.thread.is_alive():
            return
        directory = self._ftp.list().split('\n')
        _layout = QtWidgets.QGridLayout()
        _layout.setSpacing(5)
        i = 0
        for item in directory:
            button = QtWidgets.QPushButton()
            button.setText(item)
            button.released.connect(lambda x=item: self._move(
                x.split(' ')[-1].strip('\r')))
            _layout.addWidget(button, i, 0)
            i += 1

        _window = QtWidgets.QWidget()
        _window.setLayout(_layout)

        self.setCentralWidget(_window)

    def _move(self, path):
        if self.thread and self.thread.is_alive():
            return
        try:
            self._ftp.cwd(path if len(path) > 1 else '..')
        except PermanentError as err:
            options = QtWidgets.QFileDialog.Options()
            options |= QtWidgets.QFileDialog.DontUseNativeDialog
            filename, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Save file as", path,
                "All Files (*);;Text Files (*.txt)",
                options=options)
            if filename:
                self.thread = threading.Thread(target=self._ftp.retr,
                                               args=(path, filename))

                self.thread.start()
        self._print_list()

    def get_params(self):
        self._con_dialog.show()

    def login(self):
        self._login_dialog.show()

    def _login(self):
        try:
            self._username = self._login_dialog._login.text()
            self._password = self._login_dialog._password.text()
        except Exception as e:
            self.statusBar().showMessage("Connection error: {}".format(e))

        self.statusBar().showMessage(self._ftp.login(
            self._username, self._password))
        self._print_list()

    def _connect(self):
        try:
            self._ip = self._con_dialog._ip.text()
            self._port = int(self._con_dialog._port.text())
        except Exception as e:
            self.statusBar().showMessage("Connection error: {}".format(e))

        self.statusBar().showMessage(
            "Connected to: {}, {}".format(self._ip, self._port))
        self.statusBar().showMessage(self._ftp.connect(self._ip, self._port))
        self.login()


def main():
    app = QtWidgets.QApplication(sys.argv)

    window = FTPWindow()
    window.get_params()
    window.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
