# !/usr/bin/env python3
import os
import sys
import threading
from math import sqrt

from PyQt5 import QtWidgets, QtCore
from PyQt5.QtWidgets import QFileDialog, QPushButton, QLineEdit, \
    QGridLayout, QLabel, QVBoxLayout, QDialogButtonBox

from errors import PermanentError
from ftp import FTP

EXIT = False


class LoginWindow(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.login = QLineEdit("anonymous")
        self.password = QLineEdit("password")
        self.password.setEchoMode(QLineEdit.Password)
        self._buttons = QDialogButtonBox(
            QDialogButtonBox.Cancel | QDialogButtonBox.Ok
        )

        layout2 = QGridLayout()
        layout2.setSpacing(5)
        layout2.addWidget(QLabel("Login: "), 0, 0)
        layout2.addWidget(self.login, 0, 1)
        layout2.addWidget(QLabel("Password: "), 1, 0)
        layout2.addWidget(self.password, 1, 1)

        layout = QVBoxLayout()
        layout.setSpacing(5)
        layout.addLayout(layout2)
        layout.addWidget(self._buttons)

        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)

        self.setLayout(layout)


class ConnectionWindow(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.ip = QLineEdit("212.193.68.227")
        # self.ip = QLineEdit("localhost")
        self.port = QLineEdit("21")
        self._buttons = QDialogButtonBox(
            QDialogButtonBox.Cancel | QDialogButtonBox.Ok
        )

        layout2 = QGridLayout()
        layout2.setSpacing(5)
        layout2.addWidget(QLabel("Server IP: "), 0, 0)
        layout2.addWidget(self.ip, 0, 1)
        layout2.addWidget(QLabel("Port: "), 1, 0)
        layout2.addWidget(self.port, 1, 1)

        layout = QVBoxLayout()
        layout.setSpacing(5)
        layout.addLayout(layout2)
        layout.addWidget(self._buttons)

        self._buttons.accepted.connect(self.accept)
        self._buttons.rejected.connect(self.reject)

        self.setLayout(layout)


class DownloadThread(QtCore.QObject):
    sig_done = QtCore.pyqtSignal(str, bool)
    sig_step = QtCore.pyqtSignal(int)

    def __init__(self, ftp, server_path, local_path, download_from):
        super().__init__()
        self._ftp = ftp
        self._server_path = server_path
        self._local_path = local_path
        self._download_from = download_from

    def work(self):
        if self._download_from:
            self._ftp.retr(server_path=self._server_path,
                           local_path=self._local_path,
                           download_func=self.download_from_server)
        else:
            try:
                self._ftp.add_file(local_path=self._local_path,
                                   server_path=None,
                                   load_func=self.download_to_server)
            except PermanentError as err:
                self.sig_done.emit(err.args[0], False)

    def download_from_server(self, size, new_path, ftp):
        downloaded = 0
        with open(new_path, 'wb') as file:
            for part in ftp.get_binary_data():
                if EXIT:
                    exit()
                downloaded += len(part)
                self.sig_step.emit(100 * downloaded / int(size))
                file.write(part)
        self.sig_done.emit(
            "Download of " +
            self._server_path +
            " is complete",
            True)

    def download_to_server(self, size, filename, ftp):
        downloaded = 0
        with open(filename, 'rb') as file:
            for part in file:
                if EXIT:
                    exit()
                downloaded += len(part)
                self.sig_step.emit(100 * downloaded / int(size))
                ftp.data_socket.sendall(part)
        self.sig_done.emit("Download of " + self._local_path + " is complete",
                           True)


class NewFolderWindow(QtWidgets.QDialog):
    def __init__(self, ftp, parent=None):
        super().__init__(parent)

        self.ftp = ftp

        buttons = QDialogButtonBox(
            QDialogButtonBox.Cancel | QDialogButtonBox.Ok
        )

        self.new_folder = QLineEdit("foldername")

        layout2 = QGridLayout()
        layout2.setSpacing(5)
        layout2.addWidget(QLabel("Folder name: "), 0, 0)
        layout2.addWidget(self.new_folder, 0, 1)

        layout = QVBoxLayout()
        layout.setSpacing(5)
        layout.addLayout(layout2)
        layout.addWidget(buttons)

        buttons.accepted.connect(self.make_new_directory)
        buttons.rejected.connect(self.close)

        self.setLayout(layout)

    def make_new_directory(self):
        try:
            self.ftp.make_directory(self.new_folder.text())
            self.parent().print_list()
            self.close()
        except PermanentError as err:
            show_message(err.args[0],
                         "Error")


class DetailedInfoWindow(QtWidgets.QDialog):
    def __init__(self, ftp, filename, is_file, parent=None):
        super().__init__(parent)
        self.ftp = ftp
        self.old_filename = filename

        self.new_filename = QLineEdit(filename)

        layout2 = self.init_file_info() if is_file else self.init_folder_info()

        layout = QtWidgets.QVBoxLayout()
        layout.setSpacing(5)
        layout.addLayout(layout2)

        for button in [make_button("Rename", self.rename),
                       make_button("Delete",
                                   lambda x=self.ftp.delete_file if is_file
                                   else self.ftp.delete_directory:
                                   self.delete(x),
                                   ),
                       make_button("Cancel", self.close)]:
            layout.addWidget(button)
        self.setLayout(layout)

    def init_file_info(self):
        layout = QGridLayout()
        layout.setSpacing(5)
        layout.addWidget(QLabel("Last modified: "), 0, 0)
        layout.addWidget(QLabel(self.extract_date(self.ftp.mdtm(
            self.old_filename))), 0, 1)
        layout.addWidget(QLabel("Size: "), 1, 0)
        size = self.ftp.size(self.old_filename).strip('\n')
        layout.addWidget(QLabel(size + ' bytes'), 1, 1)
        layout.addWidget(QLabel("Rename to: "), 2, 0)
        layout.addWidget(self.new_filename, 2, 1)

        return layout

    def init_folder_info(self):
        layout = QGridLayout()
        layout.setSpacing(5)

        layout.addWidget(QLabel("Rename to: "), 0, 0)
        layout.addWidget(self.new_filename, 0, 1)

        return layout

    @staticmethod
    def extract_date(answer):
        date = answer.split(' ')[1]
        year = date[:4]
        month = date[4:6]
        day = date[6:8]
        hour = date[8:10]
        minute = date[10:12]
        second = date[12:14]
        return '.'.join([day, month, year]) \
               + ' ' + \
               ':'.join([hour, minute, second])

    def rename(self):
        try:
            self.ftp.rename_from(self.old_filename)
            self.ftp.rename_to(self.new_filename.text())
            self.parent().print_list()
            self.close()
        except PermanentError as err:
            show_message(err.args[0],
                         "Error")

    def delete(self, delete_func):
        try:
            delete_func(self.old_filename)
            self.parent().print_list()
            self.close()
        except PermanentError as err:
            show_message(err.args[0],
                         "Error")


class FTPWindow(QtWidgets.QMainWindow):
    thread = None

    def __init__(self, parent=None):
        super().__init__(parent)

        _layout = QGridLayout()
        _layout.setSpacing(5)
        _window = QtWidgets.QWidget()
        _window.setLayout(_layout)

        self.setCentralWidget(_window)

        self.resize(400, 300)
        self.setWindowTitle("FTP client")

        self.connection_dialog = ConnectionWindow(parent=self)
        self.connection_dialog.setModal(True)
        self.connection_dialog.accepted.connect(self._connect)
        self.connection_dialog.rejected.connect(self.close)

        self.login_dialog = LoginWindow(parent=self)
        self.login_dialog.setModal(True)
        self.login_dialog.accepted.connect(self._login)
        self.login_dialog.rejected.connect(self.close)

        self.progressBar = QtWidgets.QProgressBar()
        self.statusBar().addPermanentWidget(self.progressBar)
        self.statusBar().showMessage("Waiting for params...")

        self._ftp = FTP()

        self._buttons = []

    def closeEvent(self, event):
        if self.thread and self.thread.is_alive():
            text = "File is being downloaded.\nAre you sure you want to exit?"
            result = QtWidgets.QMessageBox.question(
                self, "Confirm Exit...", text,
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            event.ignore()
        else:
            result = QtWidgets.QMessageBox.question(
                self, "Confirm Exit...", "Are you sure you want to exit ?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            event.ignore()

        if result == QtWidgets.QMessageBox.Yes:
            global EXIT
            EXIT = True
            event.accept()

    def print_list(self):
        if self.thread and self.thread.is_alive():
            return

        files = self._ftp.nlst().split('\r\n')

        for item in ["", ".", ".."]:
            if item in files:
                files.remove(item)

        layout = QGridLayout()
        layout.setSpacing(5)

        self._buttons = []

        self.add_service_button(layout, "BACK",
                                lambda x="..": self._move(x), 0)
        self.add_service_button(layout, "Add Directory",
                                self.make_new_dir, 1)
        self.add_service_button(layout, "Add File",
                                self.add_file, 2)
        self.add_service_button(layout, "Download CWD",
                                self.download_folder, 3)

        self.place_file_buttons(files, layout)

        _window = QtWidgets.QWidget()
        _window.setLayout(layout)

        self.setCentralWidget(_window)

    def add_service_button(self, layout, text, func, column):
        button = make_button(text, func)
        button.setStyleSheet('background-color: white')
        layout.addWidget(button, 0, column, 1, 1)
        self._buttons.append(button)

    def place_file_buttons(self, files, layout):
        i = 0
        upper_bound = int(sqrt(len(files)))
        for column in range(0, upper_bound + 1):
            for row in range(1, upper_bound + 2):
                try:
                    item = files[i]
                except IndexError:
                    break

                button = make_button(item, lambda x=item: self._move(x))

                is_file = self.check_if_file(item)

                button.setStyleSheet('background-color: orange' if is_file
                                     else 'background-color: yellow')

                button.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
                button.customContextMenuRequested.connect(
                    lambda x=None, y=item, z=is_file:
                    self.handle_right_click(x, y, z))

                layout.addWidget(button, row, column)
                self._buttons.append(button)
                i += 1

    def handle_right_click(self, MouseEvent, filename, is_file):
        info = DetailedInfoWindow(self._ftp, filename, is_file, parent=self)
        info.setModal(True)
        info.show()

    def make_new_dir(self):
        info = NewFolderWindow(self._ftp, parent=self)
        info.setModal(True)
        info.show()

    def add_file(self):
        filename = QFileDialog.getOpenFileName()[0]
        if filename:
            self.thread = threading.Thread(target=self._download,
                                           args=(None, filename, False))
            self.thread.start()

    def check_if_file(self, path):
        try:
            self._ftp.cwd(path)
            self._ftp.cwd("..")
            return False
        except PermanentError:
            return True

    def _move(self, path):
        if self.thread and self.thread.is_alive():
            return
        try:
            self._ftp.cwd(path)
        except PermanentError as err:
            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog
            filename, _ = QFileDialog.getSaveFileName(
                self, "Save file as", path,
                "All Files (*);;Text Files (*.txt)", options=options)
            if filename:
                self.thread = threading.Thread(target=self._download,
                                               args=(path, filename, True))
                self.thread.start()

        self.print_list()

    def download_folder(self):
        new_folder = QFileDialog.getExistingDirectory(self, "Select Directory")

        if not new_folder:
            return

        if not os.path.exists(new_folder):
            os.makedirs(new_folder)

        thread = threading.Thread(
            target=self.retrieve_files, args=(
                new_folder,))
        thread.start()

    def retrieve_files(self, new_folder):
        all_items = self._ftp.nlst().split('\r\n')

        for item in ["", ".", ".."]:
            if item in all_items:
                all_items.remove(item)

        for item in all_items:
            while self.thread and self.thread.is_alive():
                if EXIT:
                    exit()
                continue
            if self.check_if_file(item):
                self.thread = threading.Thread(target=self._download,
                                               args=(item, new_folder, True))
                self.thread.start()

    def _download(self, server_path, local_path, download_from):
        enable_disable_button(self._buttons, True)
        worker = DownloadThread(self._ftp, server_path,
                                local_path, download_from)
        worker.sig_step.connect(self._on_part_downloaded)
        worker.sig_done.connect(self._file_downloaded)
        worker.work()

    @QtCore.pyqtSlot(int)
    def _on_part_downloaded(self, value):
        self.progressBar.setValue(value)

    @QtCore.pyqtSlot(str, bool)
    def _file_downloaded(self, value, success):
        enable_disable_button(self._buttons, False)
        show_message(value, "Success" if success else "Error")
        self.print_list()

    def get_params(self):
        self.connection_dialog.show()

    def login(self):
        self.login_dialog.show()

    def _login(self):
        try:
            self._username = self.login_dialog.login.text()
            self._password = self.login_dialog.password.text()
            self._ftp.login(self._username, self._password)
            self.print_list()
        except PermanentError as err:
            show_message(err.args[0], "Error")
            self.login()

    def _connect(self):
        try:
            self._ip = self.connection_dialog.ip.text()
            self._port = int(self.connection_dialog.port.text())
            self.statusBar().showMessage(
                self._ftp.connect(self._ip, self._port))
            self.login()
        except Exception as e:
            show_message(str(e), "Error")
            self.close()


def enable_disable_button(buttons, disable):
    for btn in buttons:
        btn.setDisabled(disable)


def show_message(text, title):
    msg = QtWidgets.QMessageBox()
    msg.setInformativeText(text)
    msg.setWindowTitle(title)
    msg.exec_()


def make_button(text, func):
    button = QPushButton()
    button.setText(text)
    button.released.connect(func)
    return button


def main():
    app = QtWidgets.QApplication(sys.argv)

    window = FTPWindow()
    window.get_params()
    window.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
