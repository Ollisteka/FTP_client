# !/usr/bin/env python3

import argparse
import os
import sys
from sys import platform

from ftp import FTP, FTP_PORT

if platform.startswith("linux"):
    import click_package as click
elif platform == "win32":
    import click



def main():
    parser = argparse.ArgumentParser(
        usage='{} [OPTIONS]'.format(
            os.path.basename(
                sys.argv[0])),
        description='FTP client. Using passive ASCII mode and 21 port by '
                    'default')
    parser.add_argument('address', help='address to connect')
    parser.add_argument('port', help='port', nargs='?',
                        type=int, default=FTP_PORT)
    parser.add_argument('--active', dest='active',
                        action='store_true', help='use active mode')

    args = parser.parse_args()

    con = FTP(args.address, args.port, args.active)
    print(con.connect())
    con.run_batch(download_func=download_batch)


def download_batch(size, new_path, ftp):
    """
    Download with console progress bar
    :return:
    """
    with click.progressbar(length=int(size),
                           label="Downloading file ") as bar:
        with open(new_path, 'wb') as file:
            for part in ftp.get_binary_data():
                file.write(part)
                bar.update(len(part))


if __name__ == '__main__':
    sys.exit(main())
