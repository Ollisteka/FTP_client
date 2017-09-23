from ftp import FTP, FTP_PORT
import sys
import os
import argparse


def main():
    parser = argparse.ArgumentParser(
        usage='{} [OPTIONS]'.format(
            os.path.basename(
                sys.argv[0])),
        description='FTP server. Using passive ASCII mode and 21 port by default')
    parser.add_argument('address', help='address to connect')
    parser.add_argument('port', help='port', nargs='?', type=int, default=FTP_PORT)
    parser.add_argument('--active', dest='active', action='store_true', help='use active mode')

    args = parser.parse_args()

    con = FTP(args.address, args.port, args.active)
    con.connect()
    con.run()

if __name__ == '__main__':
    sys.exit(main())
