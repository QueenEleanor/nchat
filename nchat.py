#!/bin/python3
import socket
import threading
import argparse


class options:
    port      = None
    debug     = None
    max_users = None


def conn_handler(conn):
    pass


def parse_args():
    parser = argparse.ArgumentParser("nchat")
    parser.add_argument(
        "port", 
        help="The port which the server listens on",
        type=int, 
    )
    parser.add_argument(
        "-d", "--debug",
        help="Show debug output while running the server",
        action="store_true",
    )
    parser.add_argument(
        "-u", "--max-users",
        help="Maximum number of connected clients at the same time",
        type=int, 
        default=16,
    )
    args = parser.parse_args()

    options.port  = args.port
    options.debug = args.debug
    options.max_users = args.max_users
    

def main():
    parse_args()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", options.port))
        s.listen(options.max_users)

        print("Server is listening...")

        conn, _ = s.accept()
        with conn:
            if options.debug:
                print(f"Started connection; {conn}")
            threading.Thread(target=conn_handler, args=(conn,)).start()
            if options.debug:
                print(f"Closed connection; {conn}")


if __name__ == "__main__":
    main()

