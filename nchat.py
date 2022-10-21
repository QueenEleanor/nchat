#!/bin/python3
import socket
import threading
import queue
import argparse
import re


class User:
    def __init__(self, username: str):
        self.name      = username
        self.msg_queue = queue.Queue()


class Userlist:
    def __init__(self):
        self.users = []

    def check_exists(self, username: str) -> bool:
        for user in self.users:
            if user.name == username:
                return True
        return False

    def add(self, username: str) -> None:
        if self.check_exists(username):
            raise ValueError("Username already in use.")
        self.users.append(User(username))

    def remove(self, username: str) -> None:
        for i, user in enumerate(self.users):
            if user.name == username:
                self.users.pop(i)
                return

    def sendall(self, msg: str) -> None:
        for user in self.users:
            user.msg_queue.put(msg)


class options:
    port      : int
    debug     : bool

userlist = Userlist()


ALLOWED_USERNAME_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."

MAX_USERS        = 16
MAX_USERNAME_LEN = 20

CLAIMED_USERNAMES = ["[SERVER]"]


def validate_username(username: bytes) -> tuple[bool, str]:
    for byte in username:
        if byte not in ALLOWED_USERNAME_CHARS:
            return (False, f"Username contains illegal byte '{hex(byte)}'. Allowed characters are: [A-z0-9-_.]\n")

    for val in CLAIMED_USERNAMES:
        if val == username:
            return (False, "Username is claimed by the server\n")

    if userlist.check_exists(username):
        return (False, "Username is already in use\n")

    if not username:
        return (False, "Username must not be empty\n")

    if len(username) > MAX_USERNAME_LEN:
        return (False, "Username is too long\n")

    return (True, "")


def conn_handler(conn: socket.socket) -> None:
    conn.send(
        b"Press enter to continue. [DO NOT INSERT OR REMOVE TEXT]"
    +   b"\x1b[9999;9999H[\x1b[6n"
    )
    
    buf = conn.recv(128)     

    out = re.findall(b"\x1b\[(\d+);(\d+)R", buf)
    if len(out) != 1:
        return
    scr_height, scr_width = out[0]
    scr_height, scr_width = int(scr_height), int(scr_width)

    conn.send(b"\x1b[2J\x1b[H")

    while True:
        conn.send(b"Session username: ")
        username = conn.recv(256)[:-1]

        print(username)
        success, err = validate_username(username)
        if not success:
            conn.send(err.encode("utf-8"))
            continue
        break
    username = username.decode("utf-8")
    userlist.add(username)

    if options.debug:
        print(f"added user {username} to userlist")
    else:
        print(f"{username} joined")

    #

    userlist.remove(username)
    if options.debug:
        print(f"removed user {username} from userlist")
    else:
        print(f"{username} left")



def conn_hander_wrapper(conn: socket.socket) -> None:
    if options.debug:
        print(f"Started connection; {conn}")

    try: 
        conn_handler(conn)
    except BrokenPipeError:
        pass # connection closed

    if options.debug:
        print(f"Closing connection; {conn}")
    conn.close()


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
    args = parser.parse_args()

    options.port  = args.port
    options.debug = args.debug
    

def main():
    parse_args()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", options.port))
        s.listen(MAX_USERS)

        print("Server is listening...")
        
        while True:
            conn, _ = s.accept()
            threading.Thread(target=conn_hander_wrapper, args=(conn,)).start()


if __name__ == "__main__":
    main()

