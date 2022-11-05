#!/bin/python3
from io import BufferedRWPair
from socket import socket, AF_INET, SOCK_STREAM
import threading
import queue
import time
import argparse
import re


class User:
    name: str
    msg_queue: queue.Queue

    def __init__(self, username: str):
        self.name      = username
        self.msg_queue = queue.Queue()


class Userlist:
    users: list

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

    def get(self, username: str) -> User:
        for user in self.users:
            if user.name == username:
                return user
        raise ValueError("User does not exist.")

    def sendall(self, msg: str) -> None:
        for user in self.users:
            user.msg_queue.put(msg)


class options:
    port : int
    debug : bool
    welcome_msg : str
    max_users : int
    max_username_len : int
    max_msg_len : int


userlist = Userlist()


ALLOWED_USERNAME_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
ALLOWED_MSG_CHARS      = r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ ".encode("utf-8")

C_SAVE      = "\x1b[s"
C_RESTORE   = "\x1b[u"
C_GOTO_C0   = "\x1b[0G"
C_GOTO_C0L0 = "\x1b[H"
CLEAR_SCR   = "\x1b[2J"
CLEAR_LINE  = "\x1b[2K"

CLAIMED_USERNAMES = ["[SERVER]"]


def safe_flush(cf: BufferedRWPair) -> int:
    try:
        cf.flush()
    except BrokenPipeError:
        return -1
    return 0


def readuntil(cf: BufferedRWPair, end: bytes) -> bytes:
    buf = b""
    while True:
        b = cf.read(1)

        if b == b"":
            return b"EOF"
        
        buf += b
        if end in buf:
            return buf


def validate_username(username: bytes) -> tuple[bool, str]:
    for byte in username:
        if byte not in ALLOWED_USERNAME_CHARS:
            return (False, f"Username contains illegal byte '{hex(byte)}'.\n Allowed characters are: [A-z0-9-_.]\n")

    uusername = username.decode("utf-8")

    for val in CLAIMED_USERNAMES:
        if val == uusername:
            return (False, "Username is claimed by the server\n")

    if userlist.check_exists(uusername):
        return (False, "Username is already in use\n")

    if not uusername:
        return (False, "Username must not be empty\n")

    if len(uusername) > options.max_username_len:
        return (False, "Username is too long\n")

    return (True, "")


def gen_ui(msglist: list[str], scr_height: int, scr_width: int) -> str:
    buf = ""

    # clear
    buf += C_SAVE
    buf += f"\x1b[{scr_height}A"
    for i in range(scr_height-1):
        buf += f"\x1b[{i};0H{CLEAR_LINE}"
    buf += C_RESTORE

    # messages 
    buf += C_SAVE
    buf += f"\x1b[{scr_height}A"
    for msg in msglist:
        buf += f"{C_GOTO_C0}{msg}\x1b[1B"
    buf += C_RESTORE

    # messages-input border
    buf += C_SAVE
    buf += "\x1b[1A"
    buf += f"{CLEAR_LINE}{C_GOTO_C0}"
    buf += "#" * scr_width
    buf += C_RESTORE
    
    return buf


def get_scr_size(cf: BufferedRWPair) -> tuple[int, int]:
    cf.write((
        f"{CLEAR_SCR}{C_GOTO_C0L0}\n\n" 
    +    "Press enter to continue. [DO NOT INSERT OR REMOVE TEXT]"
    +    "\x1b[9999;9999H[\x1b[6n"
    ).encode("utf-8"))
    if safe_flush(cf) != 0:
        return (-1, -1) # error, flush
    
    buf = readuntil(cf, b"\n")
    if buf == b"EOF":
        return (-1, -2) # error, eof

    out = re.findall(b"\x1b\\[(\\d+);(\\d+)R", buf)
    if len(out) != 1:
        return (-1, -3) # error, invalid input

    cf.write((
        f"{CLEAR_SCR}{C_GOTO_C0L0}"
    ).encode("utf-8"))
    if safe_flush(cf) != 0:
        return (-1, -1) # error, flush

    scr_height, scr_width = out[0]
    scr_height, scr_width = int(scr_height), int(scr_width)

    return (scr_height, scr_width)
    

def conn_handler(conn: socket, cf: BufferedRWPair) -> None:
    cf.write(f"{CLEAR_SCR}{C_GOTO_C0L0}".encode("utf-8"))
    if safe_flush(cf) != 0:
        return

    if options.welcome_msg:
        cf.write(options.welcome_msg.encode("utf-8") + b"\n")
        if safe_flush(cf) != 0:
            return

    while True:
        cf.write(b"Session username: ")
        if safe_flush(cf) != 0:
            return

        buf = readuntil(cf, b"\n")
        if buf == b"EOF":
            return

        buf = buf[:-1] # remove trailing newline
        success, err = validate_username(buf)
        if not success:
            cf.write(err.encode("utf-8"))
            if safe_flush(cf) != 0:
                return
            continue
        break
    username = buf.decode("utf-8")

    out = get_scr_size(cf)
    if out[0] == -1:
        return
    scr_height, scr_width = out

    userlist.add(username)
    user = userlist.get(username)

    if options.debug:
        print(f"added user {user.name} to userlist")
    userlist.sendall(
        f"[SERVER]: {user.name} joined! Welcome! :D"
    )

    cf.write((
        f"{CLEAR_SCR}\x1b[{scr_height}B"
    +   f"Input: "
    ).encode("utf-8"))
    if safe_flush(cf) != 0:
        return

    conn.setblocking(False)
    buf = b""
    msglist = []
    while True:
        if not user.msg_queue.empty():
            msg = user.msg_queue.get()
            msglist.append(msg)
            msglist = msglist[::-1][:scr_height-2][::-1]

            ui = gen_ui(msglist, scr_height, scr_width)

            cf.write(ui.encode("utf-8"))
            if safe_flush(cf) != 0:
                break

        b = cf.read(1)
        if b == b"": # EOF
            break
        if b is None:
            # Gives time for the CPU to execute other code
            # resulting in a lot lower total CPU usage
            time.sleep(0.1)
            continue

        buf += b
        if b"\n" in buf:
            # this fucks shit up but it 
            # gets fixed on next sent message
            cf.write((f"{CLEAR_LINE}{C_GOTO_C0}Input: ").encode("utf-8"))
            if safe_flush(cf) != 0:
                break

            success = True
            buf = buf[:-1] # remove trailing newline
            for byte in buf:
                if byte not in ALLOWED_MSG_CHARS:
                    userlist.sendall(
                        f"[SERVER]: {user.name} tried to send "
                    +   f"disallowed byte '{hex(byte)}' but "
                    +    "i blocked it! >:D"
                    )
                    buf = b""
                    success = False
            
            if not success:
                continue

            msg = buf.decode("utf-8")
            msg = msg[:options.max_msg_len]
            userlist.sendall(
                f"{user.name}: {msg}"
            )
            buf = b""

    userlist.sendall(
        f"[SERVER]: {user.name} left. bye. :c"
    )
    if options.debug:
        print(f"removed user {user.name} from userlist")

    userlist.remove(user.name)


def conn_handler_wrapper(conn: socket) -> None:
    cf = conn.makefile("rwb")

    if options.debug:
        print(f"Started connection; {conn}")

    conn_handler(conn, cf)

    if options.debug:
        print(f"Closing connection; {conn}")

    cf.close()
    conn.close()


def parse_args():
    parser = argparse.ArgumentParser("nchat")
    parser.add_argument(
        "port", 
        help="The port that the server listens on",
        type=int, 
    )
    parser.add_argument(
        "-d", "--debug",
        help="Show debug output while running the server",
        action="store_true",
    )
    parser.add_argument(
        "-w", "--welcome-message",
        help="The message users get sent on connection",
        type=str,
        default="",
    )
    parser.add_argument(
        "--max-users",
        help="Set the maximum number of concurrent users",
        type=int,
        default=16,
    )
    parser.add_argument(
        "--max-username-length",
        help="Set the maximum length of usernames",
        type=int,
        default=20,
    )
    parser.add_argument(
        "--max-message-length",
        help="Set the maximum length of messages",
        type=int,
        default=256,
    )
    args = parser.parse_args()

    options.port             = args.port
    options.debug            = args.debug
    options.welcome_msg      = args.welcome_message
    options.max_users        = args.max_users
    options.max_username_len = args.max_username_length
    options.max_msg_len      = args.max_message_length
    

def main():
    parse_args()
    
    with socket(AF_INET, SOCK_STREAM) as s:
        s.bind(("", options.port))
        s.listen(options.max_users)

        print("Server is listening...")
        
        while True:
            conn, _ = s.accept()
            threading.Thread(target=conn_handler_wrapper, args=(conn,)).start()


if __name__ == "__main__":
    main()

