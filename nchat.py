#!/bin/python3
from io import BufferedRWPair
from socket import socket, AF_INET, SOCK_STREAM
from queue import Queue
import threading
import time
import argparse
import re


ALLOWED_USERNAME_CHARS = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
ALLOWED_MSG_CHARS      = r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ ".encode("utf-8")

C_SAVE      = "\x1b[s"
C_RESTORE   = "\x1b[u"
C_GOTO_C0   = "\x1b[0G"
C_GOTO_C0L0 = "\x1b[H"
CLEAR_SCR   = "\x1b[2J"
CLEAR_LINE  = "\x1b[2K"

CLAIMED_USERNAMES = ["[SERVER]"]


class Screen:
    height: int
    width: int
    msglist: list[str]

    def __init__(self):
        self.msglist = []

    def set_size(self, cf: BufferedRWPair) -> int:
        cf.write((
           f"{CLEAR_SCR}{C_GOTO_C0L0}\n\n" 
        +   "Press enter to continue. [DO NOT INSERT OR REMOVE TEXT]"
        +   "\x1b[9999;9999H[\x1b[6n"
            ).encode("utf-8")
        )
        if safe_flush(cf) != 0:
            return -1
    
        buf = readline(cf)
        if buf == b"EOF":
            return -2

        out = re.findall(b"\x1b\\[(\\d+);(\\d+)R", buf)
        if len(out) != 1:
            return -3

        cf.write((
           f"{CLEAR_SCR}{C_GOTO_C0L0}"
            ).encode("utf-8")
        )
        if safe_flush(cf) != 0:
            return -1

        height, width = out[0]
        height, width = int(height), int(width)
        self.height, self.width = height, width

        return 0

    def generate(self) -> str:
        buf = ""

        # init
        buf += C_SAVE

        # clear
        buf += f"\x1b[0;0H"
        for i in range(self.height - 1):
            buf += f"\x1b[{i};0H{CLEAR_LINE}"

        # messages 
        buf += f"\x1b[0;0H"
        for msg in self.msglist:
            buf += f"{C_GOTO_C0}{msg}\x1b[1B"

        # messages-input border
        buf += f"\x1b[{self.height - 1};0H"
        buf += f"{CLEAR_LINE}{C_GOTO_C0}"
        buf += "#" * self.width

        # deinit
        buf += C_RESTORE
    
        return buf


class User:
    name: str
    msg_queue: Queue
    screen: Screen

    def __init__(self, username: str):
        self.name      = username
        self.msg_queue = Queue()
        self.screen    = Screen()


class Userlist:
    users: list[User]

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


def safe_flush(cf: BufferedRWPair) -> int:
    try:
        cf.flush()
    except BrokenPipeError:
        return -1
    return 0


def readline(cf: BufferedRWPair) -> bytes:
    buf = b""
    while True:
        b = cf.read(1)

        if b == b"":
            return b"EOF"
        
        buf += b
        if b == b"\n":
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


def conn_handler(conn: socket, cf: BufferedRWPair) -> None:
    cf.write((
       f"{CLEAR_SCR}{C_GOTO_C0L0}"
        ).encode("utf-8")
    )
    if safe_flush(cf) != 0:
        return

    if options.welcome_msg:
        cf.write((
           f"{options.welcome_msg}\n"
            ).encode("utf-8")
        )
        if safe_flush(cf) != 0:
            return

    while True:
        cf.write(b"Session username: ")
        if safe_flush(cf) != 0:
            return

        buf = readline(cf)
        if buf == b"EOF":
            return

        buf = buf[:-1] # remove trailing newline
        success, err = validate_username(buf)
        if success:
            break
        else:
            cf.write(err.encode("utf-8"))
            if safe_flush(cf) != 0:
                return
    username = buf.decode("utf-8")

    userlist.add(username)
    user = userlist.get(username)

    if user.screen.set_size(cf) != 0:
        return

    if options.debug:
        print(f"added user {user.name} to userlist")
    userlist.sendall(
        f"[SERVER]: {user.name} joined! Welcome! :D"
    )

    cf.write((
       f"{CLEAR_SCR}\x1b[{user.screen.height}B"
    +  f"Input: "
        ).encode("utf-8")
    )
    if safe_flush(cf) != 0:
        return

    conn.setblocking(False)
    buf = b""
    while True:
        if not user.msg_queue.empty():
            msg = user.msg_queue.get()
            user.screen.msglist.append(msg)

            ui = user.screen.generate()

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
            cf.write((
               f"{CLEAR_LINE}{C_GOTO_C0}Input: "
                ).encode("utf-8")
            )
            if safe_flush(cf) != 0:
                break

            success = True
            buf = buf[:-1] # remove trailing newline
            for byte in buf:
                if byte not in ALLOWED_MSG_CHARS:
                    userlist.sendall(
                       f"[SERVER]: {user.name} tried to send "
                    +  f"disallowed byte '{hex(byte)}' but "
                    +   "i blocked it! >:D"
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

    # Why am I assigning the values this way? I have no idea
    # It looks satisfying though
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

