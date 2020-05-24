#!/usr/bin/env python3
from random import random
from src.ui import *
from src.keys import login
import src.socks as socks
from base64 import b64encode as b64enc
from base64 import b64decode as b64dec

USERNAME = "client1"
CLIENT1_PORT = 54000
CLIENT2_PORT = 55000

class Client:
    def __init__(self, public, private, username):
        self.public = public
        self.private = private
        self.username= username

    def run(self):
        try:

            self.certificate, server_public = socks.get_certificate_from_server(self.username, self.public, self.private)
            
            socks.start_and_do_handshake(public=self.public,
                                         private=self.private,
                                         certificate=self.certificate,
                                         server_public=server_public)
        except KeyboardInterrupt:
            print_red(f"{self.username} quitting...")

if __name__ == "__main__":
    print_banner(message="ClientChat ON")
    public, private = login(USERNAME)
    
    Client(public, private, USERNAME).run() 
    print_red("Exiting slyther...")

