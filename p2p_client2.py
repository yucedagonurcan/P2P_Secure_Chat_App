#!/usr/bin/env python3
from time import sleep
from datetime import datetime
from random import random
from subprocess import run
import json

from src.ui import *
from src.keys import login
import src.socks as socks

USERNAME = "client2"
CLIENT1_PORT = 54000
CLIENT2_PORT = 55000

class Client:
    def __init__(self, public, private, username):
        self.public = public
        self.private = private
        self.username= username

    def run(self):
        try:
            # Sertifika = Username + client_publicKey + rsa_sign(server_privateKey, client_publicKey)
            self.certificate, server_public = socks.get_certificate_from_server(self.username, self.public, self.private)
            socks.wait_and_do_handshake(self.public, self.private, self.certificate, server_public)
            # self.main_menu()
        except KeyboardInterrupt:
            
            print_red(f"{self.username} quitting...")

if __name__ == "__main__":
    print_banner(message="ClientChat ON")
    public, private = login(USERNAME)
    
    Client(public, private, USERNAME).run() 
    print_red("Exiting slyther...")