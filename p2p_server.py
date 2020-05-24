#!/usr/bin/env python3
import socket
from src.ui import *
from src.keys import login
from datetime import datetime
from Crypto.PublicKey import RSA
from src.socks import receive, send, PORT, send_certificate

USERNAME="server1"

def handle_client(sock, addr, public, private):
    """
    Method that receives a message from a connection.

    Args:
        sock: The socket the client has connected on.
        addr: Tuple of the IP address and port of the connection.
        public: The public key of this user.
        private: The private key of this user.
    """
    try:
        
        
        received_msg = receive(sock)
        
        client_username = received_msg[:7].decode()
        print_yellow(f"* New connection: {client_username}")
        client_public = RSA.import_key(received_msg[7:])
        
        print(" > Performing key exchange...")
        print(f"    : Received public key from {client_username}")
        
        send_certificate(sock=sock, username=client_username, public=public, client_public=client_public, private=private)
        print(f"    : Sent certificate to >{client_username}<")

    except ValueError as e:
        
        print_red("    : Error receiving message.")
        print(e)
        
    except OSError:
        
        print_red("    : Connection lost. Message not recieved.")
        
    finally:
        
        print(f" > Closing connection with {client_username}...\n")
        sock.close()
        

if __name__ == "__main__":

    print_banner("ServerChat ON")
    
    # Load keys
    public, private = login(username=USERNAME)


    # Bind socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            server_addr = ("localhost", PORT)
            sock.bind(server_addr)
            sock.listen(5)

            # Acceptance loop
            print("Listening for connections...")
            while True:
                connection, addr = sock.accept()
                handle_client(connection, addr, public, private)

    except OSError:
        print_red("Error: Failed to start chat-app-server: Port {} in use.".format(PORT))


