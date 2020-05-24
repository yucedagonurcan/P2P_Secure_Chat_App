#!/usr/bin/env python3
import socket
from src.ui import *
from src.keys import login
from datetime import datetime
from Crypto.PublicKey import RSA
from src.socks import receive, send, PORT, send_certificate

USERNAME="server1"


def get_contact_id(ip, contacts):
    """
    Given an IP address, finds the corresponding contact ID.

    Args:
        ip: The ip address to match with a contact name.
        contacts: The contacts dictionary to search.

    Return:
        The ID of the contact if the IP is known, otherwise the IP.
    """
    for contact_id in contacts:
        if contacts[contact_id]["ip"] == ip:
            return contact_id
    return ip


def handle_client(sock, addr, public, private):
    """
    Thread that receives a message from a connection.

    Args:
        sock: The socket the client has connected on.
        addr: Tuple of the IP address and port of the connection.
        public: The public key of this user.
        private: The private key of this user.
    """
    try:
        
        
        received_msg = receive(sock)
        
        client_username = received_msg[:7].decode()
        client_public = RSA.import_key(received_msg[7:])
        
        print_yellow(f"* New connection: {client_username}")
        
        print(" > Performing key exchange...")
        
        print(f"    : Received public key from {client_username}")


        # send(sock, public.export_key())
        print(f"    : Sent public key to >{client_username}<")
        
        send_certificate(sock=sock, username=client_username, public=public, client_public=client_public, private=private)

        
        # print(" > Receiving message...")
        # session_key = receive_session(sock, client_public, private)
        # print("    : Received session key.")
        # message = receive_aes(sock, client_public, session_key)
        # print("    : Received message.")
    except ValueError as e:
        print_red("    : Error receiving message.")
        print(e)
    except OSError:
        print_red("    : Connection lost. Message not received.")
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


