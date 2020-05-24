import os
import sys 
import base64
import select
import socket
import struct
import random

from src.ui import *
from src.keys import save_keys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

PORT = 5300
CLIENT1_PORT = 54000
CLIENT2_PORT = 55000
SERVER_IP = "localhost"


def start_and_do_handshake(public, private, certificate, server_public):
    
    # We will connect client2 from client1.
    contact_addr = (SERVER_IP, CLIENT2_PORT)

    with socket.create_connection(contact_addr, 15) as to_socket:
        
        # Send the certificate of client1 to client2.
        # Also send public key and 'Hello' message as well.
        send_handshake_message_with_cert(connection=to_socket,
                                        msg="Hello",
                                        public=public,
                                        certificate=certificate)
        
        # Receive the certificate from client2.
        # Also receive client2 public key and it's generated nonce integer.
        nonce, client2_public, client2_certificate = receive_handshake_with_nonce(connection=to_socket,
                                                                public=public,
                                                                private=private, certificate=certificate)
        
        # We get the client2 public key as string, so we create RSA object from it.
        client2_public = RSA.import_key(client2_public)
        
        # Certificate has Server public key, client2 name and client2 signature so we need to parse it to get them. 
        client2_name, server_public, client2_signature = parse_certificate(client2_certificate)
        
        # Sign the nonce message with client1's private key and send it to the client2.
        send_handshake_message_with_nonce_encrypted(connection=to_socket, private=private, nonce=nonce)
        
        # Wait for ack message to be received.
        ack_received = receive_ack_message(connection=to_socket)
        
        # If ack is received okay.
        if(ack_received):
            
            # Master Secret = (16 byte AES key) + (16 byte Initialization Vector)
            master_secret = generate_master_key()

            # Encrypt Master Secret with client2's public key.
            encrypted_master_secret = encrypt_pubkey_with_master_secret(master_secret=master_secret, public=client2_public)
            
            # Send encrypted master secret to the client2.
            send_ecrypted_master_secret(connection=to_socket, enc_master_key=encrypted_master_secret)
            
            # First 16 byte is AES Key.
            aes_key = master_secret[:16]
            
            # Last 16 byte is Initialization Vector.
            init_vec = master_secret[16:]
            
            try:
                '''
                - We are ready for messaging, for client1 to be receive message we will open a second socket in client1
                and let the client2 to connect it.
                
                - We will also use 'select' library to implement concurency:
                    - We will have two different buffers:
                        - from_socket: client2's send socket, it will use this socket to send message to client1.
                        - sys.stdin: If we press < enter > we need to listen it because it means client1 wants to send a message to client2.
                    - If any of these buffers full with input, we will take action: 
                        - Send a message to client2.
                        - Receive from client2.
                ''' 
                
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_from_socket:
                    server_addr = (SERVER_IP, CLIENT1_PORT)
                    listen_from_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listen_from_socket.bind(server_addr)
                    listen_from_socket.listen(5)
                    
                    from_socket, _ = listen_from_socket.accept()                 
                    print_yellow("You are all set for the messaging...")
                    print_yellow("-------------------------------------")

                    while(True):
                        
                        # Define the buffers.
                        socket_list = [sys.stdin, from_socket]
                        
                        # Create a selector object.
                        read_from_socket, _, _ = select.select(socket_list, [], [])
                        
                        # Check select objects:
                        for cur_sock in read_from_socket:
                            
                            # If any incoming message is exist in 'from_socket'
                            if cur_sock == from_socket:
                                
                                # Receive: Hashed Message + AES Encrypted Message
                                aes_encrypted_and_hashed_message = receive_aes_encrypted_and_hashed_msg(connection=cur_sock)
                                
                                # We will use 'marmara' string as splitter for these two different message strings: Hashed Message + AES Encrypted Message
                                hashed_message, aes_encrypted_message = aes_encrypted_and_hashed_message.split("marmara".encode())
                                
                                # Decrypt the aes_encrypted_message with IV and AES Key.
                                # We will pad the string to be 16 byte in function using 'pad' function                               
                                incoming_message_raw = decrypt_aes_with_iv(message=aes_encrypted_message, key=aes_key, iv=init_vec)
                                
                                # We need to unpad and decode the incoming message to be get as a text using 'unpad' function.
                                incoming_message = process_incoming_message(incoming_message_raw)
                                
                                # Check the message integrity by:
                                #   - HMAC(AES_Key, incoming_message) ?= hashed_message
                                if(check_message_integrity(raw_message=incoming_message.encode(), aes_key=aes_key, hashed_message=hashed_message)):
                                    
                                    # If it is okay, print the incoming message as green. 
                                    print_green(f"> {client2_name}:= {incoming_message}")
                            
                            # If we want to send a message to the client2                                
                            else:
                                
                                # Process input message, make it English.
                                message = process_input_message(sys.stdin.readline())
                                
                                # Hash the message with HMAC.
                                hashed_message = encrypt_hmac(message=message.encode(), key=aes_key)
                                
                                # Encrypt the message with AES Key and Initialization Vector.
                                aes_encrypted_message = encrypt_aes_with_iv(message=message, key=aes_key, iv=init_vec)
                                
                                # Send: Hashed Message + AES Encrypted Message
                                send_aes_encrypted_and_hashed_msg(connection=to_socket, aes_encrypted_and_hashed_message=hashed_message + "marmara".encode() + aes_encrypted_message )
                                
                                # Print the message as yellow.
                                print_yellow(f"> client1:= {message}")
                                sys.stdout.flush()
                                
            except OSError as e:
                    print_red("Error: Failed to start chat-app: Port {} in use.".format(CLIENT2_PORT))
                    print_red(e)

def wait_and_do_handshake(public, private, certificate, server_public):
    
    # Open a socket in client2 that can be connected from client1.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_from_socket:
            server_addr = (SERVER_IP, CLIENT2_PORT)
            listen_from_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_from_socket.bind(server_addr)
            listen_from_socket.listen(5)


            # Accept the incoming connection request from client1
            from_socket, _ = listen_from_socket.accept()
            
            # Receive 'Hello' message from client1 with client1's public key and client1 certificate
            hello_message, client1_public, client1_cert = receive_handshake_message_with_cert(connection=from_socket, public=public, private=private)
            
            # We get the client1 public key as string, so we create RSA object from it.
            client1_public = RSA.import_key(client1_public)
            
            # Certificate has Server public key, client1 name and client1 signature so we need to parse it to get them. 
            client1_name, server_public, client1_signature = parse_certificate(client1_cert)
            
            # Generate a nonce integer between 0-9
            nonce = str(random.randint(0,9))
            
            # Send the nonce with client2's certificate as well as client2 public key.
            send_handshake_message_with_cert(connection=from_socket, msg=nonce, public=public,
                                            certificate=certificate)
            
            # Receive the nonce message with signed by client2's public key.
            encrypted_nonce_msg = receive_handshake_message_with_nonce_encrypted(from_socket, nonce)
            
            # Verify the signed nonce message with client1's public key.
            nonce_found = verify(nonce.encode(), encrypted_nonce_msg, client1_public) 
                
            # If we successfully verified the nonce message.
            if(nonce_found):
                
                # Send the ack message to client1.
                send_ack_message(connection=from_socket)
                
                # Receive Master Secret from client1: (16 byte AES key) + (16 byte Initialization Vector)
                enc_master_secret = receive_encrypted_master_secret(connection=from_socket)
                
                # Decrypt the encrypted master secret with client2's private key to get master secret.
                master_secret = decrypt_rsa(message=enc_master_secret, key=private)

                # First 16 byte is AES Key.
                aes_key = master_secret[:16]

                # Last 16 byte is Initialization Vector.
                init_vec = master_secret[16:]
                
                
                # Connect the newly created socket of client1 to send message to her.
                listen_cl1_addr = (SERVER_IP, CLIENT1_PORT)

                with socket.create_connection(listen_cl1_addr, 15) as to_socket:
                    
                    print_yellow("You are all set for the messaging...")
                    print_yellow("-------------------------------------")
                    while(True):
                        
                        # Define the buffers.
                        socket_list = [sys.stdin, from_socket]
                        
                        # Create a selector object.
                        read_from_socket, _, _ = select.select(socket_list, [], [])
                        
                        # Check select objects:
                        for cur_sock in read_from_socket:
                            
                            # If any incoming message is exist in 'from_socket'
                            if cur_sock == from_socket:
                                
                                # Receive: Hashed Message + AES Encrypted Message
                                aes_encrypted_and_hashed_message = receive_aes_encrypted_and_hashed_msg(connection=cur_sock)
                                
                                # We will use 'marmara' string as splitter for these two different message strings: Hashed Message + AES Encrypted Message
                                hashed_message, aes_encrypted_message = aes_encrypted_and_hashed_message.split("marmara".encode())

                                # Decrypt the aes_encrypted_message with IV and AES Key.
                                # We will pad the string to be 16 byte in function using 'pad' function                               
                                incoming_message_raw = decrypt_aes_with_iv(message=aes_encrypted_message, key=aes_key, iv=init_vec)
                                
                                # We need to unpad and decode the incoming message to be get as a text using 'unpad' function.
                                incoming_message = process_incoming_message(incoming_message_raw)
                                
                                # Check the message integrity by:
                                #   - HMAC(AES_Key, incoming_message) ?= hashed_message
                                if(check_message_integrity(raw_message=incoming_message.encode(), aes_key=aes_key, hashed_message=hashed_message)):
                                    
                                    # If it is okay, print the incoming message as green. 
                                    print_green(f"> {client1_name}:= {incoming_message}")
                                                                
                            else:
                                # Process input message, make it English.
                                message = process_input_message(sys.stdin.readline())
                                
                                # Hash the message with HMAC.
                                hashed_message = encrypt_hmac(message=message.encode(), key=aes_key)
                                
                                # Encrypt the message with AES Key and Initialization Vector.
                                aes_encrypted_message = encrypt_aes_with_iv(message=message, key=aes_key, iv=init_vec)
                                
                                # Send: Hashed Message + AES Encrypted Message
                                send_aes_encrypted_and_hashed_msg(connection=to_socket, aes_encrypted_and_hashed_message=hashed_message + "marmara".encode() + aes_encrypted_message )

                                # Print the message as yellow.
                                print_yellow(f"> client2:= {message}")
                                sys.stdout.flush()
    except OSError as e:
        print_red("Error: Failed to start chat-app: Port {} in use.".format(CLIENT2_PORT))
        print_red(e)
        
        
def send_handshake_message_with_cert(connection, msg, public, certificate):
    
    handshake_with_msg = base64.b64encode(msg.encode() + public.export_key() + certificate)
    send(connection, handshake_with_msg)

def parse_handshake_msg(handshake_with_msg):
    
    decoded_handshake_with_msg = base64.b64decode(handshake_with_msg)
    nonce = None
    message = None
    certificate = None
    client_public = None
    
    # If first 5 character is 'Hello' we send the Hello message.
    if(decoded_handshake_with_msg[:5].decode() == 'Hello'):
        message = decoded_handshake_with_msg[:5].decode()
        client_public = decoded_handshake_with_msg[5:455]
        certificate = decoded_handshake_with_msg[455:]
        
    # Else, we sent the nonce message.
    else:
        nonce = decoded_handshake_with_msg[:1].decode()
        client_public = decoded_handshake_with_msg[1:451]
        certificate = decoded_handshake_with_msg[451:]
        
    return nonce, message, client_public, certificate
        
        
def receive_handshake_message_with_cert(connection, public, private):
    handshake_with_msg = receive(connection)
    nonce, message, client_public, client_certificate = parse_handshake_msg(handshake_with_msg)
    
    if(message):
        return message, client_public, client_certificate
    elif(nonce):
        return nonce, client_public, client_certificate
    
    
    
def receive_handshake_with_nonce(connection, public, private, certificate):
    nonce, client_public, client2_certificate = receive_handshake_message_with_cert(connection=connection,
                                                public=public,
                                                private=private)
    return nonce, client_public, client2_certificate

def receive_handshake_message_with_nonce_encrypted(connection, nonce):
    encrypted_nonce_msg = receive(connection)
    return encrypted_nonce_msg

    
def receive_ack_message(connection):
    ack_msg = receive(connection) 
    return ack_msg == 'okay'.encode()

def send_handshake_message_with_nonce_encrypted(connection, private, nonce):
    handshake_with_nonce_enc = sign(nonce.encode(), private)
    send(connection, handshake_with_nonce_enc)      
    pass  

def send_ack_message(connection):
    send(connection, 'okay'.encode())   

def generate_master_key():
    '''
    Generate Master Secret with:
        - Random 16 byte AES Key
        - Random 16 byte Initialization Vector.
    '''
    key = os.urandom(16)
    iv = os.urandom(16)
    return key + iv

        
def process_input_message(raw_message):
    return raw_message.strip().lower().replace("ü", "u").replace("ö", "o").replace("ş", "s").replace("ğ", "g").replace("ı", "i").replace("ç", "c")
    
def send_aes_encrypted_and_hashed_msg(connection, aes_encrypted_and_hashed_message):
    send(connection, aes_encrypted_and_hashed_message)

    
def send_ecrypted_master_secret(connection, enc_master_key):
    send(connection, enc_master_key)
        
def encrypt_pubkey_with_master_secret(master_secret, public):
    encrypted_master_secret = encrypt_rsa(message=master_secret, key=public)
    return encrypted_master_secret

def check_message_integrity(raw_message, aes_key, hashed_message):
    regenerated_hashed_message = encrypt_hmac(message=raw_message, key=aes_key)
    return regenerated_hashed_message == hashed_message
    


def process_incoming_message(incoming_message_raw):
    return unpad(incoming_message_raw.decode())


def receive_aes_encrypted_and_hashed_msg(connection):
    aes_encrypted_and_hashed_message = receive(connection)
    return aes_encrypted_and_hashed_message
        
def receive_encrypted_master_secret(connection):
    encrypted_master_secret = receive(connection) 
    return encrypted_master_secret


def get_certificate_from_server(username, client_public, client_private):
    
    contact_addr = (SERVER_IP, PORT)

    with socket.create_connection(contact_addr, 15) as sock:
        # Exchanging public keys
        send(sock, username.encode() + client_public.export_key())
        certificate = receive_certificate(sock=sock)
        username, server_public, signature = parse_certificate(certificate)
        server_name = "server1"
        if (check_certificate(certificate=signature, server_public=server_public, client_public=client_public)):
            print(f'Successfully retrieved the certificate from {server_name}')
        save_keys(private=None, public=server_public, username=server_name)
        
        return certificate, server_public

def parse_certificate(certificate):
    '''
    Certificate = Username + ClientPublicKey + Signature(ClientPublicKey, ServerPrivateKey)
    '''
    decoded_cert = certificate
    username = decoded_cert[:7].decode()
    public_key = RSA.import_key(decoded_cert[7:457])
    signature = decoded_cert[457:]
    
    return username, public_key, signature


def check_certificate(certificate, server_public, client_public):
    '''
    Checks the certificate with verify function.
    '''
    return verify(message=client_public.export_key(), signature=certificate, key=server_public)



def send_certificate(sock, username, public, client_public, private):
    """
    Sends the certificate to the clients that requested.

    Args:
        sock: The socket connected to the client.
        username: Client username that will be embedded into certificate.
        public: Server's public key.
        client_public: Client's public key
        private: Server's private key.
    """
    
    # Certificate = Username + ClientPublicKey + Signature(ClientPublicKey, ServerPrivateKey)
    client_certificate = username.encode() + public.export_key() + sign(client_public.export_key(), private)
    send(sock, client_certificate)
    
    
    
def receive_certificate(sock):
    """
    Receives the certificate from sock.

    Args:
        sock: The socket connected to the client.
    """
    certificate = receive(sock)
    return certificate

def send(sock, message):
    """
    Prefixes a message with its size and sends it to be received by recvall().
    
    Args:
        sock: The socket from which to send.
        message: The data to send.
    """
    packed = struct.pack("h", len(message)) + message
    sock.sendall(packed)


def receive(sock):
    """
    Receives and returns a message sent from send().

    Args:
        sock: The sock from which to receive.
    """
    # Get the length of the message
    message_len_raw = recvall(sock, 2)
    if not message_len_raw:
        return None
    message_len = struct.unpack("=h", message_len_raw)[0]

    # Return the rest of the message
    return recvall(sock, message_len)


def recvall(sock, num_bytes):
    """
    Receives a size-prefixed message from the send() function above.
    Args:
        sock: The socket to receive from.

    Returns:
        The complete message received by the socket, or None if no data is received.
    """
    received = bytes()
    while len(received) < num_bytes:
        data = sock.recv(num_bytes - len(received))
        if not data:
            return None
        received += data

    return received

def encrypt_rsa(message, key):
    """
    Encrypts a message with the provided RSA key.

    Args:
        message: The message (in bytes) to encrypt.
        key: The Crypto.PublicKey.RSA.RsaKey with which to encrypt.

    Returns:
        The encrypted message in bytes.
    """
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(message)

def encrypt_hmac(message, key):

    h = HMAC.new(key, digestmod=SHA256)
    h.update(message)
    return h.digest()

def decrypt_rsa(message, key):
    """
    Decrypts a message with the provided RSA key.

    Args:
        message: The message (in bytes) to decrypt.
        key: The Crypto.PublicKey.RSA.RsaKey with which to decrypt.

    Returns:
        The decrypted message in bytes.
    """
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(message)


unpad = lambda s : s[:-ord(s[len(s)-1:])]
pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16) 


def encrypt_aes_with_iv(message, key, iv):
    """
    Encrypts a message with the provided AES key and Initialization Vector.

    Args:
        message: The message (in bytes) to encrypt.
        key: The AES key (in bytes) with which to encrypt.
        iv: Initialization Vector for using in encryption.
    Returns:
        The encrypted message in bytes.
    """
    
    
    aes_cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv) # master secret
    ciphertext = aes_cipher.encrypt(pad(message).encode())
    return ciphertext


def decrypt_aes_with_iv(message, key, iv):
    """
    Decrypts a message with the provided AES key and Initialization Vector.

    Args:
        message: The message (in bytes) to encrypt.
        key: The AES key (in bytes) with which to decrypt.
        iv: Initialization Vector for using in decrypt.
    Returns:
        The encrypted message in bytes.
    """
    
    aes_cipher = AES.new(key, AES.MODE_CBC, iv)
    return aes_cipher.decrypt(message)

def sign(message, key):
    """
    Returns a signature of a message given an RSA key.

    Args:
        message: The message (in bytes) to sign.
        key: The Crypto.PublicKey.RSA.RsaKey with which to sign the message.

    Returns:
        A signature (in bytes) of the message.
    """
    hasher = SHA256.new()
    hasher.update(message)
    signer = pkcs1_15.new(key)
    return signer.sign(hasher)

def verify(message, signature, key):
    """
    Verifies a signature, throwing an error if it is invalid.

    Args:
        message: The plaintext message (in bytes) signed by the signature.
        signature: The signature produced by sign() to verify.
        key: The opposing key of the Crypto.PublicKey.RSA.RsaKey used to 
            sign the message.

    Raises:
        ValueError: Invalid signature.
    """
    verifier = pkcs1_15.new(key)
    hasher = SHA256.new(message)
    verifier.verify(hasher, signature)
    return True

