from Crypto.PublicKey import RSA
from os import makedirs
from os.path import exists, isfile, join
from src.ui import *

DIR = "data/keys/"
PUBLIC_NAME = "public.pem"
PRIVATE_NAME = "private.pem"


def load_keys(username):
    """
    Loads and returns keys from default paths.
    
    Args:
        password: The password to decrypt the private key file.

    Returns:
        A tuple of (public key, private key), where both keys are 
        Crypto.PublicKey.RSA.RsaKeys.
    """
    try:
        with open(join(DIR, username, PRIVATE_NAME), "rb") as private_file:
            private = RSA.import_key(private_file.read())

        with open(join(DIR, username, PUBLIC_NAME), "rb") as public_file:
            public = RSA.import_key(public_file.read())

    except FileNotFoundError:
        print_red("Error: No keys found.")
        exit()
    except OSError:
        print_red("Error: Keys inaccessible.")
        exit()

    return public, private

def create_keys():
    """Generates and returns a Crypto.PublicKey.RSA.RsaKey pair (in a tuple)"""
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key


def save_keys(private, public, username):
    """
    Saves RSA keys to their default paths.

    Args:
        private: The private key to save.
        public: The public key to save.
        password: The password to encrypt the private key with.
    """
    if not exists(join(DIR, username)):
        makedirs(join(DIR, username))
    if(private is not None):
        encrypted_private = private.export_key(pkcs=8,
                                           protection="scryptAndAES128-CBC")

        try:
            with open(join(DIR, username, PRIVATE_NAME), "wb") as private_file:
                private_file.write(encrypted_private)
        except OSError:
            print_red("Error: Private key file inaccessible.")
            
            


    try:
        with open(join(DIR, username, PUBLIC_NAME), "wb") as public_file:
            public_file.write(public.export_key())
    except OSError:
        print_red("Error: Public key file inaccessible.")


def create_account(username):
    """
    Walks a user through the process of creating an account.
    
    Gets a user password, creates an RSA key pair, and saves them.
    """
    private, public = create_keys()
    save_keys(private, public, username)
    print_green("Account created!\n")


def login(username):
    """Prompts a user for their password, and returns a tuple of their keys upon success."""
    create_account(username)
    
    public = ""
    private = ""
    while True:
        public, private = load_keys(username)            
        break

    print_green(f"You have entered the chat as {username}\n")
    return public, private

