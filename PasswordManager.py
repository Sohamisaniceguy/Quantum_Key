import os
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from time import sleep
import getpass
import colorama
from colorama import Fore, Style
import pyotp
import qrcode

# Path to store the master password hash and encryption key
MASTER_PASSWORD_HASH_FILE = "master_password_hash.txt"
KEY_FILE = "key.key"
PASSWORD_FILE = "passwords.txt"
TOTP_SECRET_FILE = "totp_secret.key"

colorama.init(autoreset=True)  # Initialize colorama for colored output

# Secure file permission settings (for UNIX systems)
def set_secure_file_permissions(file_path):
    if os.name == 'posix':
        os.chmod(file_path, 0o600)

# Function to hash the master password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed

# Function to verify the master password
def verify_master_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash)

# Setup the master password securely
def setup_master_password():
    if not os.path.exists(MASTER_PASSWORD_HASH_FILE):
        print(f"{Fore.YELLOW}Set a strong master password:")
        master_password = getpass.getpass("Master password: ")
        hashed_password = hash_password(master_password)
        with open(MASTER_PASSWORD_HASH_FILE, "wb") as hash_file:
            hash_file.write(hashed_password)
        set_secure_file_permissions(MASTER_PASSWORD_HASH_FILE)
        print(f"{Fore.GREEN}Master password set successfully.")

        # Generate and save TOTP secret
        totp = pyotp.random_base32()
        with open(TOTP_SECRET_FILE, "wb") as secret_file:
            secret_file.write(totp.encode())
        set_secure_file_permissions(TOTP_SECRET_FILE)

        # Create a TOTP URI
        totp_uri = f"otpauth://totp/QuantumKey?secret={totp}&issuer=QuantumKey"

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_uri)
        qr.make(fit=True)

        # Create an ASCII representation of the QR code
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_img.show()  # Displaying the QR code image

        # Print the QR code in terminal
        qr_terminal = qr.get_matrix()
        for row in qr_terminal:
            print(' '.join(['██' if col else '  ' for col in row]))

        print(f"{Fore.GREEN}TOTP secret generated. Use the following key in your authenticator app: {totp}")
        

    else:
        print(f"{Fore.RED}Master password is already set.")

# Verify the master password
def verify_master_password_input():
    master_password = getpass.getpass("Enter the master password: ")
    with open(MASTER_PASSWORD_HASH_FILE, "rb") as hash_file:
        stored_hash = hash_file.read()
    return bcrypt.checkpw(master_password.encode(), stored_hash)

# Verify TOTP code
def verify_totp():
    with open(TOTP_SECRET_FILE, "rb") as secret_file:
        totp_secret = secret_file.read().decode()
    totp = pyotp.TOTP(totp_secret)
    otp_code = input("Enter the TOTP code from your authenticator app: ")
    return totp.verify(otp_code)

# Generate a 256-bit (32-byte) encryption key
def generate_key():
    key = os.urandom(32)  # Generate a 256-bit key
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    set_secure_file_permissions(KEY_FILE)

# Load the existing encryption key
def load_key():
    return open(KEY_FILE, "rb").read()

# Encrypt the password using AES
def encrypt_password(password, key):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding the password to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(password.encode()) + padder.finalize()

    encrypted_password = iv + encryptor.update(padded_data) + encryptor.finalize()  # Prepend IV
    return encrypted_password

# Decrypt the password using AES
def decrypt_password(encrypted_password, key):
    iv = encrypted_password[:16]  # Extract the IV
    ciphertext = encrypted_password[16:]  # The rest is the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpadding the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode()

# Save encrypted passwords to a file
def save_password(service, username, password):
    if not os.path.exists(KEY_FILE):
        generate_key()

    key = load_key()
    encrypted_password = encrypt_password(password, key)
    service = service.lower()

    with open(PASSWORD_FILE, "a") as password_file:
        password_file.write(f"{service}:{username}:{encrypted_password.hex()}\n")  # Store as hex for readability
    set_secure_file_permissions(PASSWORD_FILE)

# Retrieve a password
def retrieve_password(service):
    key = load_key()
    service = service.lower()

    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as password_file:
            for line in password_file.readlines():
                stored_service, stored_username, encrypted_password = line.strip().split(":")
                if stored_service == service:
                    decrypted_password = decrypt_password(bytes.fromhex(encrypted_password), key)
                    return stored_username, decrypted_password
    return None, None

# List all stored services
def list_services():
    services = set()
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r") as password_file:
            for line in password_file.readlines():
                stored_service, _, _ = line.strip().split(":")
                services.add(stored_service.lower())
    return services

# Function to add timeout for failed login attempts
def enforce_login_attempt_delay():
    print(f"{Fore.RED}Too many failed attempts. Try again in 30 seconds.")
    sleep(30)

# Function to display the logo
def display_logo():
    logo = rf""" 
   ____                   _                                     
  /___ \_   _  __ _ _ __ | |_ _   _ _ __ ___     /\ /\___ _   _ 
 //  / / | | |/ _` | '_ \| __| | | | '_ ` _ \   / //_/ _ \ | | |
/ \_/ /| |_| | (_| | | | | |_| |_| | | | | | | / __ \  __/ |_| |
\___,_\ \__,_|\__,_|_| |_|\__|\__,_|_| |_| |_| \/  \/\___|\__, |
                                                          |___/ 
                                                          
    """
    print(logo)
    print(f"{Fore.YELLOW}Welcome to QuantumKey - Your Secure Password Manager!\n")

# Main menu for the application
def main():
    display_logo()  # Display the logo at the start
    setup_master_password()

    attempts = 3
    while attempts > 0:
        if verify_master_password_input():
            print(f"{Fore.GREEN}Master password verified.")
            
            # Verify TOTP
            if verify_totp():
                print(f"{Fore.GREEN}TOTP verified successfully.")
                break
            else:
                print(f"{Fore.RED}Invalid TOTP code. Please try again.")
                attempts -= 1
                if attempts == 0:
                    enforce_login_attempt_delay()
        else:
            attempts -= 1
            print(f"{Fore.RED}Incorrect password. {attempts} attempt(s) remaining.")
            if attempts == 0:
                enforce_login_attempt_delay()

    while True:
        print(f"\n{Fore.MAGENTA}QuantumKey Menu:")
        print(f"1. {Fore.YELLOW}Save a new password")
        print(f"2. {Fore.YELLOW}List available services")
        print(f"3. {Fore.YELLOW}Retrieve a password")
        print(f"4. {Fore.RED}Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Enter the service name: ")
            username = input("Enter the username: ")
            password = getpass.getpass("Enter the password: ")
            save_password(service, username, password)
            print(f"{Fore.GREEN}Password saved successfully.")
        elif choice == '2':
            services = list_services()
            if services:
                print(f"{Fore.BLUE}Available services:")
                for idx, service in enumerate(services, start=1):
                    print(f" {idx}. {service.title()}")
            else:
                print(f"{Fore.RED}No services found.")
        elif choice == '3':
            services = list_services()
            if services:
                print(f"{Fore.BLUE}Available services:")
                for idx, service in enumerate(services, start=1):
                    print(f" {idx}. {service.title()}")

                while True:
                    service_number = input("Enter the service number (or 'exit' to cancel): ").lower()
                    if service_number == 'exit':
                        break

                    try:
                        service_index = int(service_number) - 1
                        if 0 <= service_index < len(services):
                            service = list(services)[service_index]  # Get the service name using the index
                            username, password = retrieve_password(service)
                            if username:
                                print(f"Username: {username}")
                                print(f"Password: {password}")
                                break
                            else:
                                print(f"{Fore.RED}No password found for this service.")
                        else:
                            print(f"{Fore.RED}Invalid choice. Please try again.")
                    except ValueError:
                        print(f"{Fore.RED}Please enter a valid number.")
            else:
                print(f"{Fore.RED}No services available to retrieve passwords.")
        elif choice == '4':
            print(f"{Fore.GREEN}Exiting QuantumKey. Stay secure!")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
