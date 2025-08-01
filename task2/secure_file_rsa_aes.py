# Secure File Exchange using RSA + AES

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import hashlib

# Step 1: Generate RSA key pair for Bob
def generate_bob_rsa_keys():
    key = RSA.generate(2048)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(key.publickey().export_key())
    with open("private.pem", "wb") as priv_file:
        priv_file.write(key.export_key())

# Step 2: Alice creates a plaintext message
def create_plaintext_file():
    plaintext = "Hi Bob, this file contains a very secret message."
    with open("alice_message.txt", "w") as file:
        file.write(plaintext)

# Step 3 and 4: Alice generates AES key and IV, then encrypts file with AES
def encrypt_file_with_aes(input_file):
    aes_key = get_random_bytes(32)  # AES-256
    iv = get_random_bytes(16)

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

    with open(input_file, "rb") as f:
        plaintext = f.read()

    # Padding for AES
    padding_length = 16 - len(plaintext) % 16
    plaintext += bytes([padding_length]) * padding_length

    ciphertext = cipher_aes.encrypt(plaintext)

    with open("encrypted_file.bin", "wb") as enc_file:
        enc_file.write(iv + ciphertext)

    return aes_key, iv

# Step 5: Alice encrypts AES key using Bob's RSA public key
def encrypt_aes_key_with_rsa(aes_key, public_key_file):
    public_key = RSA.import_key(open(public_key_file).read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    with open("aes_key_encrypted.bin", "wb") as key_file:
        key_file.write(encrypted_key)

# Step 6 and 7: Bob decrypts AES key with his private key and then decrypts file
def decrypt_file(private_key_file, encrypted_file):
    private_key = RSA.import_key(open(private_key_file).read())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    with open("aes_key_encrypted.bin", "rb") as key_file:
        encrypted_aes_key = key_file.read()

    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    with open(encrypted_file, "rb") as enc_file:
        iv = enc_file.read(16)
        ciphertext = enc_file.read()

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = cipher_aes.decrypt(ciphertext)

    # Remove padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    with open("decrypted_message.txt", "wb") as dec_file:
        dec_file.write(plaintext)

# Step 8: Compute SHA-256 hash for integrity verification
def verify_integrity(original_file, decrypted_file):
    hash_original = hashlib.sha256(open(original_file, "rb").read()).hexdigest()
    hash_decrypted = hashlib.sha256(open(decrypted_file, "rb").read()).hexdigest()

    print(f"Original SHA-256: {hash_original}")
    print(f"Decrypted SHA-256: {hash_decrypted}")

    if hash_original == hash_decrypted:
        print("Integrity verified: Files match.")
    else:
        print("Integrity verification failed: Files do not match.")

# Execution Flow

# Generate RSA keys for Bob
generate_bob_rsa_keys()

# Alice creates plaintext message
create_plaintext_file()

# Alice encrypts file with AES
aes_key, iv = encrypt_file_with_aes("alice_message.txt")

# Alice encrypts AES key with RSA public key
encrypt_aes_key_with_rsa(aes_key, "public.pem")

# Bob decrypts AES key and then the file
decrypt_file("private.pem", "encrypted_file.bin")

# Verify file integrity
verify_integrity("alice_message.txt", "decrypted_message.txt")
