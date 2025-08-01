# Encrypted Messaging App Prototype using RSA and AES

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# Step 1: User A generates RSA key pair
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)
    return public_key, private_key

# Step 2: User B encrypts the message with AES and encrypts AES key with RSA public key
def encrypt_message(public_key_file, message_file):
    # Read public key
    public_key = RSA.import_key(open(public_key_file).read())

    # Generate AES key
    aes_key = get_random_bytes(32)  # AES-256

    # Encrypt the message using AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    with open(message_file, "rb") as file:
        plaintext = file.read()
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)

    with open("encrypted_message.bin", "wb") as enc_file:
        enc_file.write(cipher_aes.nonce + tag + ciphertext)

    # Encrypt AES key using RSA
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    with open("aes_key_encrypted.bin", "wb") as key_file:
        key_file.write(encrypted_aes_key)

# Step 3: User A decrypts the AES key and message using private RSA key
def decrypt_message(private_key_file):
    # Load private RSA key
    private_key = RSA.import_key(open(private_key_file).read())

    # Decrypt AES key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    with open("aes_key_encrypted.bin", "rb") as key_file:
        encrypted_aes_key = key_file.read()
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    # Decrypt AES message
    with open("encrypted_message.bin", "rb") as enc_file:
        nonce = enc_file.read(16)
        tag = enc_file.read(16)
        ciphertext = enc_file.read()

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    with open("decrypted_message.txt", "wb") as dec_file:
        dec_file.write(plaintext)


# Execute steps

# Step 1: RSA keys generation
pub_key, priv_key = generate_rsa_keys()

# Prepare a sample message
with open("message.txt", "w") as msg_file:
    msg_file.write("Hello, this is a secret message!")

# Step 2: Encrypt message using RSA & AES
encrypt_message("public.pem", "message.txt")

# Step 3: Decrypt message using private RSA key
decrypt_message("private.pem")
