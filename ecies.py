#!/usr/bin/env python
# coding: utf-8

# In[2]:


import binascii
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes
import secrets
import hmac
import hashlib


def constant_time_compare(a, b):
    #Compare two byte strings in constant time.
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def validate_plaintext_input(plaintext):
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("Plaintext input must be a non-empty string.")

def validate_block_size_input(block_size):
    if not isinstance(block_size, int) or block_size <= 0 or block_size > 256 or block_size % 8 != 0:
        raise ValueError("Block size input must be a multiple of 8 and less than or equal to 256.")

def validate_ecc_key_input(key):
    if not isinstance(key, ECC.EccKey):
        raise ValueError("Invalid ECC key input.")

def validate_salt_input(salt):
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError("Salt input must be a 16-byte bytes object.")

def validate_key_input(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Key input must be a 32-byte bytes object.")

def validate_iv_input(iv):
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise ValueError("IV input must be a 16-byte bytes object.")

def validate_ciphertext_input(ciphertext):
    if not isinstance(ciphertext, bytes) or not ciphertext:
        raise ValueError("Ciphertext input must be a non-empty bytes object.")

def validate_mac_input(mac):
    if not isinstance(mac, bytes) or len(mac) != 32:
        raise ValueError("MAC input must be a 32-byte bytes object.")

def validate_plaintext_output(plaintext):
    if not isinstance(plaintext, str) or not plaintext:
        raise ValueError("Plaintext output must be a non-empty string.")

def validate_ephemeral_key_output(ephemeral_key):
    if not isinstance(ephemeral_key, ECC.EccKey):
        raise ValueError("Invalid ephemeral key output.")

def validate_key_output(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Key output must be a 32-byte bytes object.")

def validate_iv_output(iv):
    if not isinstance(iv, bytes) or len(iv) != 16:
        raise ValueError("IV output must be a 16-byte bytes object.")

def validate_ciphertext_output(ciphertext):
    if not isinstance(ciphertext, bytes) or not ciphertext:
        raise ValueError("Ciphertext output must be a non-empty bytes object.")

def validate_mac_output(mac):
    if not isinstance(mac, bytes) or len(mac) != 32:
        raise ValueError("MAC output must be a 32-byte bytes object.")


def ECIES_encrypt(sender_key, recipient_key, plaintext, block_size):
    try:
        validate_plaintext_input(plaintext)
        validate_block_size_input(block_size)
        validate_ecc_key_input(sender_key)
        validate_ecc_key_input(recipient_key)

        # Generate a new ephemeral key pair
        ephemeral_key = ECC.generate(curve='secp521r1')
        # Compute the shared secret
        shared_secret = sender_key.d * recipient_key.pointQ
        # Convert the shared secret to bytes
        shared_secret_bytes = long_to_bytes(shared_secret.x)
        # Generate a random salt value
        salt = secrets.SystemRandom().randbytes(16)
        # Derive the key and IV using HKDF with the random salt value
        key_iv = HKDF(shared_secret_bytes, 48, salt, hashmod=SHA256)
        key = key_iv[:32]
        iv = key_iv[32:]
        validate_key_output(key)
        validate_iv_output(iv)
        # Encrypt the plaintext using AES-CBC with the derived key and IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = pad(plaintext.encode('utf-8'), block_size)
        ciphertext = cipher.encrypt(plaintext)
        validate_ciphertext_output(ciphertext)
        # Compute the HMAC authentication tag
        mac = HMAC.new(key, msg=ciphertext, digestmod=SHA256).digest()
        validate_mac_output(mac)
        # Return the ephemeral key, derived key, IV, ciphertext, HMAC authentication tag, and salt
        return (ephemeral_key, key, iv, ciphertext, mac, salt)
    except ValueError as ve:
        print("Encryption failed due to a value error:", str(ve))
    except TypeError as te:
        print("Encryption failed due to a type error:", str(te))
    except OverflowError as oe:
        print("Encryption failed due to an overflow error:", str(oe))
    except AssertionError as ae:
        print("Encryption failed due to an assertion error:", str(ae))
    except Exception as e:
        print("Encryption failed due to an unexpected error:", str(e))
        return None



def ECIES_decrypt(private_key, ephemeral_key, key, iv, ciphertext, mac, block_size):
    try:
        validate_ecc_key_input(private_key)
        validate_ecc_key_input(ephemeral_key)
        validate_key_input(key)
        validate_iv_input(iv)
        validate_ciphertext_input(ciphertext)
        validate_mac_input(mac)
        validate_block_size_input(block_size)

        # Compute the shared secret
        shared_secret = ephemeral_key.d * private_key.pointQ
        # Convert the shared secret to bytes
        shared_secret_bytes = long_to_bytes(shared_secret.x)
        # Hash the shared secret
        shared_secret_hashed = SHA256.new(shared_secret_bytes).digest()

        # Verify the HMAC authentication tag
        if not constant_time_compare(HMAC.new(key, msg=ciphertext, digestmod=SHA256).digest(), mac):
            raise ValueError("MAC verification failed")

        # Decrypt the ciphertext using AES-CBC with the provided key and IV
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext, block_size)

        # securely erase sensitive data from memory
        key = bytearray(32)
        iv = bytearray(16)
        mac = bytearray(32)

        # Return the decrypted plaintext
        validate_plaintext_output(plaintext.decode('utf-8'))
        return plaintext.decode('utf-8')

    except ValueError as ve:
        print("Decryption failed due to a value error:", str(ve))
    except TypeError as te:
        print("Decryption failed due to a type error:", str(te))
    except OverflowError as oe:
        print("Decryption failed due to an overflow error:", str(oe))
    except AssertionError as ae:
        print("Decryption failed due to an assertion error:", str(ae))
    except Exception as e:
        print("Decryption failed due to an unexpected error:", str(e))
    finally:
        # securely erase sensitive data from memory
        plaintext = bytearray(len(plaintext))
        key = bytearray(32)
        iv = bytearray(16)
        mac = bytearray(32)

# Generate a new ECC key pair for the sender
sender_key = ECC.generate(curve='secp521r1')

# Generate a new ECC key pair for the recipient
recipient_key = ECC.generate(curve='secp521r1')

# User input for plaintext
def validate_plaintext(plaintext):
    if not isinstance(plaintext, str):
        raise ValueError("Plaintext must be a string")
    if len(plaintext) < 1 or len(plaintext) > 1024:
        raise ValueError("Plaintext must be between 1 and 1024 characters long")
    return plaintext

plaintext = input("Enter plaintext to encrypt: ")
plaintext = validate_plaintext(plaintext)

# Default block size of 16
block_size = 16

# Encrypt the plaintext using ECIES with the generated ephemeral key pair
ephemeral_key, key, iv, ciphertext, mac, salt = ECIES_encrypt(sender_key, recipient_key, plaintext, block_size)

# Store the returned values in a dictionary with a unique identifier for the plaintext
stored_values = {"plaintext": plaintext, "ephemeral_key": ephemeral_key, "key": key, "iv": iv, "ciphertext": ciphertext, "mac": mac}

# Validate the encryption process by decrypting the ciphertext and checking if the original plaintext is obtained
try:
    decrypted_plaintext = ECIES_decrypt(recipient_key, ephemeral_key, key, iv, ciphertext, mac, block_size)
    print("Encryption successful!")
    print("Original plaintext:", plaintext)
    print("Decrypted plaintext:", decrypted_plaintext)
    # Verify if the decrypted plaintext is equal to the original plaintext
    if decrypted_plaintext == plaintext:
        print("Original plaintext matches decrypted plaintext!")
    else:
        print("Original plaintext does not match decrypted plaintext.")
except ValueError:
    print("Decryption failed.")

# Store the ephemeral key, key, and IV in a dictionary with a unique identifier for the plaintext
stored_values = {"plaintext": plaintext, "ephemeral_key": ephemeral_key, "key": key, "iv": iv, "ciphertext": ciphertext, "mac": mac}

# Encrypt the same plaintext using ECIES with a new ephemeral key pair
new_ephemeral_key, new_key, new_iv, new_ciphertext, new_mac, new_salt = ECIES_encrypt(sender_key, recipient_key, plaintext, block_size)

if new_ephemeral_key is None:
    print("New encryption failed.")
else:
    # Store the new ephemeral key, key, and IV in the same dictionary with a new identifier
    stored_values2 = {"plaintext": plaintext, "ephemeral_key": new_ephemeral_key, "key": new_key, "iv": new_iv, "ciphertext": new_ciphertext, "mac": new_mac}

    # Decrypt the original ciphertext using ECIES with the stored ephemeral key, key, and IV
    decrypted_plaintext = ECIES_decrypt(recipient_key, stored_values["ephemeral_key"], stored_values["key"], stored_values["iv"], stored_values["ciphertext"], stored_values["mac"], block_size)
    if decrypted_plaintext is None:
        print("Decryption of original ciphertext failed.")
    else:
        print("Decryption of original ciphertext successful!")
        print("Original decrypted plaintext:", decrypted_plaintext)
        # Verify if the decrypted plaintext is equal to the original plaintext
        if decrypted_plaintext == plaintext:
            print("Original plaintext matches decrypted plaintext!")
        else:
            print("Original plaintext does not match decrypted plaintext.")

# Decrypt the new ciphertext using ECIES with the correct ephemeral key
new_decrypted_plaintext = ECIES_decrypt(recipient_key, stored_values2["ephemeral_key"], stored_values2["key"], stored_values2["iv"], new_ciphertext, stored_values2["mac"], block_size)
if new_decrypted_plaintext is None:
    print("Decryption of new ciphertext failed.")
else:
    print("Decryption of new ciphertext successful!")
    print("New decrypted plaintext:", new_decrypted_plaintext)
    # Verify if the new decrypted plaintext is equal to the original plaintext
    if new_decrypted_plaintext == plaintext:
        print("Original plaintext matches new decrypted plaintext!")
    else:
        print("Original plaintext does not match new decrypted plaintext.")


# In[ ]:





# In[ ]:




