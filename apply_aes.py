from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import binascii
import timeit


# Function to perform AES encryption with padding
def aes_encrypt(key, plaintext):
    """
    Encrypts the plaintext using AES encryption algorithm in ECB mode with padding.

    Parameters:
    key (bytes): The encryption key.
    plaintext (str): The plaintext to be encrypted.

    Returns:
    bytes: The encrypted ciphertext.
    """
    # Create a cipher object using the provided key and AES mode in ECB (Electronic Codebook) mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad the plaintext to match the block size of AES and then encrypt it
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))

    return ciphertext


# Function to perform AES decryption
def aes_decrypt(key, encrypted_text):
    """
    Decrypts the ciphertext using AES decryption algorithm in ECB mode.

    Parameters:
    key (bytes): The decryption key.
    encrypted_text (bytes): The ciphertext to be decrypted.

    Returns:
    str: The decrypted plaintext.
    """
    # Create a cipher object using the provided key and AES mode in ECB (Electronic Codebook) mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Decrypt the ciphertext and remove padding to retrieve the original plaintext
    decrypted_bytes = cipher.decrypt(encrypted_text)
    plaintext = unpad(decrypted_bytes, AES.block_size).decode()
    
    return plaintext
