from Crypto.Cipher import AES
from Bio.Seq import Seq
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import binascii
import timeit

from dna_mapping import *


#Function to perform AES encryption with padding
def aes_encrypt(key, plaintext):
    # Pad the plaintext to meet the block size requirement
    block_size = 16  # AES block size is 16 bytes
    padding = block_size - (len(plaintext) % block_size)
    
    plaintext = plaintext.encode() + bytes([padding] * padding)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


# def aes_encrypt(key, plaintext):
#     # Pad the plaintext to meet the block size requirement
#     plaintext = pad(plaintext.encode(), AES.block_size)
#     cipher = AES.new(key, AES.MODE_ECB)
#     ciphertext = cipher.encrypt(plaintext)
#     return ciphertext


# Function to perform decryption
def decrypt(key, encrypted_text):
 
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(encrypted_text)

    plaintext = unpad(decrypted_bytes, AES.block_size).decode()
    return plaintext


# Function to measure performance
def measure_performance(func, *args, **kwargs):
    start_time = timeit.default_timer()
    result = func(*args, **kwargs)
    end_time = timeit.default_timer()
    execution_time = end_time - start_time
    return result, execution_time


# Take input from the user
plaintext = "Machine learning (ML) is a subfield of artificial intelligence (AI) that uses algorithms to learn from data and perform tasks without explicit instructions. "
normal_key = "s_key1"

print("\nPlaintext : ",plaintext)
print("\nKey : ",normal_key)

try:

    dna_encrypted_key, dna_encryption_time = measure_performance(dna_encrypt, normal_key)

    print("\nDna encrypted key:", dna_encrypted_key)

    # Step 2: AES Encryption with DNA-encrypted key
    aes_key = dna_encrypted_key.encode()  # Convert DNA-encrypted key to bytes

    encrypted_text, aes_encryption_time = measure_performance(aes_encrypt, aes_key, plaintext)
    print(encrypted_text)


    # Perform AES decryption using the original DNA key
    decrypted_text, aes_decryption_time = measure_performance(decrypt, aes_key, encrypted_text)

    # Display the decrypted text
    print("\nDecrypted Text:", decrypted_text)

    # Performance Metrics
    print("\n\n:::::::::::::::::::Performance Metrics of AES Algorithm:::::::::::::::::")
    print("DNA Key Encryption Time:", dna_encryption_time, "seconds")
    print("AES Encryption Time:", aes_encryption_time, "seconds")
    print("AES Decryption Time:", aes_decryption_time, "seconds")

except:
    print("Key size issue")
