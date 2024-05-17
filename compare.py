from Crypto.Cipher import AES
from Bio.Seq import Seq
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import ipfshttpclient
import os
import binascii
import timeit
import matplotlib.pyplot as plt

# Function to convert binary to DNA format
def binary_to_dna(binary_str):
    dna_mapping = {'00': 'A', '01': 'T', '10': 'G', '11': 'C'}
    
    # Pad the binary string with '0' if its length is odd
    if len(binary_str) % 2 != 0:
        binary_str += '0'
    
    dna_seq = ''.join([dna_mapping[binary_str[i:i+2]] for i in range(0, len(binary_str), 2)])
    return dna_seq

# Function to perform DNA encryption
def dna_encrypt(key):
    binary_representation = bin(int.from_bytes(key.encode(), 'big'))[2:]
    dna_seq = binary_to_dna(binary_representation)
    return str(Seq(dna_seq).reverse_complement())

# Function to perform AES encryption with padding
def aes_encrypt(key, plaintext):
    # Pad the plaintext to meet the block size requirement
    block_size = 16  # AES block size is 16 bytes
    padding = block_size - (len(plaintext) % block_size)
    
    plaintext = plaintext.encode() + bytes([padding] * padding)

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


# Function to perform decryption
def decrypt_aes(key, encrypted_text):
 
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
plaintext = "Binary neural networks are particularly useful in scenarios where resource constraints are a concern, such as in edge computing or IoT devices. However, they may suffer from reduced representational capacity compared to their full-precision counterparts."
normal_key = "my_key"

# Step 1: DNA Encryption
dna_encrypted_key, dna_encryption_time = measure_performance(dna_encrypt, normal_key)
print("\nDna encrypted key:", dna_encrypted_key)

# Step 2: AES Encryption with DNA-encrypted key
aes_key = dna_encrypted_key.encode()

encrypted_text_aes, aes_encryption_time = measure_performance(aes_encrypt, aes_key, plaintext)


# Decryption for AES
decrypted_text_aes, aes_decryption_time = measure_performance(decrypt_aes, aes_key, encrypted_text_aes)
print("\nDecrypted Text (AES):", decrypted_text_aes)


# Calculate encryption throughput (bytes per second)
encryption_throughput = len(plaintext) / aes_encryption_time

# Calculate decryption throughput (bytes per second)
decryption_throughput = len(decrypted_text_aes.encode()) / aes_decryption_time

print("\nAES Encryption Throughput:", encryption_throughput, "bytes/sec")
print("AES Decryption Throughput:", decryption_throughput, "bytes/sec")

# Plotting the comparison graph
algorithms = ['AES Encryption', 'AES Decryption']
execution_times = [aes_encryption_time, aes_decryption_time]

plt.bar(algorithms, execution_times, color=['blue', 'green'])
plt.ylabel('Execution Time (seconds)')
plt.title('AES Performance')
plt.show()


# Plotting the comparison graph
algorithms = ['AES Encryption', 'AES Decryption']
throughputs = [encryption_throughput, decryption_throughput]

plt.bar(algorithms, throughputs, color=['blue', 'green'])
plt.ylabel('Throughput (bytes/sec)')
plt.title('AES Throughput')
plt.show()
