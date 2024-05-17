from Bio.Seq import Seq
from Crypto.Random import get_random_bytes

# Function to convert binary to DNA format
def binary_to_dna(binary_str):
    """
    Converts a binary string to DNA sequence.

    Parameters:
    binary_str (str): The binary string to be converted.

    Returns:
    str: The DNA sequence.
    """
    # Dictionary mapping binary digits to DNA nucleotides
    dna_mapping = {'00': 'A', '01': 'T', '10': 'G', '11': 'C'}
    
    # Pad the binary string with '0' if its length is odd
    if len(binary_str) % 2 != 0:
        binary_str += '0'
    
    # Convert binary digits to DNA nucleotides using the mapping
    dna_seq = ''.join([dna_mapping[binary_str[i:i+2]] for i in range(0, len(binary_str), 2)])
    
    return dna_seq


# Function to perform DNA encryption
def dna_encrypt(key):
    """
    Performs DNA encryption on the given key.

    Parameters:
    key (str): The key to be encrypted.

    Returns:
    str: The encrypted DNA sequence.
    """
    # Convert the key to binary representation
    binary_representation = bin(int.from_bytes(key.encode(), 'big'))[2:]
    
    # Convert the binary representation to DNA sequence
    dna_seq = binary_to_dna(binary_representation)

    # Reverse complement the DNA sequence using Biopython's Seq object
    encrypted_dna_seq = str(Seq(dna_seq).reverse_complement())
    
    return encrypted_dna_seq
