def apply_dp(plaintext):
    """
    Applies a XOR encryption to the plaintext.

    Parameters:
    plaintext (str): The plaintext to be encrypted.

    Returns:
    str: The encrypted text.
    """
    # Create an empty string to store the encrypted text
    encrypted_text = ""

    # Iterate over each character in the plaintext
    for char in plaintext:
        # Convert the character to its ASCII value and perform XOR operation with 0xFF (255)
        encrypted_char = chr(ord(char) ^ 0xFF)
        # Append the encrypted character to the encrypted_text string
        encrypted_text += encrypted_char

    # Return the encrypted text
    return encrypted_text


# Function to embed secret data using steganography
def embed_secret_data(encrypted_text, secret_data):
    """
    Embeds secret data into the encrypted text using steganography.

    Parameters:
    encrypted_text (bytes): The encrypted text.
    secret_data (str): The secret data to be embedded.

    Returns:
    bytes: The stego text containing the encrypted text and embedded secret data.
    """
    # Encode the secret data to bytes
    secret_data_bytes = secret_data.encode()
    
    # Append the secret data bytes to the encrypted text
    stego_text = encrypted_text + secret_data_bytes
    
    return stego_text



def reverse_obfuscation(obfuscated_text):
    """
    Reverses the obfuscation applied to the text.

    Parameters:
    obfuscated_text (str): The obfuscated text.

    Returns:
    str: The original text after reversing obfuscation.
    """
    # Create an empty string to store the original text
    original_text = ""
    
    # Iterate over each character in the obfuscated text
    for char in obfuscated_text:
        # Perform XOR operation with 0xFF (255) to reverse the obfuscation
        original_char = chr(ord(char) ^ 0xFF)
        # Append the original character to the original_text string
        original_text += original_char
    
    return original_text



# Function to extract secret data using steganography
def extract_secret_data(stego_text, encrypted_text_length):
    """
    Extracts secret data from steganographic text.

    Parameters:
    stego_text (bytes): The steganographic text containing encrypted text and embedded secret data.
    encrypted_text_length (int): The length of the encrypted text.

    Returns:
    str: The extracted secret data.
    """
    # Extract the secret data from the steganographic text
    secret_data = stego_text[encrypted_text_length:]
    
    # Decode the secret data from bytes to string
    secret_data_str = secret_data.decode()
    
    return secret_data_str
