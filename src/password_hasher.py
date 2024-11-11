import hashlib

def hash_password(password):
    """
    Hashes the password using SHA-256.

    Parameters:
    password (str): The password to be hashed.

    Returns:
    str: The SHA-256 hashed version of the password.
    """
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()
    
    # Update the hash object with the password encoded in UTF-8
    sha256_hash.update(password.encode('utf-8'))
    
    # Return the hexadecimal representation of the hash
    return sha256_hash.hexdigest()

# Example usage
if __name__ == "__main__":
    # Example password to be hashed
    password = "mySecurePassword123!"
    
    # Generate the hashed password
    hashed_password = hash_password(password)
    
    print(f"Original Password: {password}")
    print(f"Hashed Password (SHA-256): {hashed_password}")
