import secrets
import string

def generate_password(length=12):
    """
    Generates a random password with a combination of uppercase letters, 
    lowercase letters, digits, and special characters.

    Parameters:
    length (int): Length of the generated password. Default is 12 characters.

    Returns:
    str: A randomly generated password.
    """
    # Define the character sets for the password
    all_characters = string.ascii_letters + string.digits + string.punctuation
    
    # Use 'secrets' module for cryptographically secure password generation
    password = ''.join(secrets.choice(all_characters) for _ in range(length))
    
    return password

# Example usage
if __name__ == "__main__":
    # Generate a random password of length 12
    password = generate_password(12)
    print(f"Generated Password: {password}")
