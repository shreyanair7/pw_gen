import string

def check_strength(password):
    """
    Checks the strength of the password based on its length and character diversity.

    Parameters:
    password (str): The password to check.

    Returns:
    str: The strength of the password ("Very Weak", "Weak", "Moderate", "Strong").
    """
    # Password strength criteria
    length_score = len(password) >= 12  # Password must be at least 12 characters long
    has_upper = any(c.isupper() for c in password)  # Contains at least one uppercase letter
    has_lower = any(c.islower() for c in password)  # Contains at least one lowercase letter
    has_digit = any(c.isdigit() for c in password)  # Contains at least one digit
    has_special = any(c in string.punctuation for c in password)  # Contains at least one special character

    # Score based on conditions
    score = sum([length_score, has_upper, has_lower, has_digit, has_special])

    # Determine the password strength
    if score == 5:
        return "Strong"
    elif score == 4:
        return "Moderate"
    elif score == 3:
        return "Weak"
    else:
        return "Very Weak"

# Example usage
if __name__ == "__main__":
    # Test cases for password strength
    passwords = [
        "1234",  # Very Weak
        "password123",  # Weak
        "Password123!",  # Moderate
        "StrongPassword123!"  # Strong
    ]

    for pwd in passwords:
        strength = check_strength(pwd)
        print(f"Password: {pwd} | Strength: {strength}")
