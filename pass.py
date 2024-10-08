import re
import random
import string

def check_password_strength(password):
    """
    Check the strength of a password.

    Args:
    password (str): The password to check.

    Returns:
    dict: A dictionary containing the password strength and suggestions.
    """
    strength = 0
    suggestions = []

    # Check if the password is at least 8 characters long
    if len(password) < 8:
        suggestions.append("Password should be at least 8 characters long.")
    else:
        strength += 1

    # Check if the password contains at least one uppercase letter
    if not re.search("[A-Z]", password):
        suggestions.append("Password should contain at least one uppercase letter.")
    else:
        strength += 1

    # Check if the password contains at least one lowercase letter
    if not re.search("[a-z]", password):
        suggestions.append("Password should contain at least one lowercase letter.")
    else:
        strength += 1

    # Check if the password contains at least one digit
    if not re.search("[0-9]", password):
        suggestions.append("Password should contain at least one digit.")
    else:
        strength += 1

    # Check if the password contains at least one special character
    if not re.search("[^A-Za-z0-9]", password):
        suggestions.append("Password should contain at least one special character.")
    else:
        strength += 1

    # Calculate the password strength score
    if strength == 5:
        password_strength = "Strong"
    elif strength >= 3:
        password_strength = "Medium"
    else:
        password_strength = "Weak"

    return {
        "password_strength": password_strength,
        "suggestions": suggestions
    }

def generate_strong_password(length=12):
    """
    Generate a strong password.

    Args:
    length (int): The length of the password. Defaults to 12.

    Returns:
    str: A strong password.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def main():
    password = input("Enter a password: ")
    result = check_password_strength(password)

    print("Password Strength:", result["password_strength"])
    if result["password_strength"] != "Strong":
        print("Suggestions:")
        for suggestion in result["suggestions"]:
            print(suggestion)

    print("\nWould you like to generate a strong password? (yes/no)")
    choice = input().lower()
    if choice == "yes":
        print("Generated Password:", generate_strong_password())

if __name__ == "__main__":
    main()
