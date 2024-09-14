# my-third-project-
import re

def password_complexity(password):
    # Define the complexity rules
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[ !@#$%^&*()_+=-]", password) is None
    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

    # Create a dictionary of errors for better feedback
    complexity_report = {
        'Password is at least 8 characters': not length_error,
        'Contains at least one digit': not digit_error,
        'Contains at least one uppercase letter': not uppercase_error,
        'Contains at least one lowercase letter': not lowercase_error,
        'Contains at least one special symbol (e.g. @, #, $, etc.)': not symbol_error,
    }

    return password_ok, complexity_report

# Test the function
password = input("Enter a password to check: ")
is_valid, report = password_complexity(password)

if is_valid:
    print("Password is strong!")
else:
    print("Password is weak!")
    print("Here’s why:")
    for rule, passed in report.items():
        if not passed:
            print(f" - {rule}")
