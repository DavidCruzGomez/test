EMAIL_REGEX = (
    r"^"                        # Start of the string
    r"[a-zA-Z0-9._%+-]+"        # Username part (allowed alphanumeric and special characters)
    r"@"                        # The "@" symbol is mandatory
    r"[a-zA-Z0-9-]+"            # Domain (must have at least one alphanumeric character or hyphen)
    r"(\.[a-zA-Z0-9-]+)*"       # There can be additional subdomains (letters, numbers, and hyphens are allowed)
    r"\."                       # A literal dot (.) separating the domain from the extension
    r"[a-zA-Z]{2,}$"            # Domain extension (must be at least 2 letters)
)

PASSWORD_REGEX = {
    'upper': r'[A-Z]',               # At least one uppercase letter
    'lower': r'[a-z]',               # At least one lowercase letter
    'number': r'\d',                 # At least one number
    'special': r'[@$!%*?&]',         # At least one special character
    'length': r'^.{8,16}$',          # Length between 8 and 16 characters
    'all': (
        r"^(?=.*[a-z])"              # At least one lowercase letter
        r"(?=.*[A-Z])"               # At least one uppercase letter
        r"(?=.*\d)"                  # At least one number
        r"(?=.*[@$!%*?&])"           # At least one special character from the allowed set
        r"[A-Za-z\d@$!%*?&]{8,16}$"  # Only letters, numbers, and allowed special characters, with a length between 8 and 16 characters
    )
}

USERNAME_REGEX = {
    'length': r'.{3,18}',                   # Length between 3 and 18 characters
    'valid_chars': r'^[A-Za-z0-9._-]+$',    # Only alphanumeric characters, dots, hyphens, and underscores
    'start_alnum': r'^[A-Za-z0-9]',         # Starts with alphanumeric
    'end_alnum': r'[A-Za-z0-9]$',           # Ends with alphanumeric
    'all': (
        r"^[A-Za-z0-9]"              # Start with an alphanumeric character
        r"[A-Za-z0-9._-]{1,18}"      # Allows alphanumeric, dot, dash, and underscore (1 to 18 characters)
        r"[A-Za-z0-9]$"              # End with an alphanumeric character
    )
}
