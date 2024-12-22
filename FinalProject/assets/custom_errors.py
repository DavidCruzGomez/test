class DatabaseError(Exception):
    """
    Exception raised when there is an issue with the user database.

    Attributes:
        message (str): Description of the database error.
                       Default is "An error occurred with the database." (optional).
        suggestion (str): Suggested action to resolve the error.
                          Default is "Check database connectivity and logs." (optional).
    """
    def __init__(self, message: str = "An error occurred with the database.",
                 suggestion: str = "Check database connectivity and logs."):
        self.message = message
        self.suggestion = suggestion
        super().__init__(message)

    def __str__(self):
        return (
            f"DatabaseError: {self.message}\n"
            f" - Suggested action: {self.suggestion}"
        )

class ValidationError(Exception):
    """
    Exception raised for validation errors such as invalid email or existing username.

    Attributes:
        field (str): The name of the field that failed validation.
        value (str): The invalid value provided.
        message (str): Description of the validation error.
                       Default is "Validation failed." (optional).
        suggestion (str): Suggested action to resolve the error.
                          Default is "Check the field value and format." (optional).
    """
    def __init__(self, field: str, value: str, message: str = "Validation failed.",
                 suggestion: str = "Check the field value and format."):
        self.field = field
        self.value = value
        self.message = message
        self.suggestion = suggestion
        super().__init__(message)

    def __str__(self):
        return (
            f"ValidationError: {self.message}\n"
            f" - Field: {self.field}\n"
            f" - Value: {self.value}\n"
            f" - Suggested action: {self.suggestion}"
        )

class WidgetError(Exception):
    """
    Base class for widget-related errors.

    Attributes:
        message (str): Description of the widget error.
                       Default is "An error occurred with the widget." (optional).
    """
    def __init__(self, message: str = "An error occurred with the widget."):
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"WidgetError: {self.message}"

class InputValidationError(WidgetError):
    """
    Exception raised for invalid user input in widgets.

    Attributes:
        input_value (any): The invalid input provided.
        suggestion (str): Suggested action to resolve the error.
                          Default is "Check the input value and format." (optional).
    """
    def __init__(self, input_value: any, message: str = "Invalid input provided in the widget.",
                 suggestion: str = "Check the input value and format."):
        self.input_value = input_value
        self.suggestion = suggestion
        super().__init__(message)

    def __str__(self):
        return (
            f"InputValidationError: {self.message}\n"
            f" - Input value: {self.input_value}\n"
            f" - Suggested action: {self.suggestion}"
        )

class EmailConfigError(Exception):
    """
    Exception raised when there is an issue with the email configuration file.

    Attributes:
        file_path (str): Path to the configuration file.
        message (str): Description of the email configuration error.
                       Default is "Error in the email configuration." (optional).
        suggestion (str): Suggested action to resolve the error.
                          Default is "Verify the configuration file and its format." (optional).
    """
    def __init__(self, file_path: str, message: str = "Error in the email configuration.",
                 suggestion: str = "Verify the configuration file and its format."):
        self.file_path = file_path
        self.message = message
        self.suggestion = suggestion
        super().__init__(message)

    def __str__(self):
        return (
            f"EmailConfigError: {self.message}\n"
            f" - Configuration file: {self.file_path}\n"
            f" - Suggested action: {self.suggestion}"
        )

class UserNotFoundError(Exception):
    """
    Exception raised when a user cannot be found with a given email.

    Attributes:
        email (str): The email address that was not found.
        suggestion (str): Suggested action to resolve the error. Default is
                          "Verify the email address and ensure it is registered." (optional).
    """
    def __init__(self, email: str,
                 suggestion: str = "Verify the email address and ensure it is registered."):
        # Construct the message directly in the initializer.
        self.email = email # Still keep the email for potential logging or further handling.
        self.suggestion = suggestion
        message = f"User not found for email: {email}"
        super().__init__(message) # Pass the message directly to the parent Exception class.

    def __str__(self):
        # Return a string representation that includes the message and the email.
        return (
            "UserNotFoundError: An error occurred while searching for a user.\n"
            " - Suggested action: Verify the email address and ensure it is registered."
        )

class EmailSendingError(Exception):
    """
    Exception raised when an email fails to be sent.

    Attributes:
        email (str): The recipient email address.
        message (str): Description of the email sending error.
                       Default is "Failed to send the email." (optional).
        suggestion (str): Suggested action to resolve the error.
                          Default is "Check the email address and server configuration." (optional).
    """
    def __init__(self, email: str, message: str = "Failed to send the email.",
                 suggestion: str = "Check the email address and server configuration."):
        self.email = email
        self.message = message
        self.suggestion = suggestion
        super().__init__(message)

    def __str__(self):
        return (
            f"EmailSendingError: {self.message}\n"
            f" - Email: {self.email}\n"
            f" - Suggested action: {self.suggestion}"
        )
