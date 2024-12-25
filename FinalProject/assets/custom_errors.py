class DatabaseError(Exception):
    """
    Exception raised when there is an issue with the user database.

    Attributes:
        _suggestion (str): Suggested action to resolve the error.
                           Default is "Check database connectivity and logs." (optional).
    """
    def __init__(self, message: str = "An error occurred with the database.",
                 suggestion: str = "Check database connectivity and logs."):
        self._suggestion = suggestion
        Exception.__init__(self, message)

    def __str__(self):
        return (
            f"DatabaseError: {super().__str__()}\n"
            f" - Suggested action: {self._suggestion}"
        )

class ValidationError(Exception):
    """
    Exception raised for validation errors such as invalid email or existing username.

    Attributes:
        _field (str): The name of the field that failed validation.
        _value (str): The invalid value provided.
        _suggestion (str): Suggested action to resolve the error.
                           Default is "Check the field value and format." (optional).
    """
    def __init__(self, field: str, value: str, message: str = "Validation failed.",
                 suggestion: str = "Check the field value and format."):
        self._field = field
        self._value = value
        self._suggestion = suggestion
        Exception.__init__(self, message)

    def __str__(self):
        return (
            f"ValidationError: {super().__str__()}\n"
            f" - Field: {self._field}\n"
            f" - Value: {self._value}\n"
            f" - Suggested action: {self._suggestion}"
        )

class WidgetError(Exception):
    """
    Base class for widget-related errors.
    """
    def __init__(self, message: str = "An error occurred with the widget."):
        Exception.__init__(self, message)

    def __str__(self):
        return f"WidgetError: {super().__str__()}"

class InputValidationError(WidgetError):
    """
    Exception raised for invalid user input in widgets.

    Attributes:
        _input_value (any): The invalid input provided.
        _suggestion (str): Suggested action to resolve the error.
                           Default is "Check the input value and format." (optional).
    """
    def __init__(self, input_value: any, message: str = "Invalid input provided in the widget.",
                 suggestion: str = "Check the input value and format."):
        self._input_value = input_value
        self._suggestion = suggestion
        WidgetError.__init__(self, message)

    def __str__(self):
        return (
            f"InputValidationError: {super().__str__()}\n"
            f" - Input value: {self._input_value}\n"
            f" - Suggested action: {self._suggestion}"
        )

class EmailConfigError(Exception):
    """
    Exception raised when there is an issue with the email configuration file.

    Attributes:
        _file_path (str): Path to the configuration file.
        _suggestion (str): Suggested action to resolve the error.
                           Default is "Verify the configuration file and its format." (optional).
    """
    def __init__(self, file_path: str, message: str = "Error in the email configuration.",
                 suggestion: str = "Verify the configuration file and its format."):
        self._file_path = file_path
        self._suggestion = suggestion
        Exception.__init__(self, message)

    def __str__(self):
        return (
            f"EmailConfigError: {super().__str__()}\n"
            f" - Configuration file: {self._file_path}\n"
            f" - Suggested action: {self._suggestion}"
        )

class UserNotFoundError(Exception):
    """
    Exception raised when a user cannot be found with a given email.

    Attributes:
        _email (str): The email address that was not found.
        _suggestion (str): Suggested action to resolve the error. Default is
                           "Verify the email address and ensure it is registered." (optional).
    """
    def __init__(self, email: str,
                 suggestion: str = "Verify the email address and ensure it is registered."):
        # Construct the message directly in the initializer.
        self._email = email # Still keep the email for potential logging or further handling.
        self._suggestion = suggestion
        message = f"User not found for email: {email}"
        Exception.__init__(self, message)

    def __str__(self):
        # Return a string representation that includes the message and the email.
        return (
            f"UserNotFoundError: {super().__str__()}\n"
            f" - Suggested action: {self._suggestion}"
        )

class EmailSendingError(Exception):
    """
    Exception raised when an email fails to be sent.

    Attributes:
        _email (str): The recipient email address.
        _suggestion (str): Suggested action to resolve the error.
                           Default is "Check the email address and server configuration." (optional).
    """
    def __init__(self, email: str, message: str = "Failed to send the email.",
                 suggestion: str = "Check the email address and server configuration."):
        self._email = email
        self._suggestion = suggestion
        Exception.__init__(self, message)

    def __str__(self):
        return (
            f"EmailSendingError: {super().__str__()}\n"
            f" - Email: {self._email}\n"
            f" - Suggested action: {self._suggestion}"
        )
