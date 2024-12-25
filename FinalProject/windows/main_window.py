# Third-party imports
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QLabel, QSpacerItem, QSizePolicy

# Local project-specific imports
from FinalProject.assets.users_db import get_user_by_username, get_user_by_email, check_password_hash
from FinalProject.assets.utils import show_message
from FinalProject.styles.styles import (
    STYLES, create_title, create_input_field, create_button, style_feedback_label
)
from FinalProject.assets.custom_errors import WidgetError
from FinalProject.windows.dashboard_window import DashboardWindow
from FinalProject.windows.recovery_window import RecoveryWindow
from FinalProject.windows.registration_window import RegistrationWindow


class MainWindow(QMainWindow):
    """
    Represents the main window for the login functionality of the application.

    This window allows users to log in, sign up, or recover their password. It includes:
    - Input fields for username/email and password
    - Buttons for login and registration
    - A feedback label for displaying success/error messages
    - Links to open registration and password recovery windows
    """
    def __init__(self) -> None:
        """
        Initializes the main window with required widgets, layout, and event handlers.

        This method sets up the user interface elements like:
        - Title label
        - Input fields for username/email and password
        - Login and sign-up buttons
        - A feedback label for showing status messages
        - A password recovery link
        """
        super().__init__()

        # References to other windows (Dashboard, Registration, Recovery)
        self._dashboard_window = None
        self._registration_window = None
        self._recovery_window = None

        # Set the main window's properties (title and dimensions)
        self.setWindowTitle("Final project David Cruz Gómez")
        self.setGeometry(100, 100, 800, 600) # Window position and size (x, y, width, height)

        # Create the main layout for the window
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter) # Center-align all widgets
        layout.setSpacing(20) # Add space between widgets for better UI clarity

        # Add a spacer item for vertical spacing at the top
        layout.addSpacerItem(
            QSpacerItem(20, 60, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

        # Create and add the title label using the 'create_title' helper function
        self._title_label = create_title("Impulse Buying Factors on TikTok Shop")
        layout.addWidget(self._title_label)

        # Create and add the username/email input field
        self._username_input = create_input_field("Username or email")
        layout.addWidget(self._username_input)

        # Create and add the password input field
        self._password_input = create_input_field("Password", is_password=True)
        layout.addWidget(self._password_input)

        # Create and add the "Login" and "Sign up" buttons
        self._login_button = create_button("Login", self._on_login)
        self._signup_button = create_button("Sign up", self._open_registration_window)
        layout.addWidget(self._login_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._signup_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Add a feedback label for displaying messages to the user (e.g., success or errors)
        self._feedback_label = QLabel("") # Initially empty
        self._feedback_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._feedback_label)

        # Password recovery link
        self._recover_password_label = QLabel('<a href="#">Forgot your password?</a>')
        self._recover_password_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._recover_password_label.setStyleSheet(STYLES["password_recovery_link"])
        self._recover_password_label.linkActivated.connect(self._open_recovery_window)
        layout.addWidget(self._recover_password_label)

        # Add another spacer item for vertical spacing at the bottom
        layout.addSpacerItem(
            QSpacerItem(20, 60, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

        # Create and set the central widget and its layout
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Apply the main window's custom stylesheet
        self.setStyleSheet(STYLES["main_window"])


    def _on_login(self) -> None:
        """
        Handles the login process by verifying the user's credentials and providing feedback.

        If the credentials are valid, it opens the dashboard window. If there is any issue,
        it displays the appropriate error message.

        Raises:
            WidgetError: If there is an error retrieving user data or verifying credentials.
        """
        try:
            # Get user inputs (username/email and password)
            username_or_email = self._username_input.text()
            password = self._password_input.text()

            print(f"🔑 [INFO] Attempting to log in with Username/Email: '{username_or_email}' "
                  f"and Password: '[PROTECTED]'")

            if not self._are_credentials_valid(username_or_email, password):
                print("❌ [ERROR] Invalid credentials provided. Username/Email and "
                      "password cannot be empty.")
                return

            # Try to retrieve the user by their username or email
            try:
                user = get_user_by_username(username_or_email)
            except Exception as gen_err:
                print(f"❌ [ERROR] Failed to fetch user by username: {gen_err}")
                user = None

            if not user:
                try:
                    user = get_user_by_email(username_or_email)
                except Exception as gen_err:
                    print(f"❌ [ERROR] Failed to fetch user by email: {gen_err}")
                    user = None

            # Print the result of the user retrieval to check the structure
            print(f"🔍 [DEBUG] Retrieved user: {user}")

            # If the user exists, verify the password hash
            if user and check_password_hash(user["password_hash"], password):
                self._login_successful()
            else:
                self._handle_login_error(user)

        except Exception as gen_err:
            print(f"❌ [ERROR] An unexpected error occurred during login: {gen_err}")
            style_feedback_label(
                self._feedback_label,
                "An unexpected error occurred. Please try again later.",
                "error"
            )
            raise WidgetError("An unexpected error occurred. Please try again later.") from gen_err


    def _are_credentials_valid(self, username: str, password: str) -> bool:
        """
        Validates the username and password input fields.

        Args:
            username (str): The username or email entered by the user.
            password (str): The password entered by the user.

        Returns:
            bool: True if both fields are valid (non-empty), False otherwise.
        """
        if not username:
            style_feedback_label(self._feedback_label, "Username cannot be empty.", "error")
            print("⚠️ [WARNING] Username is empty.")
            return False

        if not password:
            style_feedback_label(self._feedback_label, "Password cannot be empty.", "error")
            print("⚠️ [WARNING] Password is empty.")
            return False

        return True


    def _login_successful(self) -> None:
        """
        Executes actions after a successful login:
        - Displays a success message.
        - Opens the dashboard window.
        - Closes the login window.

        Raises:
            WidgetError: If there is an issue opening the dashboard window.
        """
        show_message(self, "Success", "Login successful!")
        print("✅ [SUCCESS] 🎉 Login successful. Opening the dashboard window.")

        try:
            # Check if the object does not have the attribute '_dashboard_window',
            # or if the attribute exists but its value is falsy
            if not hasattr(self, '_dashboard_window') or not self._dashboard_window:
                self.dashboard_window = DashboardWindow()

            self._dashboard_window.show()
            self.close()

        except Exception as gen_err:
            print(f"❌ [ERROR] Failed to open dashboard window: {gen_err}")
            style_feedback_label(
                self._feedback_label,
                "Failed to open dashboard window. Please try again later.",
                "error"
            )
            raise WidgetError(
                "Failed to open dashboard window. Please try again later.") from gen_err


    def _handle_login_error(self, user) -> None:
        """
        Handles login errors, providing feedback based on whether the user was found or not.

        Args:
            user (dict or None): The user data retrieved from the database, or None if not found.
        """
        if not user:
            style_feedback_label(self._feedback_label, "User not found. Please try again.", "error")

        else:
            style_feedback_label(self._feedback_label, "Incorrect password. Please try again.", "error")


    def _open_registration_window(self) -> None:
        """
        Opens the registration window for users to create a new account.

        Raises:
            WidgetError: If there is an issue opening the registration window.
        """
        try:
            print("🔑 [INFO] Opening user registration window.")
            # Check if the object does not have the attribute '_registration_window',
            # or if the attribute exists but its value is falsy
            if not hasattr(self, '_registration_window') or not self._registration_window:
                self._registration_window = RegistrationWindow()
            self._registration_window.show() # Show the registration window

        except Exception as gen_err:
            print(f"❌ [ERROR] Failed to open registration window: {gen_err}")
            style_feedback_label(
                self._feedback_label,
                "Failed to open registration window. Please try again later.",
                "error"
            )
            raise WidgetError(
                "An error occurred while opening the registration window.") from gen_err


    def _open_recovery_window(self) -> None:
        """
        Opens the password recovery window for users who have forgotten their password.

        Raises:
            WidgetError: If there is an issue opening the recovery window.
        """
        try:
            print("🔑 [INFO] Opening user recovery window.")
            # Check if the object does not have the attribute '_recovery_window',
            # or if the attribute exists but its value is falsy
            if not hasattr(self, '_recovery_window') or not self._recovery_window:
                self._recovery_window = RecoveryWindow()
            self._recovery_window.show()

        except Exception as gen_err:
            print(f"❌ [ERROR] Failed to open recovery window: {gen_err}")
            style_feedback_label(
                self._feedback_label,
                "Failed to open recovery window. Please try again later.",
                "error"
            )
            raise WidgetError(
                "An error occurred while opening the registration window.") from gen_err
        