# Third-party imports
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QWidget, QLabel, QSpacerItem, QSizePolicy

# Local project-specific imports
from FinalProject.assets.users_db import get_user_by_username,get_user_by_email, check_password_hash
from FinalProject.assets.utils import show_message
from FinalProject.styles.styles import (
    STYLES, create_title, create_input_field, create_button, style_feedback_label
)
from .dashboard_window import DashboardWindow
from .recovery_window import RecoveryWindow
from .registration_window import RegistrationWindow


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
        self.dashboard_window = None
        self.registration_window = None
        self.recovery_window = None

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
        self.title_label = create_title("Impulse Buying Factors on TikTok Shop")
        layout.addWidget(self.title_label)

        # Create and add the username/email input field
        self.username_input = create_input_field("Username or email")
        layout.addWidget(self.username_input)

        # Create and add the password input field
        self.password_input = create_input_field("Password", is_password=True)
        layout.addWidget(self.password_input)

        # Create and add the "Login" and "Sign up" buttons
        self.login_button = create_button("Login", self.on_login)
        self.signup_button = create_button("Sign up", self.open_registration_window)
        layout.addWidget(self.login_button, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.signup_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Add a feedback label for displaying messages to the user (e.g., success or errors)
        self.feedback_label = QLabel("") # Initially empty
        self.feedback_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.feedback_label)

        # Password recovery link
        self.recover_password_label = QLabel('<a href="#">Forgot your password?</a>')
        self.recover_password_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.recover_password_label.setStyleSheet(STYLES["password_recovery_link"])
        self.recover_password_label.linkActivated.connect(self.open_recovery_window) # Link click handler
        layout.addWidget(self.recover_password_label)

        # Add another spacer item for vertical spacing at the bottom
        layout.addSpacerItem(
            QSpacerItem(20, 60, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

        # Create the central widget, set its layout, and set it as the central widget for the main window
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

        # Apply the main window's custom stylesheet
        self.setStyleSheet(STYLES["main_window"])


    def on_login(self) -> None:
        """
        Handles the login process by verifying the user's credentials and providing feedback.

        If the credentials are valid, it opens the dashboard window. If there is any issue,
        it displays the appropriate error message.

        Raises:
            WidgetError: If there is an error retrieving user data or verifying credentials.
        """
        try:
            # Get user inputs (username/email and password)
            username_or_email = self.username_input.text()
            password = self.password_input.text()

            print(f"🔑 [INFO] Attempting to log in with Username/Email: '{username_or_email}' "
                  f"and Password: '[PROTECTED]'")

            if not self.are_credentials_valid(username_or_email, password):
                print("❌ [ERROR] Invalid credentials provided. Username/Email and "
                      "password cannot be empty.")
                return

            # Try to retrieve the user by their username or email
            try:
                user = get_user_by_username(username_or_email)
            except Exception as e:
                print(f"❌ [ERROR] Failed to fetch user by username: {e}")
                user = None

            if not user:
                try:
                    user = get_user_by_email(username_or_email)
                except Exception as e:
                    print(f"❌ [ERROR] Failed to fetch user by email: {e}")
                    user = None

                # Print the result of the user retrieval to check the structure
            print(f"🔍 [DEBUG] Retrieved user: {user}")

            # If the user exists, verify the password hash
            if user and check_password_hash(user["password_hash"], password):
                self.login_successful()
            else:
                self.handle_login_error(user)

        except Exception as e:
            print(f"❌ [ERROR] An unexpected error occurred during login: {e}")
            style_feedback_label(
                self.feedback_label,
                "An unexpected error occurred. Please try again later.",
                "error"
            )

    def are_credentials_valid(self, username: str, password: str) -> bool:
        """
        Validates the username and password input fields.

        Args:
            username (str): The username or email entered by the user.
            password (str): The password entered by the user.

        Returns:
            bool: True if both fields are valid (non-empty), False otherwise.
        """
        if not username:
            style_feedback_label(self.feedback_label, "Username cannot be empty.", "error")
            print("⚠️ [WARNING] Username is empty.")
            return False
        if not password:
            style_feedback_label(self.feedback_label, "Password cannot be empty.", "error")
            print("⚠️ [WARNING] Password is empty.")
            return False
        return True

    def login_successful(self) -> None:
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
            if not self.dashboard_window:
                self.dashboard_window = DashboardWindow()
            self.dashboard_window.show()
            self.close()

        except Exception as e:
            print(f"❌ [ERROR] Failed to open dashboard window: {e}")
            style_feedback_label(
                self.feedback_label,
                "Failed to open dashboard window. Please try again later.",
                "error"
            )
    def handle_login_error(self, user) -> None:
        """
        Handles login errors, providing feedback based on whether the user was found or not.

        Args:
            user (dict or None): The user data retrieved from the database, or None if not found.
        """
        if not user:
            style_feedback_label(self.feedback_label, "User not found. Please try again.", "error")
        else:
            style_feedback_label(self.feedback_label, "Incorrect password. Please try again.", "error")


    def open_registration_window(self) -> None:
        """
        Opens the registration window for users to create a new account.

        Raises:
            WidgetError: If there is an issue opening the registration window.
        """
        try:
            print("🔑 [INFO] Opening user registration window.")
            if not self.registration_window:
                self.registration_window = RegistrationWindow()
            self.registration_window.show() # Show the registration window
        except Exception as e:
            print(f"❌ [ERROR] Failed to open registration window: {e}")
            style_feedback_label(
                self.feedback_label,
                "Failed to open registration window. Please try again later.",
                "error"
            )

    def open_recovery_window(self) -> None:
        """
        Opens the password recovery window for users who have forgotten their password.

        Raises:
            WidgetError: If there is an issue opening the recovery window.
        """
        try:
            print("🔑 [INFO] Opening user recovery window.")
            if not self.recovery_window:
                self.recovery_window = RecoveryWindow()
            self.recovery_window.show()
        except Exception as e:
            print(f"❌ [ERROR] Failed to open recovery window: {e}")
            style_feedback_label(
                self.feedback_label,
                "Failed to open recovery window. Please try again later.",
                "error"
            )
