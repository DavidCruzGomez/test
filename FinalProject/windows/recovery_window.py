# Standard library imports
import json
import os
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Third-party imports
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QPushButton

# Local project-specific imports
from FinalProject.styles.styles import STYLES
from FinalProject.assets.utils import show_message
from FinalProject.assets.regex import EMAIL_REGEX
from FinalProject.assets.custom_errors import (
    DatabaseError, EmailConfigError, EmailSendingError, UserNotFoundError
)


# Path to the user database and email configuration file
DB_FILE = os.path.join(os.getcwd(), "assets", "users_db.json")
EMAIL_CONFIG_FILE = os.path.join(os.getcwd(), "assets", "email_config.json")


def load_config() -> dict:
    """
    Loads email configuration settings from a JSON file.

    Returns:
        dict: A dictionary containing the email configuration settings, including
              `sender_email` and `sender_password`.

    Raises:
        EmailConfigError: If the configuration file is missing, invalid, or incomplete.
    """
    if os.path.exists(EMAIL_CONFIG_FILE):
        try:
            with open(EMAIL_CONFIG_FILE, "r") as email_config_file:
                config = json.load(email_config_file)

                # Check if 'sender_email' and 'sender_password' are in the config
                sender_email = config.get("sender_email")
                sender_password = config.get("sender_password")

                if not sender_email or not sender_password:
                    raise EmailConfigError("Missing email or password in the configuration file.")

                print("ℹ️ [INFO] Email config file loaded successfully.")
                return config  # Return the config if both fields are present

        except json.JSONDecodeError as e:
            print(f"❌ [ERROR] Error decoding email config file: {e}")
            show_message(None, "Configuration Error", f"Failed to decode email config: {e}")
            raise EmailConfigError(f"Failed to decode email config: {e}")

    else:
        print(f"❌ [ERROR] Email config file not found at {EMAIL_CONFIG_FILE}")
        show_message(None, "Configuration Error", f"Config file not found at {EMAIL_CONFIG_FILE}")
        raise EmailConfigError(f"Config file not found at {EMAIL_CONFIG_FILE}")

    return {}

class EmailSender:
    """
    A class responsible for sending password recovery emails.

    This class manages the creation and sending of emails with password recovery information,
    including handling the connection to the SMTP server and email formatting.

    Attributes:
        smtp_server (str): The address of the SMTP server.
        smtp_port (int): The port used by the SMTP server.
        sender_email (str): The email address used to send recovery emails.
        sender_password (str): The password associated with the sender's email address.
    """
    def __init__(
            self, smtp_server: str, smtp_port: int,
            sender_email: str, sender_password: str
    ) -> None:
        """
        Initializes the EmailSender instance with necessary SMTP details.

        Args:
            smtp_server (str): The SMTP server address.
            smtp_port (int): The SMTP server port.
            sender_email (str): The email address to send recovery emails from.
            sender_password (str): The password of the sender's email address.
        """
        print(
            f"🔄 [INFO] Initializing EmailSender with SMTP server {smtp_server} "
            f"and port {smtp_port}."
        )
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password

    def send_recovery_email(self, recipient_email: str, username: str) -> None:
        """
        Sends a password recovery email to the specified recipient.

        Args:
            recipient_email (str): The email address of the user requesting password recovery.
            username (str): The username of the user requesting recovery.

        Raises:
            EmailSendingError: If an error occurs while sending the email.
        """
        # Email subject and body content
        subject = "Password Recovery"
        body = f"Hello {username},\n\nWe received a request to recover your password.\n" \
               f"Your password is: ['password_hash']\n\n" \
               "If you did not request this, please ignore this message."

        # Create the email message with the sender, recipient, subject, and body
        msg = MIMEMultipart()
        msg["From"] = self.sender_email
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        print(
            f"⏳ [INFO] Preparing to send recovery email to {recipient_email} "
            f"for the user '{username}'."
        )

        try:
            # Connect to the SMTP server and send the email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()  # Secure connection using TLS
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, recipient_email, msg.as_string())
            print(f"✅ [SUCCESS] Recovery email successfully sent to {recipient_email}.")

        except smtplib.SMTPAuthenticationError:
            print("❌ [ERROR] Authentication error, check the email server credentials.")
            raise EmailSendingError("Authentication error: Unable to authenticate with SMTP server.")

        except smtplib.SMTPConnectError:
            print("❌ [ERROR] Unable to connect to SMTP server.")
            raise EmailSendingError("Connection error: Could not connect to SMTP server.")

        except Exception as e:
            print(f"❌ [ERROR] Failed to send email: {e}")
            raise EmailSendingError(f"Failed to send the recovery email: {e}")

class RecoveryWindow(QWidget):
    """
    A window for password recovery via email.

    This class defines the user interface and functionality for users to recover their passwords
    by entering their email. It checks if the email is valid, finds the corresponding user,
    and sends a recovery email with their password (hashed) to the provided email address.

    Attributes:
        email_sender (EmailSender): An instance of the EmailSender class for sending recovery emails.
    """
    def __init__(self) -> None:
        """
        Initializes the RecoveryWindow instance.

        Sets up the UI elements, validates email configuration, and initializes the
        EmailSender with SMTP details from the configuration file.
        """
        super().__init__()

        # Set the window's title and initial geometry
        self.setWindowTitle("Password Recovery")
        self.setGeometry(100, 100, 400, 300)

        # Create the layout and widgets for the recovery window
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)  # Center-align all widgets
        layout.setSpacing(20)  # Add spacing between widgets

        # Create and configure the email input field
        self.email_input = QLineEdit()
        self.email_input.setStyleSheet(STYLES["text_field"])  # Apply custom styling
        self.email_input.setPlaceholderText("Enter your email")

        # Create and configure the "Send Recovery Email" button
        self.recover_button = QPushButton("Send Recovery Email")
        self.recover_button.setStyleSheet(STYLES["button"])
        self.recover_button.clicked.connect(self.recover_password) # Connect button click to method

        # Add input field and button to the layout
        layout.addWidget(self.email_input)
        layout.addWidget(self.recover_button)

        # Set the layout for the window
        self.setLayout(layout)

        try:
            # Load email configuration from the config file
            config = load_config()
            sender_email = config.get("sender_email")
            sender_password = config.get("sender_password")

            if not sender_email or not sender_password:
                print("❌ [ERROR] Missing email or password in the configuration file.")
                show_message(
                    self, "Configuration Error",
                    "Missing email or password in configuration file."
                )
                raise EmailConfigError("Missing email or password in configuration file.")

            print("ℹ️ [INFO] Email configuration loaded successfully.")

            # Initialize the EmailSender with necessary SMTP details
            self.email_sender = EmailSender(
                smtp_server="smtp.gmail.com",
                smtp_port=587,
                sender_email=sender_email,
                sender_password=sender_password
            )

        except EmailConfigError as e:
            show_message(self, "Configuration Error", str(e))
            print(f"❌ [ERROR] {e}")
            raise e

    def recover_password(self) -> None:
        """
        Triggers the password recovery process by sending an email.

        This method retrieves the email entered by the user, validates the email address,
        checks if the user exists in the system, and if so, sends them a recovery email.
        If the email is not found, the user is notified and the input field is cleared.
        """
        email = self.email_input.text() # Get the email entered by the user

        # Check if the email is valid
        user = self.find_user_by_email(email)
        if user:
            print(f"🔄 [INFO] Sending recovery email to {email}...")
            try:
                # Send the recovery email
                self.email_sender.send_recovery_email(email, user)
                show_message(self, "Success", "A recovery email has been sent.")
                self.close() # Close the recovery window after sending the email
                print("📝 [INFO] Recovery window closed.")
            except Exception as e:
                show_message(self, "Error", str(e))
                print(f"❌ [ERROR] Failed to send recovery email: {e}")
        else:
            # If email not found, notify the user and clear the email input
            print(f"❌ [ERROR] No user found with email {email}.")
            show_message(self, "Error", "Email not found. Please try again.")
            self.email_input.clear()

    @staticmethod
    def find_user_by_email(email: str) -> str | None:
        """
        Finds a user by their email.

        Searches through the user database for the provided email address. If found,
        returns the username associated with the email. Otherwise, returns None.

        Args:
            email (str): The email address to search for.

        Returns:
            str or None: The username if found, otherwise None.

        Raises:
            UserNotFoundError: If no user is found with the given email address.
        """
        email = email.strip().lower()
        users_db = RecoveryWindow.load_users_db() # Load the user database
        for username, details in users_db.items():
            if details.get("email").strip().lower() == email:
                print(f"🔍 [INFO] User '{username}' found with email {email}.")
                return username # Return the username associated with the email
        print(f"❌ [ERROR] No user found with email {email}.")
        raise UserNotFoundError(email)

    @staticmethod
    def validate_users_db(users_db: dict) -> bool:
        """
        Validates the structure of the user's database.

        Args:
            users_db (dict): The user's database.

        Returns:
            bool: `True` if the database is valid, `False` if it is not.

        Raises:
            DatabaseError: If the database structure is invalid or missing required fields.
        """
        print("⏳ [INFO] Validating the structure of the users database...")
        for username, details in users_db.items():
            # Ensure 'email' and 'password_hash' are present for each user
            if "email" not in details or "password_hash" not in details:
                raise DatabaseError(f"Missing fields for user '{username}': {details}")
            # Validate the email format using regex
            if not re.fullmatch(EMAIL_REGEX, details["email"]):
                raise DatabaseError(f"Invalid email format for user '{username}': {details['email']}")
        print("✅ [SUCCESS] The users database structure is valid.")
        return True # Return True if all users are valid

    @staticmethod
    def load_users_db() -> dict:
        """
        Loads the user database from a JSON file.

        Reads the data from 'users_db.json' and validates the database structure.

        Returns:
            dict: A dictionary containing the users, or an empty dictionary if loading fails.

        Raises:
            DatabaseError: If the users database file cannot be found, is not readable, or is
                            improperly formatted.
        """
        print("⏳ [INFO] Loading users database...")
        try:
            # Check if the database file exists
            if not os.path.exists(DB_FILE):
                print(f"❌ [ERROR] Database file not found at {DB_FILE}")
                raise DatabaseError(f"Database file not found at {DB_FILE}")

            with open(DB_FILE, "r") as file:
                data = json.load(file)

                # Validate the structure of the database
                if not RecoveryWindow.validate_users_db(data):
                    print("❌ [ERROR] Invalid user database structure.")
                    raise DatabaseError("Invalid user database structure.")
                return data

            print("✅ [SUCCESS] Users database loaded successfully.")
            return data

        except FileNotFoundError:
            print(f"❌ [ERROR] Database file not found at {DB_FILE}")
            show_message(None, "File Error", f"Database file not found at {DB_FILE}")
        except json.JSONDecodeError as e:
            print(f"❌ [ERROR] Error decoding database JSON: {e}")
            show_message(None, "JSON Error", f"Failed to decode database JSON: {e}")
        except Exception as e:
            print(f"❌ [ERROR] Unexpected error loading the database: {e}")
            show_message(None, "Error", f"Unexpected error: {e}")

        return {}  # Return an empty dictionary if any error occurs
