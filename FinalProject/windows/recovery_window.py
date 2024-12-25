# Standard library imports
import json
import os
import smtplib
from smtplib import SMTPException
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Third-party imports
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLineEdit, QPushButton

# Local project-specific imports
from FinalProject.styles.styles import STYLES
from FinalProject.assets.utils import show_message
from FinalProject.assets.custom_errors import (EmailConfigError, EmailSendingError)
from FinalProject.assets.users_db import get_user_by_email

# Path to the user database and email configuration file
DB_FILE = os.path.join(os.getcwd(), "assets", "users_db.json")
EMAIL_CONFIG_FILE = os.path.join(os.getcwd(), "assets", "email_config.json")


def load_email_config() -> dict:
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

        except json.JSONDecodeError as json_err:
            print(f"❌ [ERROR] Error decoding email config file: {json_err}")
            show_message(None, "Configuration Error", f"Failed to decode email config: {json_err}")
            raise EmailConfigError(f"Failed to decode email config: {json_err}") from json_err

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
        _smtp_server (str): The address of the SMTP server.
        _smtp_port (int): The port used by the SMTP server.
        _sender_email (str): The email address used to send recovery emails.
        _sender_password (str): The password associated with the sender's email address.
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
        self._smtp_server = smtp_server
        self._smtp_port = smtp_port
        self._sender_email = sender_email
        self._sender_password = sender_password

    def _connect_and_send_email(self, recipient_email: str, msg: MIMEMultipart) -> None:
        """
        Connects to the SMTP server and sends the email.
        This is a private method.
        """
        try:
            # Connect to the SMTP server and send the email
            with smtplib.SMTP(self._smtp_server, self._smtp_port) as server:
                server.starttls()  # Secure connection using TLS
                server.login(self._sender_email, self._sender_password)
                server.sendmail(self._sender_email, recipient_email, msg.as_string())
            print(f"✅ [SUCCESS] Recovery email successfully sent to {recipient_email}.")

        except smtplib.SMTPAuthenticationError:
            print("❌ [ERROR] Authentication error, check the email server credentials.")
            raise EmailSendingError(
                "Authentication error: Unable to authenticate with SMTP server.")

        except smtplib.SMTPConnectError:
            print("❌ [ERROR] Unable to connect to SMTP server.")
            raise EmailSendingError("Connection error: Could not connect to SMTP server.")

        except Exception as gen_err:
            print(f"❌ [ERROR] Failed to send email: {gen_err}")
            raise EmailSendingError(f"Failed to send the recovery email: {gen_err}") from gen_err

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
        msg["From"] = self._sender_email
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        print(
            f"⏳ [INFO] Preparing to send recovery email to {recipient_email} "
            f"for the user '{username}'.")

        try:
            # Call the private method to connect and send the email
            self._connect_and_send_email(recipient_email, msg)

        except SMTPException as smtp_err:
            # Catch any errors related to email sending
            print(f"❌ [ERROR] Failed to send email: {smtp_err}")
            raise EmailSendingError("Failed to send recovery email to"
                                    f" {recipient_email}.") from smtp_err

class RecoveryWindow(QWidget):
    """
    A window for password recovery via email.

    This class defines the user interface and functionality for users to recover their passwords
    by entering their email. It checks if the email is valid, finds the corresponding user,
    and sends a recovery email with their password (hashed) to the provided email address.

    Attributes:
        _email_sender (EmailSender): EmailSender instance for sending recovery emails.
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
        self._email_input = QLineEdit()
        self._email_input.setStyleSheet(STYLES["text_field"])  # Apply custom styling
        self._email_input.setPlaceholderText("Enter your email")

        # Create and configure the "Send Recovery Email" button
        self._recover_button = QPushButton("Send Recovery Email")
        self._recover_button.setStyleSheet(STYLES["button"])
        self._recover_button.clicked.connect(self._recover_password) # Connect button click to method

        # Add input field and button to the layout
        layout.addWidget(self._email_input)
        layout.addWidget(self._recover_button)

        # Set the layout for the window
        self.setLayout(layout)

        try:
            # Load email configuration from the config file
            config = load_email_config()
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
            self._email_sender = EmailSender(
                smtp_server="smtp.gmail.com",
                smtp_port=587,
                sender_email=sender_email,
                sender_password=sender_password
            )

        except EmailConfigError as email_err:
            show_message(self, "Configuration Error", str(email_err))
            print(f"❌ [ERROR] {email_err}")
            raise email_err

    def _recover_password(self) -> None:
        """
        Triggers the password recovery process by sending an email.

        This method retrieves the email entered by the user, validates the email address,
        checks if the user exists in the system, and if so, sends them a recovery email.
        If the email is not found, the user is notified and the input field is cleared.
        """
        email = self._email_input.text() # Get the email entered by the user

        # Check if the email is valid
        user = get_user_by_email(email)
        if user:
            print(f"🔄 [INFO] Sending recovery email to {email}...")
            try:
                # Send the recovery email
                user_name = user.get("name", "User")  # Default to "User" if name is missing
                self._email_sender.send_recovery_email(email, user_name)
                show_message(self, "Success", "A recovery email has been sent.")
                self.close() # Close the recovery window after sending the email
                print("📝 [INFO] Recovery window closed.")
            except Exception as email_err:
                show_message(self, "Error", str(email_err))
                print(f"❌ [ERROR] Failed to send recovery email: {email_err}")
                raise EmailSendingError(f"Failed to send recovery email to {email}.") from email_err

        else:
            # If email not found, notify the user and clear the email input
            print(f"❌ [ERROR] No user found with email {email}.")
            show_message(self, "Error", "Email not found. Please try again.")
            self._email_input.clear()
