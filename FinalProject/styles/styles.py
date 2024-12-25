# Third-party imports
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QLineEdit, QPushButton
from FinalProject.assets.custom_errors import WidgetError, InputValidationError


# Styles for widgets
STYLES = {
    "button": """
        QPushButton {
            background-color: #8ED0F8;
            color: white;
            border: none;
            border-radius: 25px;
            font-size: 26px;
            padding: 8px;
            min-width: 500px;
            cursor: pointer;
        }
        QPushButton:hover {
            background-color: #1A91DA;
        }
    """,
    "main_window": """
        QMainWindow {
            background-color: #F5F5F5;
        }
    """,
    "text_field": """
        QLineEdit {
            background-color: white;
            border: 2px solid #8ED0F8;
            border-radius: 10px;
            padding: 10px;
            font-size: 18px;
            min-width: 500px;
        }
        QLineEdit:focus {
            border-color: #1A91DA;
        }
        QLineEdit::placeholder {
            color: #888888;
            font-style: italic;
        }
    """,
    "feedback": {
        "success": "color: green; font-size: 16px;",
        "error": "color: red; font-size: 16px;",
        "info": "color: blue; font-size: 16px;",
    },
    "title": "font-size: 30px; color: #333;",

    "password_recovery_link": """
        QLabel {
            color: #1A91DA;
            font-size: 16px;
            text-decoration: none;
        }
        QLabel:hover {
            text-decoration: underline;
        }
    """
}

# Constants for input fields and button sizes
DEFAULT_INPUT_WIDTH = 500
DEFAULT_INPUT_HEIGHT = 50
DEFAULT_BUTTON_WIDTH = 200
DEFAULT_BUTTON_HEIGHT = 50


def create_title(title_text: str) -> QLabel:
    """
    Creates and returns a QLabel to display the title with the defined style.

    Args:
        title_text (str): The text to display on the title label.

    Returns:
        QLabel: A QLabel widget with the title and applied style.

    Raises:
        WidgetError: If there is an issue creating the label.
    """
    try:
        title = QLabel(title_text)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(STYLES["title"])
        return title

    except InputValidationError as in_val_err:
        print(f"❌ [ERROR] {in_val_err}")
        raise

    except Exception as gen_err:
        print(f"❌ [ERROR] Failed to create title label: {gen_err}")
        raise WidgetError(f"Failed to create title label: {gen_err}") from gen_err


def create_input_field(placeholder: str, is_password: bool = False,
                       width: int = DEFAULT_INPUT_WIDTH, height: int = DEFAULT_INPUT_HEIGHT
                      ) -> QLineEdit:
    """
    Creates and returns a styled text input field.

    Args:
        placeholder (str): The placeholder text to display in the input field.
        is_password (bool): If True, the text will be hidden (for password input).
        width (int): The width of the input field.
        height (int): The height of the input field.

    Returns:
        QLineEdit: A QLineEdit widget with the specified style.

    Raises:
        WidgetError: If there is an issue creating the input field.
    """
    try:
        input_field = QLineEdit()
        input_field.setPlaceholderText(placeholder)
        if is_password:
            input_field.setEchoMode(QLineEdit.EchoMode.Password)
        input_field.setStyleSheet(STYLES["text_field"])
        input_field.setFixedSize(width, height)
        return input_field

    except InputValidationError as in_val_err:
        print(f"❌ [ERROR] {in_val_err}")
        raise

    except Exception as gen_err:
        print(f"❌ [ERROR] Failed to create input field: {gen_err}")
        raise WidgetError(f"Failed to create input field with placeholder "
                          f"'{placeholder}': {gen_err}") from gen_err


def create_button(button_text: str, callback: callable, width: int = DEFAULT_BUTTON_WIDTH,
                  height: int = DEFAULT_BUTTON_HEIGHT) -> QPushButton:
    """
    Creates and returns a QPushButton with custom text, style, and size.

    Args:
        button_text (str): The text to display on the button.
        callback (callable): The function to be executed when the button is clicked.
        width (int): The width of the button.
        height (int): The height of the button.

    Returns:
        QPushButton: A QPushButton widget with the specified text and style.

    Raises:
        WidgetError: If there is an issue creating the button.
    """
    try:
        button = QPushButton(button_text)
        button.setFixedSize(width, height)
        button.setStyleSheet(STYLES["button"])
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        button.clicked.connect(callback)
        return button

    except Exception as gen_err:
        print(f"❌ [ERROR] Failed to create button with text '{button_text}': {gen_err}")
        raise WidgetError(f"Failed to create button with text '{button_text}': {gen_err}")\
            from gen_err


def style_feedback_label(label: QLabel, message: str, message_type: str = "info") -> None:
    """
    Updates and styles the feedback label with the specified message and style.

    Args:
        label (QLabel): The label to update with the message.
        message (str): The message to display in the label.
        message_type (str): The type of message ("success", "error", or "info").

    Raises:
        InputValidationError: If the message type is invalid.
    """
    try:
        if message_type not in STYLES["feedback"]:
            raise InputValidationError(f"Invalid message type: {message_type}")

        label.setText(message)
        label.setStyleSheet(STYLES["feedback"].get(message_type, STYLES["feedback"]["info"]))

    except InputValidationError as in_val_err:
        print(f"❌ [ERROR] {in_val_err}")
        label.setText("Error: Invalid message type.")
        label.setStyleSheet(STYLES["feedback"]["error"])

    except Exception as gen_err:
        print(f"❌ [ERROR] An error occurred while styling feedback label: {gen_err}")
        label.setText("An unexpected error occurred.")
        label.setStyleSheet(STYLES["feedback"]["error"])
