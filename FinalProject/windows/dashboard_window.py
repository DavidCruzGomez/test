# Third-party imports
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMainWindow, QLabel, QVBoxLayout, QWidget


class DashboardWindow(QMainWindow):
    """
    Dashboard window class.

    This class represents the main dashboard that users see after logging in.
    """

    def __init__(self) -> None:
        """
        Initialize the dashboard window.
        """
        super().__init__()

        # Set the dashboard window's properties
        self.setWindowTitle("Dashboard")
        self.setGeometry(100, 100, 800, 600)

        # Create a layout for the dashboard content
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Add a welcome label
        welcome_label = QLabel("Welcome to the Dashboard!")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(welcome_label)

        # Set the layout to a central widget
        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
