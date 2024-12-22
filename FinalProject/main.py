# Standard library imports
import sys

# Third-party imports
from PySide6.QtWidgets import QApplication

# Local project-specific imports
from windows.main_window import MainWindow


def main():
    """
    Initializes and runs the Qt application. Handles the creation and display of the main window,
    and includes error handling for the application initialization and window setup processes.

    Raises:
        Exception: Any exception encountered during application initialization or window setup is
                   caught and logged, after which the program exits with an error code.
    """
    try:
        # Try to create and run the application
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()  # Display the main window on the screen
        sys.exit(app.exec())  # Ensures the program exits cleanly after closing
    except Exception as e:
        # Catch any exception that occurs during the application startup
        print(f"❌ [ERROR] An error occurred while initializing the application: {e}")
        # Provide additional information for the error
        print("⚠️ [WARNING] The application encountered an issue and will now exit.")
        sys.exit(1)  # Exit the program with an error code


# Check if the script is being run as the main program
if __name__ == "__main__":
    main()
