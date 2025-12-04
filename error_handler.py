# error_handler.py

import logging
import traceback
from functools import wraps
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('p2p_errors.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class P2PError(Exception):
    pass

class NetworkError(P2PError):
    pass

class FileError(P2PError):
    pass

class AuthenticationError(P2PError):
    pass

class EncryptionError(P2PError):
    pass

class ErrorHandler:
    @staticmethod
    def log_error(error_type, message, exception=None):
        """Log error with details"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        error_msg = f"[{timestamp}] {error_type}: {message}"
        
        if exception:
            error_msg += f"\nException: {str(exception)}"
            error_msg += f"\nTraceback: {traceback.format_exc()}"
        
        logger.error(error_msg)
        return error_msg
    
    @staticmethod
    def log_info(message):
        """Log informational message"""
        logger.info(message)
    
    @staticmethod
    def log_warning(message):
        """Log warning message"""
        logger.warning(message)
    
    @staticmethod
    def handle_network_error(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ConnectionError as e:
                error_msg = ErrorHandler.log_error(
                    "NETWORK ERROR",
                    f"Connection failed in {func.__name__}",
                    e
                )
                raise NetworkError(error_msg) from e
            except TimeoutError as e:
                error_msg = ErrorHandler.log_error(
                    "TIMEOUT ERROR",
                    f"Operation timed out in {func.__name__}",
                    e
                )
                raise NetworkError(error_msg) from e
            except Exception as e:
                error_msg = ErrorHandler.log_error(
                    "UNEXPECTED ERROR",
                    f"Unexpected error in {func.__name__}",
                    e
                )
                raise NetworkError(error_msg) from e
        return wrapper
    
    @staticmethod
    def handle_file_error(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except FileNotFoundError as e:
                error_msg = ErrorHandler.log_error(
                    "FILE NOT FOUND",
                    f"File not found in {func.__name__}",
                    e
                )
                raise FileError(error_msg) from e
            except PermissionError as e:
                error_msg = ErrorHandler.log_error(
                    "PERMISSION ERROR",
                    f"Permission denied in {func.__name__}",
                    e
                )
                raise FileError(error_msg) from e
            except OSError as e:
                error_msg = ErrorHandler.log_error(
                    "OS ERROR",
                    f"OS error in {func.__name__}",
                    e
                )
                raise FileError(error_msg) from e
            except Exception as e:
                error_msg = ErrorHandler.log_error(
                    "UNEXPECTED ERROR",
                    f"Unexpected error in {func.__name__}",
                    e
                )
                raise FileError(error_msg) from e
        return wrapper
    
    @staticmethod
    def handle_auth_error(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if "401" in str(e) or "Unauthorized" in str(e):
                    error_msg = ErrorHandler.log_error(
                        "AUTHENTICATION ERROR",
                        f"Authentication failed in {func.__name__}",
                        e
                    )
                    raise AuthenticationError(error_msg) from e
                raise
        return wrapper
    
    @staticmethod
    def handle_encryption_error(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_msg = ErrorHandler.log_error(
                    "ENCRYPTION ERROR",
                    f"Encryption/Decryption failed in {func.__name__}",
                    e
                )
                raise EncryptionError(error_msg) from e
        return wrapper
    
    @staticmethod
    def safe_execute(func, *args, default_return=None, error_callback=None, **kwargs):
        try:
            result = func(*args, **kwargs)
            return True, result, None
        except Exception as e:
            error_msg = ErrorHandler.log_error(
                "EXECUTION ERROR",
                f"Error executing {func.__name__}",
                e
            )
            if error_callback:
                error_callback(error_msg)
            return False, default_return, error_msg

def get_user_friendly_message(error):
    error_str = str(error).lower()
    
    if "connection" in error_str or "network" in error_str:
        return "Network connection failed. Please check your internet connection and try again."
    elif "timeout" in error_str:
        return "Operation timed out. The server might be busy or unreachable."
    elif "not found" in error_str:
        return "The requested file or resource was not found."
    elif "permission" in error_str:
        return "Permission denied. Please check file permissions."
    elif "unauthorized" in error_str or "401" in error_str:
        return "Authentication failed. Please check your token."
    elif "encryption" in error_str or "decrypt" in error_str:
        return "Encryption/Decryption failed. Please verify your password."
    else:
        return f"An error occurred: {str(error)}"