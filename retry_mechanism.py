# retry_mechanism.py

import time
import functools
from error_handler import ErrorHandler, NetworkError

class RetryConfig:
    def __init__(self, max_attempts=3, base_delay=1, max_delay=10, backoff_factor=2):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor

class RetryMechanism:
    
    def __init__(self, config=None):
        self.config = config or RetryConfig()
        self.error_handler = ErrorHandler()
    
    def retry_with_backoff(self, func, *args, on_retry_callback=None, **kwargs):
        last_exception = None
        
        for attempt in range(1, self.config.max_attempts + 1):
            try:
                self.error_handler.log_info(
                    f"Attempt {attempt}/{self.config.max_attempts} for {func.__name__}"
                )
                
                result = func(*args, **kwargs)
                
                if attempt > 1:
                    self.error_handler.log_info(
                        f"Success on attempt {attempt} for {func.__name__}"
                    )
                
                return True, result, None
                
            except Exception as e:
                last_exception = e
                
                if attempt < self.config.max_attempts:
                    # Calculate delay with exponential backoff
                    delay = min(
                        self.config.base_delay * (self.config.backoff_factor ** (attempt - 1)),
                        self.config.max_delay
                    )
                    
                    self.error_handler.log_warning(
                        f"Attempt {attempt} failed for {func.__name__}. "
                        f"Retrying in {delay} seconds... Error: {str(e)}"
                    )
                    
                    # Call retry callback if provided
                    if on_retry_callback:
                        on_retry_callback(attempt, e, delay)
                    
                    time.sleep(delay)
                else:
                    # Final attempt failed
                    error_msg = self.error_handler.log_error(
                        "RETRY EXHAUSTED",
                        f"All {self.config.max_attempts} attempts failed for {func.__name__}",
                        e
                    )
        
        return False, None, str(last_exception)
    
    def retry_decorator(self, max_attempts=None, on_retry_callback=None):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                # Use custom max_attempts if provided, otherwise use config
                attempts = max_attempts or self.config.max_attempts
                temp_config = RetryConfig(max_attempts=attempts)
                temp_retry = RetryMechanism(temp_config)
                
                success, result, error = temp_retry.retry_with_backoff(
                    func, *args, 
                    on_retry_callback=on_retry_callback,
                    **kwargs
                )
                
                if success:
                    return result
                else:
                    raise Exception(f"Operation failed after {attempts} attempts: {error}")
            
            return wrapper
        return decorator

# Create a global retry mechanism instance
default_retry = RetryMechanism()

def retry_operation(func, *args, max_attempts=3, on_retry=None, **kwargs):
    config = RetryConfig(max_attempts=max_attempts)
    retry_mech = RetryMechanism(config)
    return retry_mech.retry_with_backoff(func, *args, on_retry_callback=on_retry, **kwargs)

def with_retry(max_attempts=3):
    return default_retry.retry_decorator(max_attempts=max_attempts)