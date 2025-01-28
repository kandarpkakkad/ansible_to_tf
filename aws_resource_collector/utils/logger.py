import logging
import sys
from typing import Optional

class Logger:
    _instance: Optional[logging.Logger] = None
    
    @classmethod
    def setup(cls, level: str = 'INFO', log_file: Optional[str] = None):
        """Setup logger with console and optional file handlers"""
        if cls._instance is None:
            # Create logger
            logger = logging.getLogger('aws_resource_collector')
            logger.setLevel(getattr(logging, level.upper()))
            
            # Create formatters
            console_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            file_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
            )
            
            # Create console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
            
            # Create file handler if log file specified
            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(file_formatter)
                logger.addHandler(file_handler)
            
            cls._instance = logger
    
    @classmethod
    def get(cls) -> logging.Logger:
        """Get logger instance"""
        if cls._instance is None:
            cls.setup()
        return cls._instance 