from typing import Dict, Any
import re

class SettingsValidator:
    """Validate AWS resource collector settings"""
    
    VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR'}
    MIN_BATCH_SIZE = 1
    MAX_BATCH_SIZE = 1000
    MIN_THREADS = 1
    MAX_THREADS = 20
    MIN_RETRIES = 0
    MAX_RETRIES = 10
    MIN_TIMEOUT = 1
    MAX_TIMEOUT = 300
    
    @classmethod
    def validate_aws_settings(cls, settings: Dict[str, Any]):
        """Validate AWS settings"""
        # Validate region format
        if not re.match(r'^[a-z]{2}-[a-z]+-\d{1}$', settings['region']):
            raise ValueError(f"Invalid AWS region format: {settings['region']}")
        
        # Validate max retries
        retries = settings['max_retries']
        if not cls.MIN_RETRIES <= retries <= cls.MAX_RETRIES:
            raise ValueError(f"max_retries must be between {cls.MIN_RETRIES} and {cls.MAX_RETRIES}")
        
        # Validate timeout
        timeout = settings['timeout']
        if not cls.MIN_TIMEOUT <= timeout <= cls.MAX_TIMEOUT:
            raise ValueError(f"timeout must be between {cls.MIN_TIMEOUT} and {cls.MAX_TIMEOUT}")
    
    @classmethod
    def validate_collector_settings(cls, settings: Dict[str, Any]):
        """Validate collector settings"""
        # Validate batch size
        batch_size = settings['batch_size']
        if not cls.MIN_BATCH_SIZE <= batch_size <= cls.MAX_BATCH_SIZE:
            raise ValueError(f"batch_size must be between {cls.MIN_BATCH_SIZE} and {cls.MAX_BATCH_SIZE}")
        
        # Validate max threads
        threads = settings['max_threads']
        if not cls.MIN_THREADS <= threads <= cls.MAX_THREADS:
            raise ValueError(f"max_threads must be between {cls.MIN_THREADS} and {cls.MAX_THREADS}")
        
        # Validate boolean settings
        if not isinstance(settings['skip_empty'], bool):
            raise ValueError("skip_empty must be a boolean")
        if not isinstance(settings['include_global'], bool):
            raise ValueError("include_global must be a boolean")
    
    @classmethod
    def validate_required_tags(cls, tags: Dict[str, str]):
        """Validate required tags"""
        if not isinstance(tags, dict):
            raise ValueError("required_tags must be a dictionary")
        
        if not tags.get('ApplicationId'):
            raise ValueError("ApplicationId tag is required")
        
        for key, value in tags.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("Tag keys and values must be strings")
            if not key or not value:
                raise ValueError("Tag keys and values cannot be empty")
            if len(key) > 128:
                raise ValueError(f"Tag key '{key}' exceeds 128 characters")
            if len(value) > 256:
                raise ValueError(f"Tag value for '{key}' exceeds 256 characters")
    
    @classmethod
    def validate_output_settings(cls, settings: Dict[str, Any]):
        """Validate output settings"""
        # Validate log level
        log_level = settings['log_level'].upper()
        if log_level not in cls.VALID_LOG_LEVELS:
            raise ValueError(f"Invalid log level. Must be one of {sorted(cls.VALID_LOG_LEVELS)}")
        
        # Validate output directory
        output_dir = settings['output_dir']
        if not isinstance(output_dir, str) or not output_dir:
            raise ValueError("output_dir must be a non-empty string")
        
        # Validate log file path if provided
        log_file = settings.get('log_file')
        if log_file is not None:
            if not isinstance(log_file, str) or not log_file:
                raise ValueError("log_file must be a non-empty string if provided")
    
    @classmethod
    def validate_settings(cls, settings: Dict[str, Any]):
        """Validate all settings"""
        try:
            cls.validate_aws_settings(settings['aws'])
            cls.validate_collector_settings(settings['collector'])
            cls.validate_required_tags(settings['required_tags'])
            cls.validate_output_settings({
                'output_dir': settings['output_dir'],
                'log_level': settings['log_level'],
                'log_file': settings['log_file']
            })
        except ValueError as e:
            raise ValueError(f"Invalid settings: {str(e)}") 