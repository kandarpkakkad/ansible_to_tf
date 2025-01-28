from typing import Dict, Any, Optional
import os
import json
from dataclasses import dataclass, field
from .validation import SettingsValidator
from datetime import datetime, timedelta

@dataclass
class AWSSettings:
    """AWS-specific settings"""
    region: str
    profile: Optional[str] = None
    max_retries: int = 3
    timeout: int = 30

@dataclass
class ScraperSettings:
    """Resource scraper settings"""
    batch_size: int = 100
    max_threads: int = 5
    skip_empty: bool = True
    include_global: bool = True
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScraperSettings':
        return cls(
            batch_size=int(data.get('batch_size', 100)),
            max_threads=int(data.get('max_threads', 5)),
            skip_empty=bool(data.get('skip_empty', True)),
            include_global=bool(data.get('include_global', True))
        )

class Settings:
    """Application settings"""
    def __init__(
        self,
        aws: AWSSettings,
        scraper: ScraperSettings,
        required_tags: Optional[Dict[str, str]] = None,
        output_dir: str = 'aws_inventory',
        log_level: str = 'INFO',
        log_file: Optional[str] = None
    ):
        self.aws = aws
        self.scraper = scraper
        self.required_tags = required_tags or {}  # Initialize as empty dict if None
        self.output_dir = output_dir
        self.log_level = log_level
        self.log_file = log_file

    @property
    def application_id(self) -> str:
        """Get ApplicationId from required tags"""
        return self.required_tags.get('ApplicationID')

    @classmethod
    def load(cls, config_file: str = None) -> 'Settings':
        """Load settings from config file and environment variables"""
        settings = {
            'aws': {
                'region': os.getenv('AWS_REGION', 'us-east-1'),
                'profile': os.getenv('AWS_PROFILE'),
                'max_retries': int(os.getenv('AWS_MAX_RETRIES', '3')),
                'timeout': int(os.getenv('AWS_TIMEOUT', '30'))
            },
            'scraper': {
                'batch_size': int(os.getenv('SCRAPER_BATCH_SIZE', '100')),
                'max_threads': int(os.getenv('SCRAPER_MAX_THREADS', '5')),
                'skip_empty': os.getenv('SCRAPER_SKIP_EMPTY', 'true').lower() == 'true',
                'include_global': os.getenv('SCRAPER_INCLUDE_GLOBAL', 'true').lower() == 'true'
            },
            'required_tags': {},  # Start with empty tags
            'output_dir': os.getenv('OUTPUT_DIR', 'aws_inventory'),
            'log_level': os.getenv('LOG_LEVEL', 'INFO'),
            'log_file': os.getenv('LOG_FILE')
        }

        # Load from config file if provided
        if config_file and os.path.exists(config_file):
            with open(config_file) as f:
                file_settings = json.load(f)
                settings = cls._merge_settings(settings, file_settings)

        return cls(
            aws=AWSSettings(**settings['aws']),
            scraper=ScraperSettings.from_dict(settings['scraper']),
            required_tags=settings['required_tags'],
            output_dir=settings['output_dir'],
            log_level=settings['log_level'],
            log_file=settings['log_file']
        )

    @staticmethod
    def _merge_settings(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two settings dictionaries"""
        result = base.copy()
        
        for key, value in override.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = Settings._merge_settings(result[key], value)
            else:
                result[key] = value
                
        return result

    @staticmethod
    def _validate_settings(settings: Dict[str, Any]):
        """Validate all settings"""
        try:
            SettingsValidator.validate_aws_settings(settings['aws'])
            SettingsValidator.validate_scraper_settings(settings['scraper'])
            SettingsValidator.validate_required_tags(settings['required_tags'])
            SettingsValidator.validate_output_settings({
                'output_dir': settings['output_dir'],
                'log_level': settings['log_level'],
                'log_file': settings['log_file']
            })
        except ValueError as e:
            raise ValueError(f"Invalid settings: {str(e)}")

    @classmethod
    def validate(cls, config: dict) -> None:
        """Validate configuration settings"""
        required_fields = ['aws.region']
        for field in required_fields:
            if not cls._get_nested(config, field):
                raise ValueError(f"Missing required configuration: {field}")
        
        # Validate scraper settings
        scraper = config.get('scraper', {})
        if 'batch_size' in scraper:
            batch_size = scraper['batch_size']
            if not isinstance(batch_size, int) or batch_size < 1:
                raise ValueError("batch_size must be a positive integer")
        
        if 'max_threads' in scraper:
            max_threads = scraper['max_threads']
            if not isinstance(max_threads, int) or max_threads < 1:
                raise ValueError("max_threads must be a positive integer")
        
        if 'time_range' in scraper:
            time_range = scraper['time_range']
            if 'days' in time_range:
                days = time_range['days']
                if not isinstance(days, (int, float)) or days <= 0:
                    raise ValueError("time_range.days must be a positive number")
    
    @staticmethod
    def _get_nested(d: dict, path: str) -> Any:
        """Get nested dictionary value by dot notation path"""
        keys = path.split('.')
        value = d
        for key in keys:
            if not isinstance(value, dict):
                return None
            value = value.get(key)
        return value 

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return {
            'aws': {
                'region': self.aws.region,
                'profile': self.aws.profile,
                'max_retries': self.aws.max_retries,
                'timeout': self.aws.timeout
            },
            'scraper': {
                'batch_size': self.scraper.batch_size,
                'max_threads': self.scraper.max_threads,
                'skip_empty': self.scraper.skip_empty,
                'include_global': self.scraper.include_global
            },
            'required_tags': self.required_tags,
            'output_dir': self.output_dir,
            'log_level': self.log_level,
            'log_file': self.log_file
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Settings':
        """Create settings from dictionary"""
        return cls(
            aws=AWSSettings(**data.get('aws', {})),
            scraper=ScraperSettings.from_dict(data.get('scraper', {})),
            required_tags=data.get('required_tags'),
            output_dir=data.get('output_dir', 'aws_inventory'),
            log_level=data.get('log_level', 'INFO'),
            log_file=data.get('log_file')
        ) 