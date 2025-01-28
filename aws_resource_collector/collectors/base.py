from typing import List, Optional, Dict, Any
import os
import json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from aws_resource_collector.collectors.related import RelatedResourceScraper
from aws_resource_collector.resource_graph.graph import Resource
from filters.tag_filter import TagFilter
from utils.logger import Logger
from config.settings import Settings
from utils.json_encoder import DateTimeEncoder
import logging

class BaseScraper:
    """Base class for AWS resource scrapers"""
    
    def __init__(self, output_dir: str, tag_filter: TagFilter, settings: Settings):
        self.output_dir = output_dir
        self.tag_filter = tag_filter
        self.settings = settings
        self.logger = logging.getLogger(self.__class__.__name__)
        self.scraped_files = []
        self.related = RelatedResourceScraper(self)
        
        # Initialize AWS client with settings
        self.session = boto3.Session(
            region_name=settings.aws.region,
            profile_name=settings.aws.profile
        )
        
        # Create AWS config with retry settings
        self.aws_config = Config(
            retries={'max_attempts': settings.aws.max_retries},
            connect_timeout=settings.aws.timeout,
            read_timeout=settings.aws.timeout
        )
        
        # Initialize config client with settings
        self.config = self.session.client('config', config=self.aws_config)
    
    def get_client(self, service_name: str) -> boto3.client:
        """Get AWS client with configured settings"""
        return self.session.client(
            service_name,
            config=self.aws_config
        )
    
    def scrape(self) -> List[Resource]:
        """Scrape resources and return list of saved files"""
        raise NotImplementedError("Subclasses must implement scrape()")
    
    def save_resource(self, resource_type: str, resource_id: str, data: Dict[str, Any]) -> Optional[str]:
        """Save resource data to file"""
        try:
            # Skip empty resources if configured
            if self.settings.scraper.skip_empty and not data:
                self.logger.debug(f"Skipping empty resource {resource_type}/{resource_id}")
                return None
            
            # Create directory structure
            resource_dir = os.path.join(self.output_dir, resource_type)
            os.makedirs(resource_dir, exist_ok=True)
            
            # Save resource data
            filename = f"{resource_id}.json"
            filepath = os.path.join(resource_dir, filename)
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, cls=DateTimeEncoder)
            
            relative_path = os.path.relpath(filepath, self.output_dir)
            self.logger.info(f"Saved resource to {relative_path}")
            return relative_path
            
        except Exception as e:
            self.logger.error(f"Error saving resource {resource_type}/{resource_id}: {str(e)}")
            return None
    
    def handle_aws_error(self, operation: str, resource_id: str, error: ClientError):
        """Handle AWS API errors with improved messaging"""
        error_code = error.response['Error']['Code']
        error_message = error.response['Error']['Message']
        
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            self.logger.warning(
                f"Access denied for {operation} on {resource_id}. "
                f"Error: {error_message}. Check IAM permissions."
            )
        elif error_code == 'ThrottlingException':
            self.logger.warning(
                f"Request throttled for {operation} on {resource_id}. "
                f"Consider reducing batch size or increasing delay. Error: {error_message}"
            )
        elif error_code == 'InvalidParameter':
            self.logger.warning(
                f"Invalid parameter for {operation} on {resource_id}. "
                f"Error: {error_message}"
            )
        elif error_code == 'ResourceNotFoundException':
            self.logger.debug(
                f"Resource not found for {operation} on {resource_id}. "
                f"It may have been deleted. Error: {error_message}"
            )
        else:
            self.logger.error(
                f"AWS error during {operation} on {resource_id}: "
                f"{error_code} - {error_message}"
            )
    
    def process_batch(self, items: list, operation: callable, batch_size: Optional[int] = None) -> List[Any]:
        """Process items in batches with improved error handling"""
        batch_size = batch_size or self.settings.scraper.batch_size
        results = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            try:
                batch_results = operation(batch)
                results.extend(batch_results)
            except ClientError as e:
                self.handle_aws_error('process_batch', f'items {i}-{i+len(batch)}', e)
            except Exception as e:
                self.logger.error(
                    f"Error processing batch {i}-{i+len(batch)}: {str(e)}"
                )
                if self.settings.scraper.fail_fast:
                    raise
        
        return results 