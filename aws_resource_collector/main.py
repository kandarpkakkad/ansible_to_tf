#!/usr/bin/env python3

import os
import json
import argparse
from datetime import datetime
from collectors.compute import EC2Scraper
from collectors.storage import S3Scraper, EFSScraper
from collectors.database import RDSScraper, ElastiCacheScraper, RedshiftScraper, DynamoDBScraper
from filters.tag_filter import TagFilter
from collectors.monitoring import CloudWatchScraper
from collectors.messaging import SNSScraper, SQSScraper, EventBridgeScraper
from collectors.containers import ECRScraper, ECSScraper
from collectors.serverless import LambdaScraper, APIGatewayScraper, StepFunctionsScraper
from utils.logger import Logger
from config.settings import AWSSettings, ScraperSettings, Settings
from collectors.security import KMSScraper, SecurityGroupScraper, SecretsManagerScraper
from config.validation import SettingsValidator
from collectors.analytics import KinesisScraper, GlueScraper
from collectors.network import Route53Scraper
from collectors.transfer import TransferScraper
import sys
from typing import List, Optional
import logging

def main():
    parser = argparse.ArgumentParser(description='Collect AWS resources with specific tags')
    parser.add_argument('--config', help='Path to configuration file')
    parser.add_argument('--output-dir', help='Override output directory')
    parser.add_argument('--application-id', dest='application_id', help='Filter resources by ApplicationID tag')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                      help='Override logging level')
    parser.add_argument('--log-file', help='Override log file path')
    args = parser.parse_args()

    # Create initial settings with empty required tags
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
        'required_tags': {},
        'output_dir': os.getenv('OUTPUT_DIR', 'aws_inventory'),
        'log_level': os.getenv('LOG_LEVEL', 'INFO'),
        'log_file': os.getenv('LOG_FILE')
    }

    # Load config file if provided
    if args.config and os.path.exists(args.config):
        with open(args.config) as f:
            file_settings = json.load(f)
            settings = Settings._merge_settings(settings, file_settings)

    # Override settings with command line arguments
    if args.output_dir:
        settings['output_dir'] = args.output_dir
    if args.log_level:
        settings['log_level'] = args.log_level
    if args.log_file:
        settings['log_file'] = args.log_file

    # Set ApplicationID only if provided
    if args.application_id:
        settings['required_tags'] = {'ApplicationID': args.application_id}

    # Create Settings object
    settings = Settings(
        aws=AWSSettings(**settings['aws']),
        scraper=ScraperSettings.from_dict(settings['scraper']),
        required_tags=settings['required_tags'],
        output_dir=settings['output_dir'],
        log_level=settings['log_level'],
        log_file=settings['log_file']
    )

    # Setup logging
    Logger.setup(level=settings.log_level, log_file=settings.log_file)
    logger = Logger.get()

    # Create output directory with timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = f"{settings.output_dir}_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Created output directory: {output_dir}")

    # Initialize tag filter with optional ApplicationID
    tag_filter = TagFilter(required_tags=settings.required_tags)
    if settings.required_tags:
        logger.info(f"Initialized tag filter: {settings.required_tags}")
    else:
        logger.info("No tag filters applied - collecting all resources")

    # Initialize scrapers
    scrapers = [
        # Compute resources
        EC2Scraper(output_dir, tag_filter, settings),
        
        # Storage resources
        S3Scraper(output_dir, tag_filter, settings),
        EFSScraper(output_dir, tag_filter, settings),
        
        # Database resources
        RDSScraper(output_dir, tag_filter, settings),
        ElastiCacheScraper(output_dir, tag_filter, settings),
        DynamoDBScraper(output_dir, tag_filter, settings),
        RedshiftScraper(output_dir, tag_filter, settings),
        
        # Container resources
        ECSScraper(output_dir, tag_filter, settings),
        ECRScraper(output_dir, tag_filter, settings),
        
        # Security resources
        KMSScraper(output_dir, tag_filter, settings),
        SecurityGroupScraper(output_dir, tag_filter, settings),
        SecretsManagerScraper(output_dir, tag_filter, settings),
        
        # Messaging resources
        SNSScraper(output_dir, tag_filter, settings),
        SQSScraper(output_dir, tag_filter, settings),
        
        # Monitoring resources
        CloudWatchScraper(output_dir, tag_filter, settings),
        
        # Serverless resources
        LambdaScraper(output_dir, tag_filter, settings),
        APIGatewayScraper(output_dir, tag_filter, settings),
        StepFunctionsScraper(output_dir, tag_filter, settings),
        
        # Analytics resources
        KinesisScraper(output_dir, tag_filter, settings),
        GlueScraper(output_dir, tag_filter, settings),
        
        # Network resources
        Route53Scraper(output_dir, tag_filter, settings),
        
        # Transfer resources
        TransferScraper(output_dir, tag_filter, settings),
    ]

    # Collect resources
    collected_files = []
    for scraper in scrapers:
        logger.info(f"Running scraper: {scraper.__class__.__name__}")
        try:
            files = scraper.scrape()
            if files:
                collected_files.extend(files)
                logger.info(f"Collected {len(files)} resources")
        except Exception as e:
            logger.error(f"Error in scraper {scraper.__class__.__name__}: {str(e)}")

    # Create index file
    index = {
        'timestamp': timestamp,
        'application_id': settings.required_tags.get('ApplicationID'),  # Use ApplicationID
        'files': collected_files
    }

    index_path = os.path.join(output_dir, 'index.json')
    with open(index_path, 'w') as f:
        json.dump(index, f, indent=2)
    logger.info(f"Created index file with {len(collected_files)} resources")

class ResourceScraper:
    def __init__(self, output_dir: str, tag_filter: TagFilter, settings: Settings):
        self.output_dir = output_dir
        self.tag_filter = tag_filter
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize scrapers
        self.scrapers = [
            # Compute resources
            EC2Scraper(output_dir, tag_filter, settings),
            
            # Storage resources
            S3Scraper(output_dir, tag_filter, settings),
            EFSScraper(output_dir, tag_filter, settings),
            
            # Database resources
            RDSScraper(output_dir, tag_filter, settings),
            ElastiCacheScraper(output_dir, tag_filter, settings),
            DynamoDBScraper(output_dir, tag_filter, settings),
            RedshiftScraper(output_dir, tag_filter, settings),
            
            # Container resources
            ECSScraper(output_dir, tag_filter, settings),
            ECRScraper(output_dir, tag_filter, settings),
            
            # Security resources
            KMSScraper(output_dir, tag_filter, settings),
            SecurityGroupScraper(output_dir, tag_filter, settings),
            SecretsManagerScraper(output_dir, tag_filter, settings),
            
            # Messaging resources
            SNSScraper(output_dir, tag_filter, settings),
            SQSScraper(output_dir, tag_filter, settings),
            
            # Monitoring resources
            CloudWatchScraper(output_dir, tag_filter, settings),
            
            # Serverless resources
            LambdaScraper(output_dir, tag_filter, settings),
            APIGatewayScraper(output_dir, tag_filter, settings),
            StepFunctionsScraper(output_dir, tag_filter, settings),
            
            # Analytics resources
            KinesisScraper(output_dir, tag_filter, settings),
            GlueScraper(output_dir, tag_filter, settings),
            
            # Network resources
            Route53Scraper(output_dir, tag_filter, settings),
            
            # Transfer resources
            TransferScraper(output_dir, tag_filter, settings),
        ]
    
    def scrape(self) -> List[str]:
        """Run all scrapers and return list of scraped files"""
        scraped_files = []
        
        for scraper in self.scrapers:
            try:
                self.logger.info(f"Running scraper: {scraper.__class__.__name__}")
                files = scraper.scrape()
                scraped_files.extend(files)
            except Exception as e:
                self.logger.error(f"Error in scraper {scraper.__class__.__name__}: {str(e)}")
                
        return scraped_files

if __name__ == "__main__":
    main() 