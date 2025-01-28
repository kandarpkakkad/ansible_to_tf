from typing import List, Dict, Any
from botocore.exceptions import ClientError
from .base import BaseScraper
from aws_resource_collector.resource_graph.graph import Resource, ResourceType


class Route53Scraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape Route53 resources and their configurations"""
        route53 = self.get_client('route53')
        resources = []
        try:
            # Collect hosted zones
            paginator = route53.get_paginator('list_hosted_zones')
            for page in paginator.paginate():
                for zone in page['HostedZones']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=zone['Id'].split('/')[-1],
                            type=ResourceType.ROUTE53,
                            name=zone['Name'].rstrip('.'),
                            env=next((tag['Value'] for tag in zone.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in zone.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )
                        self.related.set_resource(resource)

                        # Get zone tags
                        tags = route53.list_tags_for_resource(
                            ResourceType='hostedzone',
                            ResourceId=zone['Id'].split('/')[-1]
                        )
                        zone['Tags'] = tags['ResourceTagSet']['Tags']
                        
                        if self.tag_filter.matches(zone):
                            # Get record sets
                            records = self._get_record_sets(route53, zone['Id'])
                            zone['RecordSets'] = records

                            # Collect related resources
                            self._collect_related_resources(zone, resource)
                            
                            # Save zone
                            file_path = self.save_resource(
                                'route53/zones',
                                zone['Name'].rstrip('.'),
                                zone
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_zone', zone['Name'], e)
            
            # Collect health checks
            self._collect_health_checks(route53, resource)
            
        except ClientError as e:
            self.handle_aws_error('list_hosted_zones', 'all', e)
            
        return resources

    def _get_record_sets(self, route53, zone_id: str) -> List[Dict[str, Any]]:
        """Get record sets for a hosted zone"""
        records = []
        try:
            paginator = route53.get_paginator('list_resource_record_sets')
            for page in paginator.paginate(HostedZoneId=zone_id):
                records.extend(page['ResourceRecordSets'])
        except ClientError as e:
            self.handle_aws_error('get_record_sets', zone_id, e)
        return records

    def _collect_health_checks(self, route53, resource: Resource):
        """Collect Route53 health checks"""
        try:
            paginator = route53.get_paginator('list_health_checks')
            for page in paginator.paginate():
                for check in page['HealthChecks']:
                    try:
                        # Get health check tags
                        tags = route53.list_tags_for_resource(
                            ResourceType='healthcheck',
                            ResourceId=check['Id']
                        )
                        check['Tags'] = tags['ResourceTagSet']['Tags']
                        
                        if self.tag_filter.matches(check):
                            file_path = self.save_resource(
                                'route53/health_checks',
                                check['Id'],
                                check
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resource.depends_on.append(f"route53:health_check:{check['Id']}")
                                
                    except ClientError as e:
                        self.handle_aws_error('process_health_check', check['Id'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_health_checks', 'all', e)

    def _collect_related_resources(self, zone: Dict[str, Any], resource: Resource):
        """Collect resources related to Route53 zone"""
        try:
            # Collect related resources from record sets
            for record in zone.get('RecordSets', []):
                # Collect alias targets
                if 'AliasTarget' in record:
                    target = record['AliasTarget']
                    if 'elasticloadbalancing' in target.get('DNSName', ''):
                        self.related.collect_load_balancer(target['DNSName'], resource)
                    elif 's3-website' in target.get('DNSName', ''):
                        bucket_name = target['DNSName'].split('.')[0]
                        self.related.collect_s3_bucket(bucket_name, resource)
                    elif 'cloudfront' in target.get('DNSName', ''):
                        distribution_id = target['DNSName'].split('.')[0]
                        self.related.collect_cloudfront_distribution(distribution_id, resource)
                    elif 'apigateway' in target.get('DNSName', ''):
                        api_id = target['DNSName'].split('.')[0]
                        self.related.collect_api_gateway(api_id, resource)

                # Collect targets from records
                for value in record.get('ResourceRecords', []):
                    if 'amazonaws.com' in value.get('Value', ''):
                        if 'elasticloadbalancing' in value['Value']:
                            self.related.collect_load_balancer(value['Value'], resource)
                        elif 's3' in value['Value']:
                            bucket_name = value['Value'].split('.')[0]
                            self.related.collect_s3_bucket(bucket_name, resource)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for zone {zone.get('Name')}: {str(e)}")