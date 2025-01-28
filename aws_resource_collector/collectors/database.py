from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError

from aws_resource_collector.resource_graph.graph import Resource, ResourceType
from .base import BaseScraper

class RDSScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape RDS instances and their configurations"""
        rds = self.get_client('rds')
        resources = []
        try:
            paginator = rds.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=instance['DBInstanceArn'],
                            type=ResourceType.RDS,
                            name=instance['DBInstanceIdentifier'],
                            env=next((tag['Value'] for tag in instance.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in instance.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get instance tags
                        tags = rds.list_tags_for_resource(
                            ResourceName=instance['DBInstanceArn']
                        )
                        instance['Tags'] = tags['TagList']
                        
                        if self.tag_filter.matches(instance):
                            # Collect related resources
                            self._scrape_related_resources(instance)
                            
                            # Save instance
                            file_path = self.save_resource(
                                'rds/instances',
                                instance['DBInstanceIdentifier'],
                                instance
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_instance', instance['DBInstanceIdentifier'], e)
                        
        except ClientError as e:
            self.handle_aws_error('describe_db_instances', 'all', e)
            
        return resources
    
    def _scrape_related_resources(self, instance: Dict[str, Any]):
        """Scrape resources related to RDS instance"""
        try:
            if 'DBSubnetGroup' in instance:
                for subnet in instance['DBSubnetGroup']['Subnets']:
                    self.related.collect_subnet(subnet['SubnetIdentifier'])
            
            for sg in instance.get('VpcSecurityGroups', []):
                self.related.collect_security_group(sg['VpcSecurityGroupId'])
            
            if instance.get('KmsKeyId'):
                self.related.collect_kms_key(instance['KmsKeyId'])
            
        except Exception as e:
            self.logger.error(f"Error collecting related resources for instance {instance['DBInstanceIdentifier']}: {str(e)}")

    def _scrape_parameter_groups(self, rds, instance: dict, resource: Resource):
        """Scrape parameter groups for instance"""
        try:
            # Get parameter group details
            if instance.get('DBParameterGroups'):
                for pg in instance['DBParameterGroups']:
                    try:
                        parameters = rds.describe_db_parameters(
                            DBParameterGroupName=pg['DBParameterGroupName']
                        )
                        pg['Parameters'] = parameters['Parameters']

                        resource.depends_on.append(f"rds:parameter_group:{pg['DBParameterGroupName']}")
                    except ClientError as e:
                        self.handle_aws_error('get_parameters', pg['DBParameterGroupName'], e)
                        
        except Exception as e:
            self.logger.error(f"Error collecting parameter groups for {instance['DBInstanceIdentifier']}: {str(e)}")

class ElastiCacheScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape ElastiCache clusters and their configurations"""
        elasticache = self.get_client('elasticache')
        resources = []
        
        try:
            paginator = elasticache.get_paginator('describe_cache_clusters')
            for page in paginator.paginate():
                for cluster in page['CacheClusters']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=cluster['ARN'],
                            type=ResourceType.ELASTICACHE,
                            name=cluster['CacheClusterId'],
                            env=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get cluster tags
                        tags = elasticache.list_tags_for_resource(
                            ResourceName=cluster['ARN']
                        )
                        cluster['Tags'] = tags['TagList']
                        
                        if self.tag_filter.matches(cluster):
                            # Collect related resources
                            self._scrape_related_resources(cluster, resource)
                            
                            # Save cluster
                            file_path = self.save_resource(
                                'elasticache/clusters',
                                cluster['CacheClusterId'],
                                cluster
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                    except ClientError as e:
                        self.handle_aws_error('process_cluster', cluster['CacheClusterId'], e)
                        
        except ClientError as e:
            self.handle_aws_error('describe_cache_clusters', 'all', e)
            
        return resources

    def _scrape_related_resources(self, cluster: Dict[str, Any], resource: Resource):
        """Scrape resources related to ElastiCache cluster"""
        try:
            # Collect subnet group and VPC resources
            if 'CacheSubnetGroup' in cluster:
                subnet_group = self._get_subnet_group(cluster['CacheSubnetGroup']['CacheSubnetGroupName'])
                if subnet_group:
                    # Collect subnets
                    for subnet in subnet_group['Subnets']:
                        self.related.scrape_subnet(subnet['SubnetIdentifier'], resource)

            # Collect security groups
            for sg in cluster.get('SecurityGroups', []):
                self.related.collect_security_group(sg['SecurityGroupId'], resource)

            # Collect parameter group
            if cluster.get('CacheParameterGroup'):
                self._scrape_parameter_group(cluster['CacheParameterGroup']['CacheParameterGroupName'], resource)

            # Collect KMS key if encrypted
            if cluster.get('AtRestEncryptionEnabled'):
                kms_key = cluster.get('KmsKeyId')
                if kms_key:
                    self.related.collect_kms_key(kms_key, resource)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for cluster {cluster.get('CacheClusterId')}: {str(e)}")

    def _get_subnet_group(self, group_name: str) -> dict:
        """Get subnet group details"""
        try:
            elasticache = self.get_client('elasticache')
            response = elasticache.describe_cache_subnet_groups(
                CacheSubnetGroupName=group_name
            )
            if response['CacheSubnetGroups']:
                return response['CacheSubnetGroups'][0]
        except ClientError as e:
            self.handle_aws_error('get_subnet_group', group_name, e)
        return None

    def _scrape_parameter_group(self, group_name: str, resource: Resource):
        """Scrape parameter group configuration"""
        try:
            elasticache = self.get_client('elasticache')
            response = elasticache.describe_cache_parameters(
                CacheParameterGroupName=group_name
            )
            
            # Save parameter group
            file_path = self.save_resource(
                'elasticache/parameter_groups',
                group_name,
                response
            )
            if file_path:
                self.collected_files.append(file_path)
                resource.depends_on.append(f"elasticache:parameter_group:{group_name}")

        except ClientError as e:
            self.handle_aws_error('get_parameter_group', group_name, e)

class RedshiftScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape Redshift clusters"""
        redshift = boto3.client('redshift')
        resources = []
        
        # Collect clusters
        paginator = redshift.get_paginator('describe_clusters')
        for page in paginator.paginate():
            for cluster in page['Clusters']:
                try:
                    # Create resource
                    resource = Resource(
                        id=cluster['ClusterNamespaceArn'],
                        type=ResourceType.REDSHIFT,
                        name=cluster['ClusterIdentifier'],
                        env=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                if tag['Key'] == 'Environment'), "Dev"),
                        app_id=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                   if tag['Key'] == 'ApplicationId'), "Unknown")
                    )

                    self.related.set_resource(resource)

                    # Get cluster tags
                    tags = redshift.describe_tags(
                        ResourceName=cluster['ClusterNamespaceArn'],
                        ResourceType='cluster'
                    )
                    cluster['Tags'] = tags['TaggedResources']
                    
                    if self.tag_filter.matches(cluster):
                        file_path = self.save_resource(
                            'redshift/clusters',
                            cluster['ClusterIdentifier'],
                            cluster
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            
                            # Collect parameter groups
                            self._collect_parameter_groups(redshift, cluster['ClusterParameterGroups'][0]['ParameterGroupName'], resource)

                            resources.append(resource)
                            
                except ClientError as e:
                    self.handle_aws_error('describe_clusters', 'all', e)
        
        return resources
    
    def _collect_parameter_groups(self, redshift, group_name: str, resource: Resource):
        """Collect parameter groups for cluster"""
        try:
            group = redshift.describe_cluster_parameters(ParameterGroupName=group_name)
            file_path = self.save_resource(
                'redshift/parameter_groups',
                group_name,
                group
            )
            if file_path:
                self.collected_files.append(file_path)
                resource.depends_on.append(f"redshift:parameter_group:{group_name}")
        except ClientError as e:
            self.handle_aws_error('describe_cluster_parameters', group_name, e)

class DynamoDBScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape DynamoDB tables and their configurations"""
        dynamodb = self.get_client('dynamodb')
        resources = []
        
        try:
            paginator = dynamodb.get_paginator('list_tables')
            for page in paginator.paginate():
                for table_name in page['TableNames']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=table_name,
                            type=ResourceType.DYNAMODB,
                            name=table_name,
                            env=next((tag['Value'] for tag in table.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in table.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get table details
                        table = dynamodb.describe_table(TableName=table_name)['Table']
                        
                        # Get table tags
                        tags = dynamodb.list_tags_of_resource(
                            ResourceArn=table['TableArn']
                        )
                        table['Tags'] = tags['Tags']
                        
                        if self.tag_filter.matches(table):
                            # Collect KMS key if encrypted
                            if table.get('SSEDescription', {}).get('KMSMasterKeyArn'):
                                self.related.collect_kms_key(table['SSEDescription']['KMSMasterKeyArn'], resource)
                            
                            # Collect replica KMS keys if any
                            for replica in table.get('Replicas', []):
                                # Collect KMS key if encrypted
                                if replica.get('KMSMasterKeyArn'):
                                    self.related.collect_kms_key(replica['KMSMasterKeyArn'], resource)
                                
                                # Collect replica region
                                if replica.get('RegionName'):
                                    resource.depends_on.append(f"region:{replica['RegionName']}")
                                
                                # Collect IAM role if specified
                                if replica.get('RoleArn'):
                                    role_name = replica['RoleArn'].split('/')[-1]
                                    self.related.collect_iam_role(role_name)
                            
                            # Save table
                            file_path = self.save_resource(
                                'dynamodb/tables',
                                table_name,
                                table
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                    except ClientError as e:
                        self.handle_aws_error('process_table', table_name, e)
                    except Exception as e:
                        self.logger.error(f"Error processing table {table_name}: {str(e)}")
                        
        except ClientError as e:
            self.handle_aws_error('list_tables', 'all', e)
        except Exception as e:
            self.logger.error(f"Error collecting DynamoDB tables: {str(e)}")
            
        return resources
