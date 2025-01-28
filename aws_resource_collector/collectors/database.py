from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError

from aws_resource_collector.resource_graph.graph import Resource, ResourceType
from .base import BaseScraper

class RDSScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape RDS instances and Aurora clusters with their configurations"""
        rds = self.get_client('rds')
        resources = []
        
        # Collect standalone instances
        resources.extend(self._scrape_instances(rds))
        
        # Collect Aurora clusters
        resources.extend(self._scrape_clusters(rds))
        
        return resources

    def _scrape_instances(self, rds) -> List[Resource]:
        """Scrape RDS instances and their configurations"""
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
                            self._scrape_related_resources(instance, resource)
                            
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

    def _scrape_clusters(self, rds) -> List[Resource]:
        """Scrape Aurora clusters and their configurations"""
        resources = []
        try:
            paginator = rds.get_paginator('describe_db_clusters')
            for page in paginator.paginate():
                for cluster in page['DBClusters']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=cluster['DBClusterArn'],
                            type=ResourceType.RDS,
                            name=cluster['DBClusterIdentifier'],
                            env=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get cluster tags
                        tags = rds.list_tags_for_resource(
                            ResourceName=cluster['DBClusterArn']
                        )
                        cluster['Tags'] = tags['TagList']
                        
                        if self.tag_filter.matches(cluster):
                            # Collect related resources
                            self._scrape_cluster_related_resources(cluster, resource)
                            
                            # Save cluster
                            file_path = self.save_resource(
                                'rds/clusters',
                                cluster['DBClusterIdentifier'],
                                cluster
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                            
                    except ClientError as e:
                        self.handle_aws_error('process_cluster', cluster['DBClusterIdentifier'], e)
                    
        except ClientError as e:
            self.handle_aws_error('describe_db_clusters', 'all', e)
            
        return resources

    def _scrape_cluster_related_resources(self, cluster: Dict[str, Any], resource: Resource):
        """Scrape resources related to Aurora cluster"""
        try:
            # Collect subnet group and subnets
            if 'DBSubnetGroup' in cluster:
                self._scrape_subnet_group(cluster['DBSubnetGroup']['DBSubnetGroupName'], resource)
            
            # Collect security groups
            for sg in cluster.get('VpcSecurityGroups', []):
                self.related.collect_security_group(sg['VpcSecurityGroupId'])
            
            # Collect KMS key
            if cluster.get('KmsKeyId'):
                self.related.collect_kms_key(cluster['KmsKeyId'])
            
            # Collect cluster instances
            self._scrape_cluster_instances(cluster['DBClusterIdentifier'], resource)
            
            # Collect cluster autoscaling
            self._collect_cluster_autoscaling(cluster['DBClusterIdentifier'], resource)
            
        except Exception as e:
            self.logger.error(f"Error collecting related resources for cluster {cluster['DBClusterIdentifier']}: {str(e)}")

    def _scrape_cluster_instances(self, cluster_id: str, resource: Resource):
        """Collect Aurora cluster member instances"""
        try:
            rds = self.get_client('rds')
            instances = rds.describe_db_instances(
                Filters=[{'Name': 'db-cluster-id', 'Values': [cluster_id]}]
            )['DBInstances']
            
            for instance in instances:
                try:
                    # Save instance
                    file_path = self.save_resource(
                        f'rds/clusters/{cluster_id}/instances',
                        instance['DBInstanceIdentifier'],
                        instance
                    )
                    if file_path:
                        self.collected_files.append(file_path)
                        resource.depends_on.append(f"rds:instance:{instance['DBInstanceIdentifier']}")
                    
                except ClientError as e:
                    self.handle_aws_error('process_cluster_instance', instance['DBInstanceIdentifier'], e)
                
        except ClientError as e:
            self.handle_aws_error('describe_cluster_instances', cluster_id, e)

    def _collect_cluster_autoscaling(self, cluster_id: str, resource: Resource):
        """Collect autoscaling configurations for Aurora cluster"""
        try:
            app_autoscaling = self.get_client('application-autoscaling')
            try:
                # Get scalable targets
                targets = app_autoscaling.describe_scalable_targets(
                    ServiceNamespace='rds',
                    ResourceIds=[f'cluster:{cluster_id}']
                )['ScalableTargets']
                
                # Get scaling policies for each target
                for target in targets:
                    try:
                        policies = app_autoscaling.describe_scaling_policies(
                            ServiceNamespace='rds',
                            ResourceId=target['ResourceId'],
                            ScalableDimension=target['ScalableDimension']
                        )['ScalingPolicies']
                        
                        target['ScalingPolicies'] = policies
                        
                        # Save autoscaling configuration
                        file_path = self.save_resource(
                            f'rds/clusters/{cluster_id}/autoscaling',
                            target['ScalableDimension'].split(':')[-1],
                            target
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            resource.depends_on.append(f"autoscaling:policy:{target['ResourceId']}")
                            
                    except ClientError as e:
                        self.handle_aws_error('get_cluster_scaling_policies', cluster_id, e)
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'ValidationException':
                    self.handle_aws_error('get_cluster_scalable_targets', cluster_id, e)
                
        except Exception as e:
            self.logger.error(f"Error collecting autoscaling for cluster {cluster_id}: {str(e)}")

    def _scrape_related_resources(self, instance: Dict[str, Any], resource: Resource):
        """Scrape resources related to RDS instance"""
        try:
            # Collect subnet group and subnets
            if 'DBSubnetGroup' in instance:
                self._scrape_subnet_group(instance['DBSubnetGroup']['DBSubnetGroupName'], resource)
            
            # Collect security groups
            for sg in instance.get('VpcSecurityGroups', []):
                self.related.collect_security_group(sg['VpcSecurityGroupId'])
            
            # Collect KMS key
            if instance.get('KmsKeyId'):
                self.related.collect_kms_key(instance['KmsKeyId'])

            # Add autoscaling collection
            self._collect_autoscaling(instance['DBInstanceIdentifier'], resource)
            
        except Exception as e:
            self.logger.error(f"Error collecting related resources for instance {instance['DBInstanceIdentifier']}: {str(e)}")

    def _scrape_subnet_group(self, subnet_group_name: str, resource: Resource):
        """Scrape subnet group and its subnets"""
        try:
            rds = self.get_client('rds')
            
            # Get subnet group details
            subnet_group = rds.describe_db_subnet_groups(
                DBSubnetGroupName=subnet_group_name
            )['DBSubnetGroups'][0]
            
            # Save subnet group
            file_path = self.save_resource(
                'rds/subnet_groups',
                subnet_group_name,
                subnet_group
            )
            if file_path:
                self.collected_files.append(file_path)
                resource.depends_on.append(f"rds:subnet_group:{subnet_group_name}")
            
            # Collect subnets
            for subnet in subnet_group['Subnets']:
                self.related.collect_subnet(subnet['SubnetIdentifier'])
            
        except ClientError as e:
            self.handle_aws_error('get_subnet_group', subnet_group_name, e)
        except Exception as e:
            self.logger.error(f"Error collecting subnet group {subnet_group_name}: {str(e)}")

    def _collect_autoscaling(self, db_instance_id: str, resource: Resource):
        """Collect autoscaling configurations for RDS instance"""
        try:
            rds = self.get_client('rds')
            
            # Get scalable targets
            app_autoscaling = self.get_client('application-autoscaling')
            try:
                targets = app_autoscaling.describe_scalable_targets(
                    ServiceNamespace='rds',
                    ResourceIds=[f'db:{db_instance_id}']
                )['ScalableTargets']
                
                # Get scaling policies for each target
                for target in targets:
                    try:
                        policies = app_autoscaling.describe_scaling_policies(
                            ServiceNamespace='rds',
                            ResourceId=target['ResourceId'],
                            ScalableDimension=target['ScalableDimension']
                        )['ScalingPolicies']
                        
                        target['ScalingPolicies'] = policies
                        
                        # Save autoscaling configuration
                        file_path = self.save_resource(
                            f'rds/instances/{db_instance_id}/autoscaling',
                            target['ScalableDimension'].split(':')[-1],
                            target
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            resource.depends_on.append(f"autoscaling:policy:{target['ResourceId']}")
                            
                    except ClientError as e:
                        self.handle_aws_error('get_scaling_policies', db_instance_id, e)
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'ValidationException':
                    self.handle_aws_error('get_scalable_targets', db_instance_id, e)
                
        except Exception as e:
            self.logger.error(f"Error collecting autoscaling for instance {db_instance_id}: {str(e)}")

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
