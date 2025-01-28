from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError

from aws_resource_collector.resource_graph.graph import Resource, ResourceType
from .base import BaseScraper

class ECRScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape ECR repositories and images"""
        ecr = boto3.client('ecr')
        resources = []
        try:
            # List repositories
            paginator = ecr.get_paginator('describe_repositories')
            for page in paginator.paginate():
                for repo in page['repositories']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=repo['repositoryArn'],
                            type=ResourceType.ECR,
                            name=repo['repositoryName'],
                            env=next((tag['Value'] for tag in repo.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in repo.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get repository tags
                        tags = ecr.list_tags_for_resource(resourceArn=repo['repositoryArn'])
                        repo['Tags'] = tags['tags']
                        
                        if self.tag_filter.matches(repo):
                            file_path = self.save_resource(
                                'ecr/repositories',
                                repo['repositoryName'],
                                repo
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                
                                # Collect images for this repository
                                self._collect_images(ecr, repo['repositoryName'], resource)
                                
                                resources.append(resource)
                                
                    except ecr.exceptions.ClientError:
                        continue
                        
        except ecr.exceptions.ClientError:
            pass
        
        return resources
    
    def _collect_images(self, ecr, repository_name: str, resource: Resource):
        """Collect images for a repository"""
        try:
            paginator = ecr.get_paginator('describe_images')
            for page in paginator.paginate(repositoryName=repository_name):
                for image in page['imageDetails']:
                    file_path = self.save_resource(
                        f'ecr/repositories/{repository_name}/images',
                        image['imageDigest'].replace('sha256:', ''),
                        image
                    )
                    if file_path:
                        self.collected_files.append(file_path)

                        resource.depends_on.append(f"image:{image['imageDigest'].replace('sha256:', '')}")
                        
        except ecr.exceptions.ClientError:
            pass

class ECSScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape ECS clusters and their configurations"""
        ecs = self.get_client('ecs')
        resources = []
        try:
            paginator = ecs.get_paginator('list_clusters')
            for page in paginator.paginate():
                for cluster_arn in page['clusterArns']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=cluster_arn,
                            type=ResourceType.ECS,
                            name=cluster_arn,
                            env=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get cluster details
                        cluster = ecs.describe_clusters(
                            clusters=[cluster_arn],
                            include=['TAGS']
                        )['clusters'][0]
                        
                        if self.tag_filter.matches(cluster):
                            # Collect services and tasks
                            self._collect_services(ecs, cluster_arn, resource)
                            self._collect_tasks(ecs, cluster_arn, resource)
                            
                            # Save cluster
                            file_path = self.save_resource(
                                'ecs/clusters',
                                cluster['clusterName'],
                                cluster
                            )
                            if file_path:
                                self.collected_files.append(file_path)

                                resources.append(resource)
                    except ClientError as e:
                        self.handle_aws_error('process_cluster', cluster_arn, e)
                        
        except ClientError as e:
            self.handle_aws_error('list_clusters', 'all', e)
            
        return resources

    def _collect_services(self, ecs, cluster_arn: str, resource: Resource):
        """Collect ECS services and their related resources"""
        try:
            paginator = ecs.get_paginator('list_services')
            for page in paginator.paginate(cluster=cluster_arn):
                if page['serviceArns']:
                    services = ecs.describe_services(
                        cluster=cluster_arn,
                        services=page['serviceArns'],
                        include=['TAGS']
                    )['services']
                    
                    for service in services:
                        try:
                            if self.tag_filter.matches(service):
                                # Collect related resources
                                self._collect_service_resources(service, resource)
                                
                                # Save service
                                file_path = self.save_resource(
                                    'ecs/services',
                                    service['serviceName'],
                                    service
                                )
                                if file_path:
                                    self.collected_files.append(file_path)

                                    resource.depends_on.append(f"service:{service['serviceName']}")
                        except ClientError as e:
                            self.handle_aws_error('process_service', service['serviceName'], e)
                            
        except ClientError as e:
            self.handle_aws_error('list_services', cluster_arn, e)

    def _collect_tasks(self, ecs, cluster_arn: str, resource: Resource):
        """Collect ECS tasks and their related resources"""
        try:
            paginator = ecs.get_paginator('list_tasks')
            for page in paginator.paginate(cluster=cluster_arn):
                if page['taskArns']:
                    tasks = ecs.describe_tasks(
                        cluster=cluster_arn,
                        tasks=page['taskArns'],
                        include=['TAGS']
                    )['tasks']
                    
                    for task in tasks:
                        try:
                            if self.tag_filter.matches(task):
                                # Collect related resources
                                self._collect_task_resources(task, resource)
                                
                                # Save task
                                file_path = self.save_resource(
                                    'ecs/tasks',
                                    task['taskArn'].split('/')[-1],
                                    task
                                )
                                if file_path:
                                    self.collected_files.append(file_path)

                                    resource.depends_on.append(f"task:{task['taskArn'].split('/')[-1]}")
                                    
                        except ClientError as e:
                            self.handle_aws_error('process_task', task['taskArn'], e)
                            
        except ClientError as e:
            self.handle_aws_error('list_tasks', cluster_arn, e)

    def _collect_service_resources(self, service: Dict[str, Any], resource: Resource):
        """Collect resources related to ECS service"""
        try:
            # Collect VPC resources
            if 'networkConfiguration' in service:
                config = service['networkConfiguration']['awsvpcConfiguration']
                for subnet_id in config.get('subnets', []):
                    self.related.collect_subnet(subnet_id)
                for sg_id in config.get('securityGroups', []):
                    self.related.collect_security_group(sg_id)

            # Collect load balancer resources
            for lb in service.get('loadBalancers', []):
                if 'targetGroupArn' in lb:
                    self.related.collect_target_group(lb['targetGroupArn'])

            # Collect task definition
            if service.get('taskDefinition'):
                self._collect_task_definition(service['taskDefinition'], resource)

            # Collect IAM roles
            if service.get('roleArn'):
                role_name = service['roleArn'].split('/')[-1]
                self.related.collect_iam_role(role_name)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for service {service.get('serviceName')}: {str(e)}")

    def _collect_task_resources(self, task: Dict[str, Any], resource: Resource):
        """Collect resources related to ECS task"""
        try:
            # Collect VPC resources
            if 'attachments' in task:
                for attachment in task['attachments']:
                    if attachment['type'] == 'ElasticNetworkInterface':
                        for detail in attachment['details']:
                            if detail['name'] == 'subnetId':
                                self.related.collect_subnet(detail['value'])
                            elif detail['name'] == 'networkInterfaceId':
                                self.related.collect_network_interface(detail['value'])

            # Collect task definition
            if task.get('taskDefinitionArn'):
                self._collect_task_definition(task['taskDefinitionArn'], resource)

            # Collect container instance
            if task.get('containerInstanceArn'):
                self._collect_container_instance(task['containerInstanceArn'], task['clusterArn'], resource)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for task {task.get('taskArn')}: {str(e)}")

    def _collect_task_definition(self, task_def_arn: str, resource: Resource):
        """Collect task definition and related resources"""
        try:
            ecs = self.get_client('ecs')
            task_def = ecs.describe_task_definition(
                taskDefinition=task_def_arn,
                include=['TAGS']
            )['taskDefinition']
            
            # Collect execution role
            if task_def.get('executionRoleArn'):
                role_name = task_def['executionRoleArn'].split('/')[-1]
                self.related.collect_iam_role(role_name)

            # Collect task role
            if task_def.get('taskRoleArn'):
                role_name = task_def['taskRoleArn'].split('/')[-1]
                self.related.collect_iam_role(role_name)

            # Save task definition
            file_path = self.save_resource(
                'ecs/task_definitions',
                task_def['family'],
                task_def
            )
            if file_path:
                self.collected_files.append(file_path)

                resource.depends_on.append(f"task_definition:{task_def['family']}")
        except ClientError as e:
            self.handle_aws_error('get_task_definition', task_def_arn, e)

    def _collect_container_instance(self, instance_arn: str, cluster_arn: str, resource: Resource):
        """Collect container instance and related resources"""
        try:
            ecs = self.get_client('ecs')
            instance = ecs.describe_container_instances(
                cluster=cluster_arn,
                containerInstances=[instance_arn],
                include=['TAGS']
            )['containerInstances'][0]
            
            # Collect EC2 instance
            if instance.get('ec2InstanceId'):
                self.related.collect_ec2_instance(instance['ec2InstanceId'])

            # Save container instance
            file_path = self.save_resource(
                'ecs/container_instances',
                instance['containerInstanceArn'].split('/')[-1],
                instance
            )
            if file_path:
                self.collected_files.append(file_path)

                resource.depends_on.append(f"ec2:instance:{instance['ec2InstanceId']}")
        except ClientError as e:
            self.handle_aws_error('get_container_instance', instance_arn, e)

class EKSCollector(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Collect EKS clusters and their configurations"""
        eks = self.get_client('eks')
        resources = []
        
        try:
            paginator = eks.get_paginator('list_clusters')
            for page in paginator.paginate():
                for cluster_name in page['clusters']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=cluster_name,
                            type=ResourceType.EKS,
                            name=cluster_name,
                            env=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in cluster.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get cluster details
                        cluster = eks.describe_cluster(name=cluster_name)['cluster']
                        
                        # Get cluster tags
                        tags = eks.list_tags_for_resource(
                            resourceArn=cluster['arn']
                        )
                        cluster['tags'] = tags['tags']
                        
                        if self.tag_filter.matches(cluster):
                            # Collect VPC resources
                            for subnet_id in cluster['resourcesVpcConfig']['subnetIds']:
                                self.related.collect_subnet(subnet_id)
                            for sg_id in cluster['resourcesVpcConfig'].get('securityGroupIds', []):
                                self.related.collect_security_group(sg_id)
                            
                            # Collect cluster role
                            if cluster.get('roleArn'):
                                role_name = cluster['roleArn'].split('/')[-1]
                                self.related.collect_iam_role(role_name)
                            
                            # Collect encryption key
                            if cluster.get('encryptionConfig'):
                                for config in cluster['encryptionConfig']:
                                    if config.get('provider', {}).get('keyArn'):
                                        key_id = config['provider']['keyArn'].split('key/')[-1]
                                        self.related.collect_kms_key(key_id)
                            
                            # Collect node groups
                            self._collect_node_groups(eks, cluster_name, resource)
                            
                            # Collect Fargate profiles
                            if self.settings.collector.include_global:
                                self._collect_fargate_profiles(eks, cluster_name, resource)
                            
                            # Save cluster
                            file_path = self.save_resource(
                                'eks/clusters',
                                cluster_name,
                                cluster
                            )
                            if file_path:
                                self.collected_files.append(file_path)

                                resources.append(resource)
                    except ClientError as e:
                        self.handle_aws_error('process_cluster', cluster_name, e)
                    except Exception as e:
                        self.logger.error(f"Error processing cluster {cluster_name}: {str(e)}")
                        
        except ClientError as e:
            self.handle_aws_error('list_clusters', 'all', e)
        except Exception as e:
            self.logger.error(f"Error collecting EKS clusters: {str(e)}")
            
        return resources
    
    def _collect_node_groups(self, eks, cluster_name: str, resource: Resource):
        """Collect EKS node groups and related resources"""
        try:
            paginator = eks.get_paginator('list_nodegroups')
            for page in paginator.paginate(clusterName=cluster_name):
                for group_name in page['nodegroups']:
                    try:
                        group = eks.describe_nodegroup(
                            clusterName=cluster_name,
                            nodegroupName=group_name
                        )['nodegroup']
                        
                        # Collect node role
                        if group.get('nodeRole'):
                            role_name = group['nodeRole'].split('/')[-1]
                            self.related.collect_iam_role(role_name)
                        
                        # Collect launch template
                        if group.get('launchTemplate'):
                            self.related.collect_launch_template(
                                group['launchTemplate']['id']
                            )
                        
                        # Save node group
                        file_path = self.save_resource(
                            f'eks/clusters/{cluster_name}/nodegroups',
                            group_name,
                            group
                        )
                        if file_path:
                            self.collected_files.append(file_path)

                            resource.depends_on.append(f"eks:cluster:{cluster_name}:nodegroup:{group_name}")
                            
                    except ClientError as e:
                        self.handle_aws_error('process_nodegroup', group_name, e)
                    except Exception as e:
                        self.logger.error(f"Error processing node group {group_name}: {str(e)}")
                        
        except ClientError as e:
            self.handle_aws_error('list_nodegroups', cluster_name, e)
        except Exception as e:
            self.logger.error(f"Error collecting node groups for cluster {cluster_name}: {str(e)}")
    
    def _collect_fargate_profiles(self, eks, cluster_name: str, resource: Resource):
        """Collect Fargate profiles and related resources"""
        try:
            paginator = eks.get_paginator('list_fargate_profiles')
            for page in paginator.paginate(clusterName=cluster_name):
                for profile_name in page['fargateProfileNames']:
                    try:
                        profile = eks.describe_fargate_profile(
                            clusterName=cluster_name,
                            fargateProfileName=profile_name
                        )['fargateProfile']
                        
                        # Collect pod execution role
                        if profile.get('podExecutionRoleArn'):
                            role_name = profile['podExecutionRoleArn'].split('/')[-1]
                            self.related.collect_iam_role(role_name)
                        
                        # Collect subnets
                        for subnet_id in profile['subnets']:
                            self.related.collect_subnet(subnet_id)
                        
                        # Save profile
                        file_path = self.save_resource(
                            f'eks/clusters/{cluster_name}/fargate_profiles',
                            profile_name,
                            profile
                        )
                        if file_path:
                            self.collected_files.append(file_path)

                            resource.depends_on.append(f"eks:cluster:{cluster_name}:fargate_profile:{profile_name}")
                    except ClientError as e:
                        self.handle_aws_error('process_fargate_profile', profile_name, e)
                    except Exception as e:
                        self.logger.error(f"Error processing Fargate profile {profile_name}: {str(e)}")
                        
        except ClientError as e:
            self.handle_aws_error('list_fargate_profiles', cluster_name, e)
        except Exception as e:
            self.logger.error(f"Error collecting Fargate profiles for cluster {cluster_name}: {str(e)}") 