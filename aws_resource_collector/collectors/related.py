from typing import Set, Dict, Any
import boto3
import json
import traceback

from aws_resource_collector.resource_graph.graph import Resource
from .base import BaseScraper
from botocore.exceptions import ClientError

class RelatedResourceScraper:
    """Helper class to scrape related resources"""
    
    def __init__(self, scraper: BaseScraper):
        self.scraper = scraper
        self.resource = None
        self.scraped_resources = set()
    
    def set_resource(self, resource: Resource):
        self.resource = resource
    
    def collect_subnet(self, subnet_id: str) -> None:
        """Collect subnet and its configurations"""
        if subnet_id in self.scraped_resources:
            return
            
        try:
            ec2 = self.scraper.get_client('ec2')
            response = ec2.describe_subnets(SubnetIds=[subnet_id])
            if response['Subnets']:
                subnet = response['Subnets'][0]
                
                # Collect subnet configuration
                self.scraper.save_resource(
                    'ec2/subnets',
                    subnet_id,
                    subnet
                )

                self.resource.depends_on.append(f"subnet:{subnet_id}")
                
                # Collect route tables and NACLs if enabled
                if self.scraper.settings.scraper.include_global:
                    self._scrape_subnet_route_tables(ec2, subnet_id)
                    self._scrape_subnet_nacls(ec2, subnet_id)
                
                self.scraped_resources.add(subnet_id)
                
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related subnet {subnet_id}: {str(e)}")
    
    def collect_security_group(self, group_id: str) -> None:
        """Collect security group and its rules"""
        if group_id in self.scraped_resources:
            return
            
        try:
            ec2 = self.scraper.get_client('ec2')
            response = ec2.describe_security_groups(GroupIds=[group_id])
            if response['SecurityGroups']:
                sg = response['SecurityGroups'][0]
                
                # Collect security group
                self.scraper.save_resource(
                    'ec2/security_groups',
                    group_id,
                    sg
                )

                self.resource.depends_on.append(f"security_group:{group_id}")
                
                # Collect referenced security groups
                for rule in sg.get('IpPermissions', []) + sg.get('IpPermissionsEgress', []):
                    for ref in rule.get('UserIdGroupPairs', []):
                        self.collect_security_group(ref['GroupId'])
                
                self.scraped_resources.add(group_id)
                
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related security group {group_id}: {str(e)}")
        
    def collect_kms_key(self, key_id: str) -> None:
        """Collect KMS key and its details"""
        try:
            kms = self.scraper.get_client('kms')
            
            # Extract key ID from ARN if needed
            if key_id.startswith('arn:aws:kms'):
                key_id = key_id.split('key/')[-1]
            # Handle key aliases
            elif key_id.startswith('alias/'):
                try:
                    alias_response = kms.describe_key(KeyId=key_id)
                    key_id = alias_response['KeyMetadata']['KeyId']
                except ClientError as e:
                    self.scraper.handle_aws_error('describe_key', key_id, e)
                    return

            # Get key details
            try:
                key = kms.describe_key(KeyId=key_id)['KeyMetadata']
                
                # Get key tags
                try:
                    tags = kms.list_resource_tags(KeyId=key_id)
                    key['Tags'] = tags.get('Tags', [])
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidArnException':
                        self.scraper.handle_aws_error('list_resource_tags', key_id, e)
                
                # Get key policy
                try:
                    policy = kms.get_key_policy(
                        KeyId=key_id,
                        PolicyName='default'
                    )
                    key['Policy'] = policy['Policy']
                except ClientError as e:
                    self.scraper.handle_aws_error('get_key_policy', key_id, e)
                
                # Get key grants
                try:
                    grants = kms.list_grants(KeyId=key_id)
                    key['Grants'] = grants.get('Grants', [])
                except ClientError as e:
                    self.scraper.handle_aws_error('list_grants', key_id, e)
                
                # Save key
                file_path = self.scraper.save_resource(
                    'kms/keys',
                    key['KeyId'],
                    key
                )
                self.resource.depends_on.append(f"kms:{key_id}")
                if file_path:
                    self.scraper.scraped_files.append(file_path)
                    self.scraped_resources.add(key_id)
                    
            except ClientError as e:
                self.scraper.handle_aws_error('describe_key', key_id, e)
                
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related KMS key {key_id}: {str(e)}")
    
    def collect_iam_role(self, role_name: str) -> None:
        """Collect IAM role and its policies"""
        if role_name in self.scraped_resources:
            return
            
        try:
            iam = self.scraper.get_client('iam')
            
            # Get role
            role = iam.get_role(RoleName=role_name)['Role']
            
            # Get attached policies
            if self.scraper.settings.scraper.include_global:
                policies = iam.list_attached_role_policies(RoleName=role_name)
                role['AttachedPolicies'] = policies['AttachedPolicies']
                
                # Get inline policies
                inline = iam.list_role_policies(RoleName=role_name)
                role['InlinePolicies'] = {}
                for policy_name in inline['PolicyNames']:
                    policy = iam.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    role['InlinePolicies'][policy_name] = policy['PolicyDocument']
            
            # Save role
            self.scraper.save_resource(
                'iam/roles',
                role_name,
                role
            )

            self.resource.depends_on.append(f"iam:role:{role_name}")
            
            self.scraped_resources.add(role_name)
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related IAM role {role_name}: {str(e)}")
    
    def _collect_iam_from_policy(self, policy: Dict[str, Any]) -> None:
        """Extract and collect IAM principals from policy"""
        try:
            # Parse policy and extract principals
            if isinstance(policy, str):
                import json
                policy = json.loads(policy)
            
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                if isinstance(principal, dict):
                    # Collect IAM roles
                    for role_arn in principal.get('AWS', []):
                        if ':role/' in role_arn:
                            role_name = role_arn.split('/')[-1]
                            self.collect_iam_role(role_name)
                            self.resource.depends_on.append(f"iam:role:{role_name}")
        except Exception as e:
            self.scraper.logger.error(f"Error extracting IAM from policy: {str(e)}")

    def _scrape_subnet_route_tables(self, ec2, subnet_id: str) -> None:
        """Collect route tables associated with subnet"""
        try:
            response = ec2.describe_route_tables(
                Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
            )
            for rt in response['RouteTables']:
                self.scraper.save_resource(
                    'ec2/route_tables',
                    rt['RouteTableId'],
                    rt
                )
                self.resource.depends_on.append(f"route_table:{rt['RouteTableId']}")
                self.scraped_resources.add(rt['RouteTableId'])
        except Exception as e:
            self.scraper.logger.error(f"Error collecting route tables for subnet {subnet_id}: {str(e)}")

    def _scrape_subnet_nacls(self, ec2, subnet_id: str) -> None:
        """Collect network ACLs associated with subnet"""
        try:
            response = ec2.describe_network_acls(
                Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
            )
            for nacl in response['NetworkAcls']:
                self.scraper.save_resource(
                    'ec2/network_acls',
                    nacl['NetworkAclId'],
                    nacl
                )
                self.resource.depends_on.append(f"network_acl:{nacl['NetworkAclId']}")
                self.scraped_resources.add(nacl['NetworkAclId'])
        except Exception as e:
            self.scraper.logger.error(f"Error collecting NACLs for subnet {subnet_id}: {str(e)}")

    def collect_sqs_queue(self, queue_arn: str) -> None:
        """Collect SQS queue and its configurations"""
        if queue_arn in self.scraped_resources:
            return
        
        try:
            sqs = self.scraper.get_client('sqs')
            
            # Parse queue ARN to get region and account
            # arn:aws:sqs:region:account-id:queue-name
            parts = queue_arn.split(':')
            if len(parts) != 6:
                self.scraper.logger.warning(f"Invalid SQS queue ARN format: {queue_arn}")
                return
            
            region = parts[3]
            account_id = parts[4]
            queue_name = parts[5]
            
            # If queue is in different region, get regional client
            if region != self.scraper.settings.aws.region:
                sqs = boto3.client('sqs', region_name=region)
            
            # Get queue URL using account ID and name
            try:
                queue_url = sqs.get_queue_url(
                    QueueName=queue_name,
                    QueueOwnerAWSAccountId=account_id
                )['QueueUrl']
            except ClientError as e:
                if e.response['Error']['Code'] == 'AWS.SimpleQueueService.NonExistentQueue':
                    self.scraper.logger.warning(f"SQS queue does not exist: {queue_arn}")
                    return
                raise
            
            # Get queue attributes
            attributes = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=['All']
            )['Attributes']
            
            # Get queue tags
            try:
                tags = sqs.list_queue_tags(QueueUrl=queue_url)
                attributes['Tags'] = tags.get('Tags', {})
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidRequest':  # No tags
                    raise
                
            # Save queue
            self.scraper.save_resource(
                'sqs/queues',
                queue_name,
                attributes
            )
            self.scraped_resources.add(queue_arn)
            
            self.resource.depends_on.append(f"sqs:queue:{queue_name}")
            
            # Collect KMS key if encrypted
            if attributes.get('KmsMasterKeyId'):
                self.collect_kms_key(attributes['KmsMasterKeyId'])
            
            # Collect dead-letter queue if configured
            if attributes.get('RedrivePolicy'):
                redrive = json.loads(attributes['RedrivePolicy'])
                if redrive.get('deadLetterTargetArn'):
                    self.collect_sqs_queue(redrive['deadLetterTargetArn'])
                
        except ClientError as e:
            self.scraper.handle_aws_error('process_queue', queue_arn, e)
        except Exception as e:
            self.scraper.logger.error(
                f"Error collecting related SQS queue {queue_arn}: {str(e)}\n"
                f"Traceback:\n{traceback.format_exc()}"
            )

    def collect_state_machine(self, state_machine_arn: str) -> None:
        """Collect Step Functions state machine and related resources"""
        if state_machine_arn in self.scraped_resources:
            return
            
        try:
            sfn = self.scraper.get_client('stepfunctions')
            
            # Get state machine
            machine = sfn.describe_state_machine(
                stateMachineArn=state_machine_arn
            )
            
            # Get tags
            tags = sfn.list_tags_for_resource(
                resourceArn=state_machine_arn
            )
            machine['Tags'] = tags['tags']
            
            # Collect IAM role
            if machine.get('roleArn'):
                role_name = machine['roleArn'].split('/')[-1]
                self.collect_iam_role(role_name)
            
            # Save state machine
            self.scraper.save_resource(
                'stepfunctions/state_machines',
                machine['name'],
                machine
            )
            self.scraped_resources.add(state_machine_arn)
            
            self.resource.depends_on.append(f"stepfunctions:{state_machine_arn}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related state machine {state_machine_arn}: {str(e)}")

    def collect_rds_instance(self, instance_arn: str) -> None:
        """Collect RDS instance and related resources"""
        if instance_arn in self.scraped_resources:
            return
            
        try:
            rds = self.scraper.get_client('rds')
            instance = rds.describe_db_instances(
                DBInstanceIdentifier=instance_arn.split(':')[-1]
            )['DBInstances'][0]
            
            # Collect related resources
            if 'DBSubnetGroup' in instance:
                for subnet in instance['DBSubnetGroup']['Subnets']:
                    self.collect_subnet(subnet['SubnetIdentifier'])
            
            for sg in instance.get('VpcSecurityGroups', []):
                self.collect_security_group(sg['VpcSecurityGroupId'])
            
            if instance.get('KmsKeyId'):
                self.collect_kms_key(instance['KmsKeyId'])
            
            # Save instance
            self.scraper.save_resource(
                'rds/instances',
                instance['DBInstanceIdentifier'],
                instance
            )
            self.scraped_resources.add(instance_arn)
            
            self.resource.depends_on.append(f"rds:{instance_arn}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related RDS instance {instance_arn}: {str(e)}")

    def collect_elasticache_cluster(self, cluster_arn: str) -> None:
        """Collect ElastiCache cluster and related resources"""
        if cluster_arn in self.scraped_resources:
            return
            
        try:
            elasticache = self.scraper.get_client('elasticache')
            cluster = elasticache.describe_cache_clusters(
                CacheClusterId=cluster_arn.split(':')[-1]
            )['CacheClusters'][0]
            
            # Collect related resources
            if 'CacheSubnetGroup' in cluster:
                subnet_group = elasticache.describe_cache_subnet_groups(
                    CacheSubnetGroupName=cluster['CacheSubnetGroup']['CacheSubnetGroupName']
                )['CacheSubnetGroups'][0]
                
                for subnet in subnet_group['Subnets']:
                    self.collect_subnet(subnet['SubnetIdentifier'])
            
            for sg in cluster.get('SecurityGroups', []):
                self.collect_security_group(sg['SecurityGroupId'])
            
            # Save cluster
            self.scraper.save_resource(
                'elasticache/clusters',
                cluster['CacheClusterId'],
                cluster
            )
            self.scraped_resources.add(cluster_arn)
            
            self.resource.depends_on.append(f"elasticache:{cluster_arn}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related ElastiCache cluster {cluster_arn}: {str(e)}")

    def collect_ebs_volume(self, volume_id: str) -> None:
        """Collect EBS volume and its configurations"""
        if volume_id in self.scraped_resources:
            return
        
        try:
            ec2 = self.scraper.get_client('ec2')
            response = ec2.describe_volumes(VolumeIds=[volume_id])
            if response['Volumes']:
                volume = response['Volumes'][0]
                
                # Collect KMS key if encrypted
                if volume.get('KmsKeyId'):
                    self.collect_kms_key(volume['KmsKeyId'])
                
                # Save volume
                self.scraper.save_resource(
                    'ec2/volumes',
                    volume_id,
                    volume
                )
                self.scraped_resources.add(volume_id)
                
                self.resource.depends_on.append(f"ec2:volume:{volume_id}")
                
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related EBS volume {volume_id}: {str(e)}")

    def collect_network_interface(self, eni_id: str) -> None:
        """Collect network interface and its configurations"""
        if eni_id in self.scraped_resources:
            return
        
        try:
            ec2 = self.scraper.get_client('ec2')
            response = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
            if response['NetworkInterfaces']:
                eni = response['NetworkInterfaces'][0]
                
                # Collect related resources
                if 'SubnetId' in eni:
                    self.collect_subnet(eni['SubnetId'])
                for group in eni.get('Groups', []):
                    self.collect_security_group(group['GroupId'])
                
                # Save network interface
                self.scraper.save_resource(
                    'ec2/network_interfaces',
                    eni_id,
                    eni
                )
                self.scraped_resources.add(eni_id)
                
                self.resource.depends_on.append(f"ec2:network_interface:{eni_id}")
                
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related network interface {eni_id}: {str(e)}")

    def collect_target_group(self, target_group_arn: str) -> None:
        """Collect target group and its configurations"""
        if target_group_arn in self.scraped_resources:
            return
        
        try:
            elbv2 = self.scraper.get_client('elbv2')
            
            # Get target group details
            target_group = elbv2.describe_target_groups(
                TargetGroupArns=[target_group_arn]
            )['TargetGroups'][0]
            
            # Get target group attributes
            attributes = elbv2.describe_target_group_attributes(
                TargetGroupArn=target_group_arn
            )
            target_group['Attributes'] = attributes['Attributes']
            
            # Get target health
            try:
                health = elbv2.describe_target_health(
                    TargetGroupArn=target_group_arn
                )
                target_group['TargetHealth'] = health['TargetHealthDescriptions']
            except ClientError as e:
                if e.response['Error']['Code'] != 'TargetGroupNotFound':
                    self.scraper.handle_aws_error('get_target_health', target_group_arn, e)
            
            # Get tags
            try:
                tags = elbv2.describe_tags(
                    ResourceArns=[target_group_arn]
                )['TagDescriptions'][0]['Tags']
                target_group['Tags'] = tags
            except ClientError as e:
                if e.response['Error']['Code'] != 'TargetGroupNotFound':
                    self.scraper.handle_aws_error('get_tags', target_group_arn, e)
            
            # Collect related resources
            if target_group.get('VpcId'):
                for target in target_group.get('TargetHealth', []):
                    if target.get('Target', {}).get('Id'):
                        target_id = target['Target']['Id']
                        if target_id.startswith('i-'):  # EC2 instance
                            self.collect_ec2_instance(target_id)
                        elif target_id.startswith('eni-'):  # Network interface
                            self.collect_network_interface(target_id)
                        elif target_id.startswith('ip-'):  # IP address
                            continue  # No related resource to collect for IP targets
            
            # Save target group
            self.scraper.save_resource(
                'elbv2/target_groups',
                target_group_arn.split('/')[-1],
                target_group
            )
            self.scraped_resources.add(target_group_arn)
            
            self.resource.depends_on.append(f"elbv2:{target_group_arn}")
            
        except ClientError as e:
            self.scraper.handle_aws_error('describe_target_group', target_group_arn, e)
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related target group {target_group_arn}: {str(e)}")

    def collect_lambda_function(self, function_arn: str) -> None:
        """Collect Lambda function and its configurations"""
        if function_arn in self.scraped_resources:
            return
        
        try:
            lambda_client = self.scraper.get_client('lambda')
            
            # Extract function name from ARN
            function_name = function_arn.split(':')[-1]
            
            # Get function details
            function = lambda_client.get_function(FunctionName=function_name)['Configuration']
            
            # Get function tags
            tags = lambda_client.list_tags(Resource=function_arn)
            function['Tags'] = tags['Tags']
            
            # Collect related resources
            if 'VpcConfig' in function:
                for subnet_id in function['VpcConfig'].get('SubnetIds', []):
                    self.collect_subnet(subnet_id)
                for sg_id in function['VpcConfig'].get('SecurityGroupIds', []):
                    self.collect_security_group(sg_id)
            
            if function.get('KMSKeyArn'):
                self.collect_kms_key(function['KMSKeyArn'])
            
            if function.get('Role'):
                role_name = function['Role'].split('/')[-1]
                self.collect_iam_role(role_name)
            
            # Save function
            self.scraper.save_resource(
                'lambda/functions',
                function_name,
                function
            )
            self.scraped_resources.add(function_arn)
            
            self.resource.depends_on.append(f"lambda:{function_arn}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related Lambda function {function_arn}: {str(e)}")

    def collect_lambda_layer(self, layer_arn: str) -> None:
        """Collect Lambda layer and its versions"""
        if layer_arn in self.scraped_resources:
            return
        
        try:
            lambda_client = self.scraper.get_client('lambda')
            
            # Extract layer name and version
            layer_parts = layer_arn.split(':')
            layer_name = layer_parts[-2]
            version = int(layer_parts[-1])
            
            # Get layer version details
            layer = lambda_client.get_layer_version(
                LayerName=layer_name,
                VersionNumber=version
            )
            
            # Save layer
            self.scraper.save_resource(
                'lambda/layers',
                f"{layer_name}/{version}",
                layer
            )
            self.scraped_resources.add(layer_arn)
            
            self.resource.depends_on.append(f"lambda:{layer_arn}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related Lambda layer {layer_arn}: {str(e)}")

    def collect_dynamodb_stream(self, stream_arn: str) -> None:
        """Collect DynamoDB stream and its configurations"""
        if stream_arn in self.scraped_resources:
            return
        
        try:
            dynamodb = self.scraper.get_client('dynamodbstreams')
            
            # Get stream description
            stream = dynamodb.describe_stream(StreamArn=stream_arn)['StreamDescription']
            
            # Save stream
            self.scraper.save_resource(
                'dynamodb/streams',
                stream['StreamId'],
                stream
            )
            self.scraped_resources.add(stream_arn)
            
            self.resource.depends_on.append(f"dynamodb:{stream_arn}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related DynamoDB stream {stream_arn}: {str(e)}")

    def collect_kinesis_stream(self, stream_arn: str) -> None:
        """Collect Kinesis stream and its configurations"""
        if stream_arn in self.scraped_resources:
            return
        
        try:
            kinesis = self.scraper.get_client('kinesis')
            
            # Extract stream name from ARN
            stream_name = stream_arn.split('/')[-1]
            
            # Get stream description
            stream = kinesis.describe_stream(StreamName=stream_name)['StreamDescription']
            
            # Get stream tags
            tags = kinesis.list_tags_for_stream(StreamName=stream_name)
            stream['Tags'] = tags['Tags']
            
            # Collect KMS key if encrypted
            if stream.get('EncryptionType') == 'KMS':
                self.collect_kms_key(stream['KeyId'])
            
            # Save stream
            self.scraper.save_resource(
                'kinesis/streams',
                stream_name,
                stream
            )
            self.scraped_resources.add(stream_arn)
            
            self.resource.depends_on.append(f"kinesis:{stream_arn}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related Kinesis stream {stream_arn}: {str(e)}")

    def collect_kafka_topic(self, topic_arn: str) -> None:
        """Collect MSK topic and its configurations"""
        if topic_arn in self.scraped_resources:
            return
        
        try:
            kafka = self.scraper.get_client('kafka')
            
            # Extract cluster ARN and topic name
            cluster_arn = ':'.join(topic_arn.split(':')[:-1])
            topic_name = topic_arn.split(':')[-1]
            
            # Get cluster description
            cluster = kafka.describe_cluster(ClusterArn=cluster_arn)['ClusterInfo']
            
            # Get cluster tags
            tags = kafka.list_tags_for_resource(ResourceArn=cluster_arn)
            cluster['Tags'] = tags['Tags']
            
            # Collect related resources
            for subnet_id in cluster.get('BrokerNodeGroupInfo', {}).get('ClientSubnets', []):
                self.collect_subnet(subnet_id)
            
            for sg_id in cluster.get('BrokerNodeGroupInfo', {}).get('SecurityGroups', []):
                self.collect_security_group(sg_id)
            
            if cluster.get('EncryptionInfo', {}).get('EncryptionAtRest', {}).get('DataVolumeKMSKeyId'):
                self.collect_kms_key(cluster['EncryptionInfo']['EncryptionAtRest']['DataVolumeKMSKeyId'])
            
            # Save cluster and topic info
            self.scraper.save_resource(
                'kafka/clusters',
                cluster_arn.split('/')[-1],
                {
                    'Cluster': cluster,
                    'Topic': topic_name
                }
            )
            self.scraped_resources.add(topic_arn)
            
            self.resource.depends_on.append(f"kafka:{topic_arn}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related Kafka topic {topic_arn}: {str(e)}")

    def collect_launch_template(self, template_id: str) -> None:
        """Collect EC2 launch template and its configurations"""
        if template_id in self.scraped_resources:
            return
        
        try:
            ec2 = self.scraper.get_client('ec2')
            
            # Get template details
            template = ec2.describe_launch_templates(LaunchTemplateIds=[template_id])['LaunchTemplates'][0]
            
            # Get latest version details
            version = ec2.describe_launch_template_versions(
                LaunchTemplateId=template_id,
                Versions=['$Latest']
            )['LaunchTemplateVersions'][0]
            
            template['LatestVersion'] = version
            
            # Save template
            self.scraper.save_resource(
                'ec2/launch_templates',
                template_id,
                template
            )
            self.scraped_resources.add(template_id)
            
            self.resource.depends_on.append(f"ec2:launch_template:{template_id}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related launch template {template_id}: {str(e)}")

    def collect_ec2_instance(self, instance_id: str) -> None:
        """Collect EC2 instance and its configurations"""
        if instance_id in self.scraped_resources:
            return
        
        try:
            ec2 = self.scraper.get_client('ec2')
            
            # Get instance details
            instance = ec2.describe_instances(InstanceIds=[instance_id])['Reservations'][0]['Instances'][0]
            
            # Collect related resources
            if 'SubnetId' in instance:
                self.collect_subnet(instance['SubnetId'])
            
            for sg in instance.get('SecurityGroups', []):
                self.collect_security_group(sg['GroupId'])
            
            for device in instance.get('BlockDeviceMappings', []):
                if 'Ebs' in device:
                    self.collect_ebs_volume(device['Ebs']['VolumeId'])
            
            for eni in instance.get('NetworkInterfaces', []):
                self.collect_network_interface(eni['NetworkInterfaceId'])
            
            if 'IamInstanceProfile' in instance:
                profile_arn = instance['IamInstanceProfile']['Arn']
                role_name = profile_arn.split('/')[-1]
                self.collect_iam_role(role_name)
            
            # Save instance
            self.scraper.save_resource(
                'ec2/instances',
                instance_id,
                instance
            )
            self.scraped_resources.add(instance_id)
            
            self.resource.depends_on.append(f"ec2:instance:{instance_id}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related EC2 instance {instance_id}: {str(e)}")

    def collect_iam_user(self, user_name: str) -> None:
        """Collect IAM user and their configurations"""
        if user_name in self.scraped_resources:
            return
        
        try:
            iam = self.scraper.get_client('iam')
            
            # Get user details
            user = iam.get_user(UserName=user_name)['User']
            
            # Get user tags
            try:
                tags = iam.list_user_tags(UserName=user_name)
                user['Tags'] = tags['Tags']
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    self.scraper.handle_aws_error('list_user_tags', user_name, e)
            
            if self.scraper.settings.scraper.include_global:
                # Get attached policies
                policies = iam.list_attached_user_policies(UserName=user_name)
                user['AttachedPolicies'] = policies['AttachedPolicies']
                
                # Get inline policies
                inline = iam.list_user_policies(UserName=user_name)
                user['InlinePolicies'] = {}
                for policy_name in inline['PolicyNames']:
                    policy = iam.get_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name
                    )
                    user['InlinePolicies'][policy_name] = policy['PolicyDocument']
                
                # Get access keys (without secret keys)
                keys = iam.list_access_keys(UserName=user_name)
                user['AccessKeys'] = keys['AccessKeyMetadata']
                
                # Get MFA devices
                mfa = iam.list_mfa_devices(UserName=user_name)
                user['MFADevices'] = mfa['MFADevices']
                
                # Get groups
                groups = iam.list_groups_for_user(UserName=user_name)
                user['Groups'] = groups['Groups']
                
                # Get SSH public keys
                try:
                    ssh_keys = iam.list_ssh_public_keys(UserName=user_name)
                    user['SSHPublicKeys'] = ssh_keys['SSHPublicKeys']
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchEntity':
                        self.scraper.handle_aws_error('list_ssh_keys', user_name, e)
                
                # Get service-specific credentials
                try:
                    service_creds = iam.list_service_specific_credentials(UserName=user_name)
                    user['ServiceSpecificCredentials'] = service_creds['ServiceSpecificCredentials']
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchEntity':
                        self.scraper.handle_aws_error('list_service_creds', user_name, e)
            
            # Save user
            self.scraper.save_resource(
                'iam/users',
                user_name,
                user
            )
            self.scraped_resources.add(user_name)
            
            self.resource.depends_on.append(f"iam:user:{user_name}")
            
        except ClientError as e:
            self.scraper.handle_aws_error('get_user', user_name, e)
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related IAM user {user_name}: {str(e)}")

    def collect_ecs_cluster(self, cluster_arn: str) -> None:
        """Collect ECS cluster and its configurations"""
        if cluster_arn in self.scraped_resources:
            return
        
        try:
            ecs = self.scraper.get_client('ecs')
            
            # Get cluster details
            cluster = ecs.describe_clusters(
                clusters=[cluster_arn],
                include=['TAGS', 'CONFIGURATIONS', 'SETTINGS']
            )['clusters'][0]
            
            # Collect related resources
            if cluster.get('configuration'):
                # Collect execution role
                if cluster['configuration'].get('executeCommandConfiguration', {}).get('kmsKeyId'):
                    self.collect_kms_key(
                        cluster['configuration']['executeCommandConfiguration']['kmsKeyId'],
                        self.resource
                    )
            
            # Save cluster
            self.scraper.save_resource(
                'ecs/clusters',
                cluster['clusterName'],
                cluster
            )
            self.scraped_resources.add(cluster_arn)
            
            self.resource.depends_on.append(f"ecs:cluster:{cluster['clusterName']}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related ECS cluster {cluster_arn}: {str(e)}")

    def collect_batch_queue(self, queue_arn: str) -> None:
        """Collect Batch job queue and its configurations"""
        if queue_arn in self.scraped_resources:
            return
        
        try:
            batch = self.scraper.get_client('batch')
            
            # Get queue details
            queue = batch.describe_job_queues(
                jobQueues=[queue_arn]
            )['jobQueues'][0]
            
            # Collect compute environments
            for compute_env in queue.get('computeEnvironmentOrder', []):
                try:
                    env = batch.describe_compute_environments(
                        computeEnvironments=[compute_env['computeEnvironment']]
                    )['computeEnvironments'][0]
                    
                    # Collect related resources
                    if env.get('computeResources'):
                        # Collect IAM role
                        if env['computeResources'].get('instanceRole'):
                            self.collect_iam_role(
                                env['computeResources']['instanceRole'].split('/')[-1]
                            )
                        
                        # Collect security groups
                        for sg_id in env['computeResources'].get('securityGroupIds', []):
                            self.collect_security_group(sg_id)
                        
                        # Collect subnets
                        for subnet_id in env['computeResources'].get('subnets', []):
                            self.collect_subnet(subnet_id)
                        
                        # Collect launch template
                        if env['computeResources'].get('launchTemplate'):
                            self.collect_launch_template(
                                env['computeResources']['launchTemplate']['launchTemplateId'],
                                self.resource
                            )
                    
                    # Save compute environment
                    self.scraper.save_resource(
                        f'batch/job_queues/{queue["jobQueueName"]}/compute_environments',
                        env['computeEnvironmentName'],
                        env
                    )
                    
                except Exception as e:
                    self.scraper.logger.error(
                        f"Error collecting compute environment {compute_env['computeEnvironment']}: {str(e)}"
                    )
            
            # Save queue
            self.scraper.save_resource(
                'batch/job_queues',
                queue['jobQueueName'],
                queue
            )
            self.scraped_resources.add(queue_arn)
            
            self.resource.depends_on.append(f"batch:queue:{queue['jobQueueName']}")
            
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related Batch queue {queue_arn}: {str(e)}")

    def collect_iam_instance_profile(self, profile_name: str) -> None:
        """Collect IAM instance profile and its configurations"""
        if profile_name in self.scraped_resources:
            return
        
        try:
            iam = self.scraper.get_client('iam')
            
            # Get instance profile details
            profile = iam.get_instance_profile(InstanceProfileName=profile_name)['InstanceProfile']
            
            # Collect attached roles
            for role in profile.get('Roles', []):
                self.collect_iam_role(role['RoleName'])
            
            # Save instance profile
            self.scraper.save_resource(
                'iam/instance_profiles',
                profile_name,
                profile
            )
            self.scraped_resources.add(profile_name)
            
            self.resource.depends_on.append(f"iam:instance_profile:{profile_name}")
            
        except ClientError as e:
            self.scraper.handle_aws_error('get_instance_profile', profile_name, e)
        except Exception as e:
            self.scraper.logger.error(f"Error collecting related IAM instance profile {profile_name}: {str(e)}")

    def collect_s3_storage_lens(self, storage_lens_arn: str) -> None:
        """Collect S3 Storage Lens configuration"""
        if storage_lens_arn in self.scraped_resources:
            return
        
        try:
            s3control = self.scraper.get_client('s3control')
            account_id = storage_lens_arn.split(':')[4]
            config_id = storage_lens_arn.split('/')[-1]
            
            # Get storage lens configuration
            config = s3control.get_storage_lens_configuration(
                ConfigId=config_id,
                AccountId=account_id
            )
            
            # Get tags
            try:
                tags = s3control.get_storage_lens_configuration_tagging(
                    ConfigId=config_id,
                    AccountId=account_id
                )
                config['StorageLensConfiguration']['Tags'] = tags.get('Tags', [])
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchTagSet':
                    raise
                config['StorageLensConfiguration']['Tags'] = []
            
            # Save configuration
            self.scraper.save_resource(
                's3/storage_lens',
                config_id,
                config['StorageLensConfiguration']
            )
            self.scraped_resources.add(storage_lens_arn)
            
            self.resource.depends_on.append(f"s3:storage_lens:{config_id}")
            
        except ClientError as e:
            self.scraper.handle_aws_error('process_storage_lens', storage_lens_arn, e)
        except Exception as e:
            self.scraper.logger.error(f"Error collecting S3 Storage Lens {storage_lens_arn}: {str(e)}") 