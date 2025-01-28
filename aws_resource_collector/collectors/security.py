from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError

from aws_resource_collector.resource_graph.graph import Resource, ResourceType
from .base import BaseScraper
import json

class KMSScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape KMS keys and their configurations"""
        kms = self.get_client('kms')
        resources = []
        try:
            paginator = kms.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page['Keys']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=key['KeyId'],
                            type=ResourceType.KMS,
                            name=key['KeyId'],
                            env=next((tag['Value'] for tag in key.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in key.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )
                        self.related.set_resource(resource)
                        
                        # Get key details
                        key_details = kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']
                        
                        # Get key tags
                        try:
                            tags = kms.list_resource_tags(KeyId=key['KeyId'])
                            key_details['Tags'] = tags.get('Tags', [])
                            
                            # Convert tags for filtering
                            tags_dict = {}
                            for tag in key_details['Tags']:
                                if isinstance(tag, dict):
                                    if 'TagKey' in tag and 'TagValue' in tag:
                                        tags_dict[tag['TagKey']] = tag['TagValue']
                                    elif 'Key' in tag and 'Value' in tag:
                                        tags_dict[tag['Key']] = tag['Value']
                            
                            if self.tag_filter.matches({'Tags': tags_dict}):
                                # Get key policy
                                try:
                                    policy = kms.get_key_policy(
                                        KeyId=key['KeyId'],
                                        PolicyName='default'
                                    )
                                    key_details['Policy'] = policy['Policy']
                                    
                                    # Collect IAM roles/users from policy
                                    self._scrape_iam_from_policy(policy['Policy'], resource)
                                except ClientError as e:
                                    self.handle_aws_error('get_key_policy', key['KeyId'], e)
                                
                                # Get key grants
                                try:
                                    grants = kms.list_grants(KeyId=key['KeyId'])
                                    key_details['Grants'] = grants.get('Grants', [])
                                    
                                    # Collect IAM roles/users from grants
                                    for grant in grants.get('Grants', []):
                                        if grant.get('GranteePrincipal'):
                                            if ':role/' in grant['GranteePrincipal']:
                                                role_name = grant['GranteePrincipal'].split('/')[-1]
                                                self.related.collect_iam_role(role_name, resource)
                                            elif ':user/' in grant['GranteePrincipal']:
                                                user_name = grant['GranteePrincipal'].split('/')[-1]
                                                self.related.collect_iam_user(user_name, resource)
                                except ClientError as e:
                                    self.handle_aws_error('list_grants', key['KeyId'], e)
                                
                                # Save key
                                file_path = self.save_resource(
                                    'kms/keys',
                                    key['KeyId'],
                                    key_details
                                )
                                if file_path:
                                    self.collected_files.append(file_path)
                                    resources.append(resource)
                                    
                        except ClientError as e:
                            if e.response['Error']['Code'] != 'InvalidArnException':
                                self.handle_aws_error('list_resource_tags', key['KeyId'], e)
                            
                    except ClientError as e:
                        self.handle_aws_error('process_key', key['KeyId'], e)
                    except Exception as e:
                        self.logger.error(f"Error processing key {key['KeyId']}: {str(e)}")
                        
        except ClientError as e:
            self.handle_aws_error('list_keys', 'all', e)
        except Exception as e:
            self.logger.error(f"Error collecting KMS keys: {str(e)}")
            
        return resources
    
    def _scrape_iam_from_policy(self, policy_str: str, resource: Resource):
        """Extract and scrape IAM roles/users from policy"""
        try:
            policy = json.loads(policy_str)
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                if isinstance(principal, dict):
                    for key, value in principal.items():
                        if key == 'AWS':
                            if isinstance(value, str):
                                values = [value]
                            else:
                                values = value
                            for arn in values:
                                if ':role/' in arn:
                                    role_name = arn.split('/')[-1]
                                    self.related.collect_iam_role(role_name, resource)
                                elif ':user/' in arn:
                                    user_name = arn.split('/')[-1]
                                    self.related.collect_iam_user(user_name, resource)
        except Exception as e:
            self.logger.error(f"Error parsing policy: {str(e)}")

class SecurityGroupScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape security groups and their configurations"""
        ec2 = self.get_client('ec2')
        resources = []
        
        try:
            paginator = ec2.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=sg['GroupId'],
                            type=ResourceType.EC2,
                            name=sg['GroupId'],
                            env=next((tag['Value'] for tag in sg.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in sg.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )
                        self.related.set_resource(resource)
                        
                        if self.tag_filter.matches(sg):
                            # Collect referenced security groups
                            for rule in sg.get('IpPermissions', []) + sg.get('IpPermissionsEgress', []):
                                for ref in rule.get('UserIdGroupPairs', []):
                                    self.related.collect_security_group(ref['GroupId'], resource)
                            
                            # Save security group
                            file_path = self.save_resource(
                                'ec2/security_groups',
                                sg['GroupId'],
                                sg
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_security_group', sg['GroupId'], e)
                    except Exception as e:
                        self.logger.error(f"Error processing security group {sg['GroupId']}: {str(e)}")
                        
        except ClientError as e:
            self.handle_aws_error('describe_security_groups', 'all', e)
        except Exception as e:
            self.logger.error(f"Error collecting security groups: {str(e)}")
            
        return resources

class SecretsManagerScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape Secrets Manager secrets and their configurations"""
        secrets = self.get_client('secretsmanager')
        resources = []
        
        try:
            paginator = secrets.get_paginator('list_secrets')
            for page in paginator.paginate():
                for secret in page['SecretList']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=secret['ARN'],
                            type=ResourceType.SECRETS_MANAGER,
                            name=secret['Name'],
                            env=next((tag['Value'] for tag in secret.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in secret.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )
                        self.related.set_resource(resource)
                        
                        if self.tag_filter.matches(secret):
                            self._scrape_related_resources(secret, resource)
                            
                            # Get policy if enabled
                            if self.settings.scraper.include_global:
                                try:
                                    policy = secrets.get_resource_policy(SecretId=secret['ARN'])
                                    secret['ResourcePolicy'] = policy.get('ResourcePolicy')
                                except ClientError as e:
                                    if e.response['Error']['Code'] != 'ResourceNotFoundException':
                                        self.handle_aws_error('get_policy', secret['Name'], e)
                            
                            # Save secret (without the actual secret value)
                            file_path = self.save_resource(
                                'secretsmanager/secrets',
                                secret['Name'],
                                secret
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                    except ClientError as e:
                        self.handle_aws_error('process_secret', secret['Name'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_secrets', 'all', e)
            
        return resources

    def _scrape_related_resources(self, secret: Dict[str, Any], resource: Resource):
        """Scrape resources related to Secrets Manager secret"""
        try:
            # Collect KMS key
            if secret.get('KmsKeyId'):
                self.related.scrape_kms_key(secret['KmsKeyId'], resource)

            # Collect related resources based on secret type
            if secret.get('SecretType') == 'rds-credentials':
                # Extract RDS instance from secret name pattern
                if '/rds-db-credentials/' in secret.get('Name', ''):
                    instance_id = secret['Name'].split('/')[-1]
                    self.related.collect_rds_instance(instance_id, resource)
            elif secret.get('SecretType') == 'redshift-credentials':
                if '/redshift-credentials/' in secret.get('Name', ''):
                    cluster_id = secret['Name'].split('/')[-1]
                    self.related.collect_redshift_cluster(cluster_id, resource)

            # Collect IAM roles from resource policy
            if secret.get('ResourcePolicy'):
                policy = json.loads(secret['ResourcePolicy'])
                for statement in policy.get('Statement', []):
                    principal = statement.get('Principal', {})
                    if isinstance(principal, dict):
                        for key, value in principal.items():
                            if key == 'AWS':
                                values = [value] if isinstance(value, str) else value
                                for arn in values:
                                    if ':role/' in arn:
                                        role_name = arn.split('/')[-1]
                                        self.related.collect_iam_role(role_name, resource)
                                    elif ':user/' in arn:
                                        user_name = arn.split('/')[-1]
                                        self.related.collect_iam_user(user_name, resource)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for secret {secret.get('Name')}: {str(e)}") 