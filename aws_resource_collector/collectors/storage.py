from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError

from aws_resource_collector.resource_graph.graph import Resource
from .base import BaseScraper
import json

class S3Scraper(BaseScraper):
    def scrape(self) -> List[str]:
        """Scrape S3 buckets and their configurations"""
        s3 = self.get_client('s3')
        
        try:
            response = s3.list_buckets()
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                try:
                    # Get bucket location
                    location = s3.get_bucket_location(Bucket=bucket_name)
                    bucket['Location'] = location.get('LocationConstraint') or 'us-east-1'
                    
                    # Get bucket tags
                    try:
                        tags = s3.get_bucket_tagging(Bucket=bucket_name)
                        bucket['Tags'] = []
                        for tag in tags.get('TagSet', []):
                            if isinstance(tag, dict) and 'Key' in tag and 'Value' in tag:
                                bucket['Tags'].append({
                                    'Key': tag['Key'],
                                    'Value': tag['Value']
                                })
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchTagSet':
                            bucket['Tags'] = []
                        else:
                            raise

                    if self.tag_filter.matches(bucket):
                        # Collect all related resources
                        self._collect_related_resources(s3, bucket_name)
                        
                        # Save bucket
                        file_path = self.save_resource(
                            's3/buckets',
                            bucket_name,
                            bucket
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            
                except ClientError as e:
                    self.handle_aws_error('process_bucket', bucket_name, e)
                except Exception as e:
                    self.logger.error(f"Error processing bucket {bucket_name}: {str(e)}")
                    
        except ClientError as e:
            self.handle_aws_error('list_buckets', 'all', e)
            
        return self.collected_files

    def _collect_related_resources(self, s3, bucket_name: str):
        """Collect resources related to S3 bucket"""
        try:
            # Get bucket encryption
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                if 'ServerSideEncryptionConfiguration' in encryption:
                    for rule in encryption['ServerSideEncryptionConfiguration']['Rules']:
                        if 'ApplyServerSideEncryptionByDefault' in rule:
                            default_encryption = rule['ApplyServerSideEncryptionByDefault']
                            if default_encryption.get('SSEAlgorithm') == 'aws:kms':
                                kms_key = default_encryption.get('KMSMasterKeyId')
                                if kms_key:
                                    self.logger.debug(f"Found KMS key for bucket {bucket_name}: {kms_key}")
                                    self.related.collect_kms_key(kms_key)
            except ClientError as e:
                if e.response['Error']['Code'] != 'ServerSideEncryptionConfigurationNotFoundError':
                    self.handle_aws_error('get_bucket_encryption', bucket_name, e)

            # Get bucket policy
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                if 'Policy' in policy:
                    policy_doc = json.loads(policy['Policy'])
                    # Collect IAM roles/users from policy
                    self._collect_iam_from_policy(policy_doc)
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    self.handle_aws_error('get_bucket_policy', bucket_name, e)

            # Get replication configuration
            try:
                replication = s3.get_bucket_replication(Bucket=bucket_name)
                if 'ReplicationConfiguration' in replication:
                    for rule in replication['ReplicationConfiguration']['Rules']:
                        # Collect destination bucket
                        if 'Destination' in rule:
                            dest_bucket = rule['Destination'].get('Bucket')
                            if dest_bucket:
                                # Remove 'arn:aws:s3:::' prefix if present
                                if dest_bucket.startswith('arn:aws:s3:::'):
                                    dest_bucket = dest_bucket[13:]
                                self.related.collect_s3_bucket(dest_bucket)
                            # Collect KMS key for destination encryption
                            if rule['Destination'].get('EncryptionConfiguration', {}).get('ReplicaKmsKeyID'):
                                self.related.collect_kms_key(rule['Destination']['EncryptionConfiguration']['ReplicaKmsKeyID'])
                        # Collect source selection KMS key
                        if rule.get('SourceSelectionCriteria', {}).get('SseKmsEncryptedObjects', {}).get('KmsKeyId'):
                            self.related.collect_kms_key(rule['SourceSelectionCriteria']['SseKmsEncryptedObjects']['KmsKeyId'])
            except ClientError as e:
                if e.response['Error']['Code'] != 'ReplicationConfigurationNotFoundError':
                    self.handle_aws_error('get_bucket_replication', bucket_name, e)

            # Get lifecycle configuration
            try:
                lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                if 'Rules' in lifecycle:
                    for rule in lifecycle['Rules']:
                        # Check for transitions to other storage classes
                        for transition in rule.get('Transitions', []):
                            if transition.get('StorageClass', '').startswith('arn:'):
                                self.related.collect_s3_storage_lens(transition['StorageClass'])
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchLifecycleConfiguration':
                    self.handle_aws_error('get_bucket_lifecycle', bucket_name, e)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for bucket {bucket_name}: {str(e)}")

    def _collect_iam_from_policy(self, policy: Dict[str, Any]):
        """Extract and collect IAM principals from policy"""
        try:
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                if isinstance(principal, dict):
                    for key, value in principal.items():
                        if key == 'AWS':
                            values = [value] if isinstance(value, str) else value
                            for arn in values:
                                if ':role/' in arn:
                                    role_name = arn.split('/')[-1]
                                    self.related.collect_iam_role(role_name)
                                elif ':user/' in arn:
                                    user_name = arn.split('/')[-1]
                                    self.related.collect_iam_user(user_name)
        except Exception as e:
            self.logger.error(f"Error extracting IAM from policy: {str(e)}")

class EFSScraper(BaseScraper):
    def scrape(self) -> List[str]:
        """Scrape EFS filesystems and their configurations"""
        efs = self.get_client('efs')
        
        try:
            paginator = efs.get_paginator('describe_file_systems')
            for page in paginator.paginate():
                for filesystem in page['FileSystems']:
                    try:
                        # Get file system tags
                        tags = efs.list_tags_for_resource(
                            ResourceId=filesystem['FileSystemId']
                        )
                        filesystem['Tags'] = tags['Tags']
                        
                        if self.tag_filter.matches(filesystem):
                            # Collect related resources
                            self._collect_related_resources(efs, filesystem)
                            
                            # Save filesystem
                            file_path = self.save_resource(
                                'efs/filesystems',
                                filesystem['FileSystemId'],
                                filesystem
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_filesystem', filesystem['FileSystemId'], e)
                        
        except ClientError as e:
            self.handle_aws_error('describe_file_systems', 'all', e)
            
        return self.collected_files

    def _collect_related_resources(self, efs, filesystem: Dict[str, Any], resource: Resource):
        """Collect resources related to EFS filesystem"""
        filesystem_id = filesystem['FileSystemId']
        try:
            # Collect KMS key if encrypted
            if filesystem.get('KmsKeyId'):
                self.related.collect_kms_key(filesystem['KmsKeyId'])

            # Get mount targets and their resources
            try:
                paginator = efs.get_paginator('describe_mount_targets')
                for page in paginator.paginate(FileSystemId=filesystem_id):
                    for mount_target in page['MountTargets']:
                        try:
                            # Collect VPC resources
                            if mount_target.get('SubnetId'):
                                self.related.collect_subnet(mount_target['SubnetId'])

                            # Get and collect security groups
                            try:
                                security_groups = efs.describe_mount_target_security_groups(
                                    MountTargetId=mount_target['MountTargetId']
                                )
                                mount_target['SecurityGroups'] = security_groups['SecurityGroups']
                                
                                for sg_id in security_groups['SecurityGroups']:
                                    self.related.collect_security_group(sg_id)
                            except ClientError as e:
                                self.handle_aws_error('get_mount_target_security_groups', 
                                                    mount_target['MountTargetId'], e)

                            # Save mount target
                            file_path = self.save_resource(
                                f'efs/filesystems/{filesystem_id}/mount_targets',
                                mount_target['MountTargetId'],
                                mount_target
                            )
                            if file_path:
                                self.collected_files.append(file_path)

                        except ClientError as e:
                            self.handle_aws_error('process_mount_target', 
                                                mount_target['MountTargetId'], e)
            except ClientError as e:
                self.handle_aws_error('describe_mount_targets', filesystem_id, e)

            # Get and process filesystem policy
            try:
                policy = efs.describe_file_system_policy(FileSystemId=filesystem_id)
                filesystem['FileSystemPolicy'] = policy['Policy']
                
                # Collect IAM principals from policy
                self._collect_iam_from_policy(json.loads(policy['Policy']))
            except ClientError as e:
                if e.response['Error']['Code'] != 'PolicyNotFound':
                    self.handle_aws_error('get_filesystem_policy', filesystem_id, e)

            # Get backup policy
            try:
                backup_policy = efs.describe_backup_policy(FileSystemId=filesystem_id)
                filesystem['BackupPolicy'] = backup_policy['BackupPolicy']
            except ClientError as e:
                if e.response['Error']['Code'] != 'PolicyNotFound':
                    self.handle_aws_error('get_backup_policy', filesystem_id, e)

            # Get lifecycle configuration
            try:
                lifecycle = efs.describe_lifecycle_configuration(FileSystemId=filesystem_id)
                filesystem['LifecycleConfiguration'] = lifecycle['LifecyclePolicies']
            except ClientError as e:
                if e.response['Error']['Code'] != 'LifecycleConfigurationNotFound':
                    self.handle_aws_error('get_lifecycle_config', filesystem_id, e)

            # Collect access points
            self._collect_access_points(efs, filesystem_id, resource)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for filesystem {filesystem_id}: {str(e)}")

    def _collect_iam_from_policy(self, policy: Dict[str, Any]):
        """Extract and collect IAM principals from policy"""
        try:
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                if isinstance(principal, dict):
                    for key, value in principal.items():
                        if key == 'AWS':
                            values = [value] if isinstance(value, str) else value
                            for arn in values:
                                if ':role/' in arn:
                                    role_name = arn.split('/')[-1]
                                    self.related.collect_iam_role(role_name)
                                elif ':user/' in arn:
                                    user_name = arn.split('/')[-1]
                                    self.related.collect_iam_user(user_name)
        except Exception as e:
            self.logger.error(f"Error extracting IAM from policy: {str(e)}")

    def _collect_access_points(self, efs, filesystem_id: str, resource: Resource) -> None:
        """Collect access points for EFS filesystem"""
        try:
            paginator = efs.get_paginator('describe_access_points')
            for page in paginator.paginate(FileSystemId=filesystem_id):
                for access_point in page['AccessPoints']:
                    try:
                        # Collect IAM role if PosixUser has one
                        if access_point.get('PosixUser', {}).get('SecondaryGids'):
                            for gid in access_point['PosixUser']['SecondaryGids']:
                                if isinstance(gid, str) and ':role/' in gid:
                                    role_name = gid.split('/')[-1]
                                    self.related.collect_iam_role(role_name)

                        # Save access point
                        file_path = self.save_resource(
                            f'efs/filesystems/{filesystem_id}/access_points',
                            access_point['AccessPointId'],
                            access_point
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            resource.depends_on.append(f"efs:access_point:{access_point['AccessPointId']}")

                    except ClientError as e:
                        self.handle_aws_error('process_access_point', 
                                            access_point['AccessPointId'], e)

        except ClientError as e:
            self.handle_aws_error('describe_access_points', filesystem_id, e) 