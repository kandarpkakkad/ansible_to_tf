from typing import List, Dict, Any
import boto3

from aws_resource_collector.resource_graph.graph import Resource, ResourceType
from .base import BaseScraper

class EC2Scraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape EC2 instances and their configurations"""
        ec2 = self.get_client('ec2')
        resources = []
        try:
            paginator = ec2.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        try:
                            # Create resource
                            resource = Resource(
                                id=instance['InstanceId'],
                                type=ResourceType.EC2,
                                name=instance['InstanceId'],
                                env=next((tag['Value'] for tag in instance.get('Tags', []) 
                                        if tag['Key'] == 'Environment'), "Dev"),
                                app_id=next((tag['Value'] for tag in instance.get('Tags', []) 
                                           if tag['Key'] == 'ApplicationId'), "Unknown")
                            )

                            self.related.set_resource(resource)

                            # Convert tags list to dict format for filtering
                            if 'Tags' in instance:
                                instance['Tags'] = [{'Key': tag['Key'], 'Value': tag['Value']} 
                                                  for tag in instance['Tags']]
                            
                            if self.tag_filter.matches(instance):
                                # Always collect related resources regardless of tag matching
                                self._scrape_related_resources(instance, resource)
                                
                                # Save instance
                                file_path = self.save_resource(
                                    'ec2/instances',
                                    instance['InstanceId'],
                                    instance
                                )
                                if file_path:
                                    self.collected_files.append(file_path)
                                
                                resources.append(resource)
                                    
                        except boto3.exceptions.ClientError as e:
                            self.handle_aws_error('process_instance', instance['InstanceId'], e)
                        except Exception as e:
                            self.logger.error(f"Error processing instance {instance['InstanceId']}: {str(e)}")
                            
            # Collect global resources if configured
            if self.settings.scraper.include_global:
                self._scrape_amis(ec2)
                self._scrape_snapshots(ec2)
                
        except boto3.exceptions.ClientError as e:
            self.handle_aws_error('describe_instances', 'all', e)
        except Exception as e:
            self.logger.error(f"Error collecting EC2 instances: {str(e)}")
        
        return resources
    
    def _scrape_related_resources(self, instance: Dict[str, Any], resource: Resource):
        """Scrape all resources related to an EC2 instance"""
        try:
            # Collect Subnet
            if 'SubnetId' in instance:
                self.logger.debug(f"Scraping Subnet {instance['SubnetId']}")
                self.related.collect_subnet(instance['SubnetId'])

            # Collect Security Groups
            for sg in instance.get('SecurityGroups', []):
                self.logger.debug(f"Collecting Security Group {sg['GroupId']}")
                self.related.collect_security_group(sg['GroupId'])

            # Collect EBS Volumes
            for block_device in instance.get('BlockDeviceMappings', []):
                if 'Ebs' in block_device:
                    volume_id = block_device['Ebs'].get('VolumeId')
                    if volume_id:
                        self.logger.debug(f"Collecting EBS Volume {volume_id}")
                        self.related.collect_ebs_volume(volume_id)

            # Collect Network Interfaces
            for eni in instance.get('NetworkInterfaces', []):
                eni_id = eni.get('NetworkInterfaceId')
                if eni_id:
                    self.logger.debug(f"Collecting Network Interface {eni_id}")
                    self.related.collect_network_interface(eni_id)

            # Collect IAM Instance Profile
            if 'IamInstanceProfile' in instance:
                profile_arn = instance['IamInstanceProfile'].get('Arn')
                if profile_arn:
                    profile_name = profile_arn.split('/')[-1]
                    self.logger.debug(f"Collecting IAM Instance Profile {profile_name}")
                    self.related.collect_iam_instance_profile(profile_name)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for instance {instance.get('InstanceId')}: {str(e)}")
    
    def _scrape_amis(self, ec2, resource: Resource):
        """Collect AMIs owned by account"""
        try:
            images = ec2.describe_images(Owners=['self'])
            for image in images['Images']:
                if self.tag_filter.matches(image):
                    file_path = self.save_resource(
                        'ec2/images',
                        image['ImageId'],
                        image
                    )
                    if file_path:
                        self.collected_files.append(file_path)
                        resource.depends_on.append(f"ami:{image['ImageId']}")

        except Exception as e:
            self.logger.error(f"Error collecting AMIs: {str(e)}")
    
    def _scrape_snapshots(self, ec2, resource: Resource):
        """Collect EBS snapshots"""
        try:
            snapshots = ec2.describe_snapshots(OwnerIds=['self'])
            
            # Process snapshots in batches
            def process_snapshot_batch(batch):
                results = []
                for snapshot in batch:
                    if self.tag_filter.matches(snapshot):
                        file_path = self.save_resource(
                            'ec2/snapshots',
                            snapshot['SnapshotId'],
                            snapshot
                        )
                        if file_path:
                            results.append(file_path)
                            resource.depends_on.append(f"snapshot:{snapshot['SnapshotId']}")

                return results
            
            batch_results = self.process_batch(
                snapshots['Snapshots'],
                process_snapshot_batch
            )
            self.collected_files.extend(batch_results)
            
        except Exception as e:
            self.logger.error(f"Error collecting snapshots: {str(e)}")

    def _collect_layers(self, lambda_client, resource: Resource):
        """Collect Lambda layers"""
        try:
            paginator = lambda_client.get_paginator('list_layers')
            for page in paginator.paginate():
                for layer in page['Layers']:
                    try:
                        # Process layer versions in batches
                        versions = lambda_client.list_layer_versions(
                            LayerName=layer['LayerName']
                        )
                        layer['Versions'] = []
                        
                        def process_version_batch(batch):
                            results = []
                            for version in batch:
                                try:
                                    policy = lambda_client.get_layer_version_policy(
                                        LayerName=layer['LayerName'],
                                        VersionNumber=version['Version']
                                    )
                                    version['Policy'] = policy['Policy']
                                except lambda_client.exceptions.ResourceNotFoundException:
                                    pass
                                results.append(version)
                            return results
                        
                        layer['Versions'] = self.process_batch(
                            versions['LayerVersions'],
                            process_version_batch
                        )
                        
                        file_path = self.save_resource(
                            'lambda/layers',
                            layer['LayerName'],
                            layer
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            resource.depends_on.append(f"layer:{layer['LayerName']}")

                    except boto3.exceptions.ClientError as e:
                        self.handle_aws_error('process_layer', layer.get('LayerName', 'unknown'), e)
                    except Exception as e:
                        self.logger.error(f"Error processing layer {layer.get('LayerName')}: {str(e)}")
                        
        except boto3.exceptions.ClientError as e:
            self.handle_aws_error('list_layers', 'all', e)
        except Exception as e:
            self.logger.error(f"Error collecting layers: {str(e)}") 