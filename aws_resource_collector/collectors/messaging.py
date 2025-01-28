from typing import List
import boto3
from botocore.exceptions import ClientError
from .base import BaseCollector
import json
from aws_resource_collector.resource_graph.graph import Resource, ResourceType


class SNSCollector(BaseCollector):
    def collect(self) -> List[Resource]:
        """Collect SNS topics and their configurations"""
        sns = self.get_client('sns')
        resources = []
        
        try:
            paginator = sns.get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page['Topics']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=topic['TopicArn'],
                            type=ResourceType.SNS,
                            name=topic['TopicArn'].split(':')[-1],
                            env=next((tag['Value'] for tag in topic.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in topic.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get topic attributes
                        attributes = sns.get_topic_attributes(TopicArn=topic['TopicArn'])
                        topic.update(attributes['Attributes'])
                        
                        # Get topic tags
                        tags = sns.list_tags_for_resource(ResourceArn=topic['TopicArn'])
                        topic['Tags'] = tags['Tags']
                        
                        if self.tag_filter.matches(topic):
                            # Collect KMS key if encrypted
                            if topic.get('KmsMasterKeyId'):
                                self.related.collect_kms_key(topic['KmsMasterKeyId'], resource)
                            
                            # Collect subscriptions
                            subs = sns.list_subscriptions_by_topic(TopicArn=topic['TopicArn'])
                            topic['Subscriptions'] = subs['Subscriptions']
                            
                            # Collect related resources from subscriptions
                            for sub in topic['Subscriptions']:
                                if sub['Protocol'] == 'sqs':
                                    self.related.collect_sqs_queue(sub['Endpoint'], resource)
                                elif sub['Protocol'] == 'lambda':
                                    self.related.collect_lambda_function(sub['Endpoint'], resource)
                            
                            # Save topic
                            file_path = self.save_resource(
                                'sns/topics',
                                topic['TopicArn'].split(':')[-1],
                                topic
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                    except ClientError as e:
                        self.handle_aws_error('process_topic', topic['TopicArn'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_topics', 'all', e)
            
        return resources

class SQSCollector(BaseCollector):
    def collect(self) -> List[Resource]:
        """Collect SQS queues and their configurations"""
        sqs = self.get_client('sqs')
        resources = []
        
        try:
            queues = sqs.list_queues()
            for queue_url in queues.get('QueueUrls', []):
                try:
                    # Create resource
                    resource = Resource(
                        id=queue_url,
                        type=ResourceType.SQS,
                        name=queue_url.split('/')[-1],
                        env=next((tag['Value'] for tag in queue.get('Tags', []) 
                                if tag['Key'] == 'Environment'), "Dev"),
                        app_id=next((tag['Value'] for tag in queue.get('Tags', []) 
                                   if tag['Key'] == 'ApplicationId'), "Unknown")
                    )

                    self.related.set_resource(resource)

                    # Get queue attributes
                    attributes = sqs.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['All']
                    )
                    queue = attributes['Attributes']
                    queue['QueueUrl'] = queue_url
                    
                    # Get queue tags
                    tags = sqs.list_queue_tags(QueueUrl=queue_url)
                    queue['Tags'] = tags.get('Tags', {})
                    
                    if self.tag_filter.matches(queue):
                        # Collect KMS key if encrypted
                        if queue.get('KmsMasterKeyId'):
                            self.related.collect_kms_key(queue['KmsMasterKeyId'], resource)
                        
                        # Collect dead letter queue if configured
                        if queue.get('RedrivePolicy'):
                            redrive = json.loads(queue['RedrivePolicy'])
                            if 'deadLetterTargetArn' in redrive:
                                self.related.collect_sqs_queue(redrive['deadLetterTargetArn'], resource)
                        
                        # Save queue
                        file_path = self.save_resource(
                            'sqs/queues',
                            queue_url.split('/')[-1],
                            queue
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            resources.append(resource)
                except ClientError as e:
                    self.handle_aws_error('process_queue', queue_url, e)
                    
        except ClientError as e:
            self.handle_aws_error('list_queues', 'all', e)
            
        return resources

class EventBridgeCollector(BaseCollector):
    def collect(self) -> List[Resource]:
        """Collect EventBridge resources and their configurations"""
        events = self.get_client('events')
        resources = []
        try:
            # List event buses
            response = events.list_event_buses()
            for bus in response['EventBuses']:
                try:
                    # Create resource
                    resource = Resource(
                        id=bus['Arn'],
                        type=ResourceType.EVENTBRIDGE,
                        name=bus['Name'],
                        env=next((tag['Value'] for tag in bus.get('Tags', []) 
                                if tag['Key'] == 'Environment'), "Dev"),
                        app_id=next((tag['Value'] for tag in bus.get('Tags', []) 
                                   if tag['Key'] == 'ApplicationId'), "Unknown")
                    )

                    self.related.set_resource(resource)

                    # Get bus tags
                    tags = events.list_tags_for_resource(
                        ResourceARN=bus['Arn']
                    )
                    bus['Tags'] = tags['Tags']
                    
                    if self.tag_filter.matches(bus):
                        # Save bus
                        file_path = self.save_resource(
                            'eventbridge/buses',
                            bus['Name'],
                            bus
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            
                            # Collect rules and their targets
                            self._collect_rules(events, bus['Name'], resource)
                            resources.append(resource)
                            
                except ClientError as e:
                    self.handle_aws_error('process_bus', bus['Name'], e)
                    
        except ClientError as e:
            self.handle_aws_error('list_event_buses', 'all', e)
            
        return resources
    
    def _collect_rules(self, events, bus_name: str, resource: Resource):
        """Collect rules and their targets"""
        try:
            paginator = events.get_paginator('list_rules')
            for page in paginator.paginate(EventBusName=bus_name):
                for rule in page['Rules']:
                    try:
                        # Get rule tags
                        tags = events.list_tags_for_resource(ResourceARN=rule['Arn'])
                        rule['Tags'] = tags['Tags']
                        
                        if self.tag_filter.matches(rule):
                            # Get rule targets
                            targets = events.list_targets_by_rule(
                                Rule=rule['Name'],
                                EventBusName=bus_name
                            )
                            rule['Targets'] = targets['Targets']
                            
                            # Collect related resources from targets
                            for target in targets['Targets']:
                                arn = target['Arn']
                                if ':lambda:' in arn:
                                    self.related.collect_lambda_function(arn, resource)
                                elif ':sqs:' in arn:
                                    self.related.collect_sqs_queue(arn, resource)
                                elif ':sns:' in arn:
                                    self.related.collect_sns_topic(arn, resource)
                                elif ':states:' in arn:
                                    self.related.collect_state_machine(arn, resource)
                                elif ':api-gateway:' in arn:
                                    self.related.collect_api_gateway(arn, resource)
                                elif ':ecs:' in arn:
                                    self.related.collect_ecs_task(arn, resource)
                            
                            # Save rule
                            file_path = self.save_resource(
                                'eventbridge/rules',
                                rule['Name'],
                                rule
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resource.depends_on.append(f"eventbridge:rule:{rule['Name']}")
                                
                    except ClientError as e:
                        self.handle_aws_error('process_rule', rule['Name'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_rules', bus_name, e) 