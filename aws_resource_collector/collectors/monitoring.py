from typing import List
import boto3
from botocore.exceptions import ClientError
from .base import BaseCollector
from aws_resource_collector.resource_graph.graph import Resource, ResourceType


class CloudWatchCollector(BaseCollector):
    def collect(self) -> List[Resource]:
        cloudwatch = self.get_client('cloudwatch')
        resources = []

        # Collect alarms
        resources.extend(self._collect_alarms(cloudwatch))

        # Collect metrics
        resources.extend(self._collect_metrics(cloudwatch))

        # Collect dashboards
        resources.extend(self._collect_dashboards(cloudwatch))

        # Collect log groups
        resources.extend(self._collect_log_groups())

        return resources
        
    def _collect_alarms(self, cloudwatch):
        """Collect CloudWatch alarms"""
        resources = []
        
        try:
            paginator = cloudwatch.get_paginator('describe_alarms')
            for page in paginator.paginate():
                for alarm in page['MetricAlarms'] + page.get('CompositeAlarms', []):
                    try:
                        # Create resource
                        resource = Resource(
                            id=alarm['AlarmArn'],
                            type=ResourceType.CLOUDWATCH,
                            name=alarm['AlarmName'],
                            env=next((tag['Value'] for tag in alarm.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in alarm.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get alarm tags
                        tags = cloudwatch.list_tags_for_resource(
                            ResourceARN=alarm['AlarmArn']
                        )
                        alarm['Tags'] = tags['Tags']
                        
                        if self.tag_filter.matches(alarm):
                            # Collect related SNS topics
                            for action in (
                                alarm.get('AlarmActions', []) +
                                alarm.get('OKActions', []) +
                                alarm.get('InsufficientDataActions', [])
                            ):
                                if 'sns' in action:
                                    self.related.collect_sns_topic(action, resource)
                                elif 'lambda' in action:
                                    self.related.collect_lambda_function(action, resource)
                            
                            # Save alarm
                            file_path = self.save_resource(
                                'cloudwatch/alarms',
                                alarm['AlarmName'],
                                alarm
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_alarm', alarm['AlarmName'], e)
                        
        except ClientError as e:
            self.handle_aws_error('describe_alarms', 'all', e)
            
        return resources

    def _collect_metrics(self, cloudwatch):
        """Collect CloudWatch metrics"""
        resources = []

        try:
            paginator = cloudwatch.get_paginator('list_metrics')
            for page in paginator.paginate():
                for metric in page['Metrics']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=metric['MetricArn'],
                            type=ResourceType.CLOUDWATCH,
                            name=metric['MetricName'],
                            env=next((tag['Value'] for tag in metric.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in metric.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)
                        # Construct metric identifier
                        metric_id = f"{metric['Namespace']}/{metric['MetricName']}"
                        if 'Dimensions' in metric:
                            for dim in metric['Dimensions']:
                                metric_id += f"/{dim['Name']}={dim['Value']}"
                        
                        # Get metric statistics for the last hour
                        stats = cloudwatch.get_metric_statistics(
                            Namespace=metric['Namespace'],
                            MetricName=metric['MetricName'],
                            Dimensions=metric.get('Dimensions', []),
                            StartTime=self.settings.collector.start_time,
                            EndTime=self.settings.collector.end_time,
                            Period=300,  # 5 minute periods
                            Statistics=['Average', 'Minimum', 'Maximum']
                        )
                        metric['Statistics'] = stats['Datapoints']
                        
                        # Save metric without trying to get tags
                        file_path = self.save_resource(
                            'cloudwatch/metrics',
                            metric_id.replace('/', '-'),
                            metric
                        )
                        if file_path:
                            self.collected_files.append(file_path)

                            resources.append(resource)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_metric', metric.get('MetricName', 'unknown'), e)
                        
        except ClientError as e:
            self.handle_aws_error('list_metrics', 'all', e)
        
        return resources
    
    def _collect_dashboards(self, cloudwatch):
        """Collect CloudWatch dashboards"""
        resources = []

        try:
            paginator = cloudwatch.get_paginator('list_dashboards')
            for page in paginator.paginate():
                for dashboard in page['DashboardEntries']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=dashboard['DashboardArn'],
                            type=ResourceType.CLOUDWATCH,
                            name=dashboard['DashboardName'],
                            env=next((tag['Value'] for tag in dashboard.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in dashboard.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Get dashboard details
                        details = cloudwatch.get_dashboard(
                            DashboardName=dashboard['DashboardName']
                        )
                        dashboard['Body'] = details['DashboardBody']
                        
                        # Get dashboard tags
                        tags = cloudwatch.list_tags_for_resource(
                            ResourceARN=dashboard['DashboardArn']
                        )
                        dashboard['Tags'] = tags['Tags']
                        
                        if self.tag_filter.matches(dashboard):
                            file_path = self.save_resource(
                                'cloudwatch/dashboards',
                                dashboard['DashboardName'],
                                dashboard
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                    except ClientError as e:
                        self.handle_aws_error('process_dashboard', dashboard['DashboardName'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_dashboards', 'all', e)
        
        return resources
    
    def _collect_log_groups(self):
        """Collect CloudWatch log groups"""
        resources = []
        logs = self.get_client('logs')

        try:
            paginator = logs.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                for group in page['logGroups']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=group['logGroupName'],
                            type=ResourceType.CLOUDWATCH,
                            name=group['logGroupName'],
                            env=next((tag['Value'] for tag in group.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in group.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)
                        # Get log group tags
                        tags = logs.list_tags_log_group(
                            logGroupName=group['logGroupName']
                        )
                        group['tags'] = tags['tags']
                        
                        if self.tag_filter.matches(group):
                            # Collect KMS key if encrypted
                            if group.get('kmsKeyId'):
                                self.related.collect_kms_key(group['kmsKeyId'], resource)
                            
                            file_path = self.save_resource(
                                'cloudwatch/log_groups',
                                group['logGroupName'].replace('/', '-'),
                                group
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                    except ClientError as e:
                        self.handle_aws_error('process_log_group', group['logGroupName'], e)
                        
        except ClientError as e:
            self.handle_aws_error('describe_log_groups', 'all', e) 
        
        return resources