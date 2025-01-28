from typing import List, Dict, Any
import boto3
from botocore.exceptions import ClientError
from .base import BaseScraper
import json

from aws_resource_collector.resource_graph.graph import Resource, ResourceType

class LambdaScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape Lambda functions and their configurations"""
        lambda_client = self.get_client('lambda')
        resources = []
        try:
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for function in page['Functions']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=function['FunctionArn'],
                            type=ResourceType.LAMBDA,
                            name=function['FunctionName'],
                            env=next((tag['Value'] for tag in function.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in function.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )
                        self.related.set_resource(resource)
                        
                        # Get function tags
                        tags = lambda_client.list_tags(Resource=function['FunctionArn'])
                        function['Tags'] = tags['Tags']
                        
                        if self.tag_filter.matches(function):
                            # Collect related resources
                            self._collect_related_resources(function, resource)
                            
                            # Get function configuration
                            config = lambda_client.get_function_configuration(
                                FunctionName=function['FunctionName']
                            )
                            function.update(config)
                            
                            # Save function
                            file_path = self.save_resource(
                                'lambda/functions',
                                function['FunctionName'],
                                function
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)

                    except ClientError as e:
                        self.handle_aws_error('process_function', function['FunctionName'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_functions', 'all', e)
            
        return resources

    def _collect_related_resources(self, function: Dict[str, Any], resource: Resource):
        """Collect resources related to Lambda function"""
        try:
            # Collect VPC resources
            if 'VpcConfig' in function:
                vpc_config = function['VpcConfig']
                for subnet_id in vpc_config.get('SubnetIds', []):
                    self.related.collect_subnet(subnet_id)
                for sg_id in vpc_config.get('SecurityGroupIds', []):
                    self.related.collect_security_group(sg_id)

            # Collect KMS key
            if function.get('KMSKeyArn'):
                self.related.collect_kms_key(function['KMSKeyArn'])

            # Collect IAM role
            if function.get('Role'):
                role_name = function['Role'].split('/')[-1]
                self.related.collect_iam_role(role_name)

            # Collect event source mappings
            self._scrape_event_sources(function['FunctionName'], resource)

            # Collect layers
            for layer in function.get('Layers', []):
                self.related.collect_lambda_layer(layer['Arn'])

        except Exception as e:
            self.logger.error(f"Error collecting related resources for function {function.get('FunctionName')}: {str(e)}")

    def _scrape_event_sources(self, function_name: str, resource: Resource):
        """Scrape event source mappings and related resources"""
        try:
            lambda_client = self.get_client('lambda')
            paginator = lambda_client.get_paginator('list_event_source_mappings')
            for page in paginator.paginate(FunctionName=function_name):
                for mapping in page['EventSourceMappings']:
                    try:
                        # Collect related resources based on source type
                        source_arn = mapping.get('EventSourceArn', '')
                        if ':sqs:' in source_arn:
                            self.related.collect_sqs_queue(source_arn)
                        elif ':dynamodb:' in source_arn:
                            self.related.collect_dynamodb_stream(source_arn)
                        elif ':kinesis:' in source_arn:
                            self.related.collect_kinesis_stream(source_arn)
                        elif ':kafka:' in source_arn:
                            self.related.collect_kafka_topic(source_arn)

                        # Save mapping
                        file_path = self.save_resource(
                            f'lambda/functions/{function_name}/event_sources',
                            mapping['UUID'],
                            mapping
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            resource.depends_on.append(f'lambda:functions:{function_name}:event_sources:{mapping["UUID"]}')

                    except ClientError as e:
                        self.handle_aws_error('process_event_source', mapping['UUID'], e)

        except ClientError as e:
            self.handle_aws_error('list_event_sources', function_name, e)

class APIGatewayScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape API Gateway resources and their configurations"""
        apigw = self.get_client('apigateway')
        resources = []
        try:
            paginator = apigw.get_paginator('get_rest_apis')
            for page in paginator.paginate():
                for api in page['items']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=api['id'],
                            type=ResourceType.API_GATEWAY,
                            name=api['name'],
                            env=next((tag['Value'] for tag in api.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in api.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )
                        self.related.set_resource(resource)
                        
                        # Get API tags
                        tags = apigw.get_tags(
                            resourceArn=f"arn:aws:apigateway:{self.settings.aws.region}::/restapis/{api['id']}"
                        )
                        api['Tags'] = tags.get('tags', {})
                        
                        if self.tag_filter.matches(api):
                            # Collect related resources
                            self._collect_related_resources(api)
                            
                            # Save API
                            file_path = self.save_resource(
                                'apigateway/apis',
                                api['name'],
                                api
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_api', api['name'], e)
                        
        except ClientError as e:
            self.handle_aws_error('get_rest_apis', 'all', e)
            
        return resources

    def _collect_related_resources(self, api: Dict[str, Any]):
        """Collect resources related to API Gateway"""
        try:
            apigw = self.get_client('apigateway')

            # Collect resources and methods
            resources = self._get_api_resources(api['id'])
            for resource in resources:
                for method in resource.get('resourceMethods', {}).values():
                    # Collect Lambda integrations
                    if method.get('methodIntegration', {}).get('type') == 'AWS':
                        uri = method['methodIntegration'].get('uri', '')
                        if ':lambda:' in uri:
                            self.related.collect_lambda_function(uri)

            # Collect authorizers
            authorizers = apigw.get_authorizers(restApiId=api['id'])
            for authorizer in authorizers['items']:
                if authorizer['type'] == 'TOKEN' and 'authorizerUri' in authorizer:
                    self.related.collect_lambda_function(authorizer['authorizerUri'])

        except Exception as e:
            self.logger.error(f"Error collecting related resources for API {api.get('name')}: {str(e)}")

    def _get_api_resources(self, api_id: str) -> List[Dict[str, Any]]:
        """Get resources for API"""
        try:
            apigw = self.get_client('apigateway')
            resources = []
            paginator = apigw.get_paginator('get_resources')
            for page in paginator.paginate(restApiId=api_id):
                resources.extend(page['items'])
            return resources
        except Exception as e:
            self.logger.error(f"Error getting resources for API {api_id}: {str(e)}")
            return []

class StepFunctionsScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape Step Functions state machines and their configurations"""
        sfn = self.get_client('stepfunctions')
        resources = []
        
        try:
            paginator = sfn.get_paginator('list_state_machines')
            for page in paginator.paginate():
                for machine in page['stateMachines']:
                    try:
                        # Create resource
                        resource = Resource(
                            id=machine['stateMachineArn'],
                            type=ResourceType.STEP_FUNCTIONS,
                            name=machine['name'],
                            env=next((tag['Value'] for tag in machine.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in machine.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )
                        self.related.set_resource(resource)
                        
                        # Get state machine details
                        details = sfn.describe_state_machine(
                            stateMachineArn=machine['stateMachineArn']
                        )
                        
                        # Get tags
                        tags = sfn.list_tags_for_resource(
                            resourceArn=machine['stateMachineArn']
                        )
                        details['tags'] = tags['tags']
                        
                        if self.tag_filter.matches(details):
                            # Collect related resources
                            self._collect_related_resources(details)
                            
                            # Get execution history if enabled
                            if self.settings.scraper.include_global:
                                self._scrape_executions(sfn, machine['stateMachineArn'], resource)
                            
                            # Save state machine
                            file_path = self.save_resource(
                                'stepfunctions/state_machines',
                                machine['name'],
                                details
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                resources.append(resource)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_state_machine', machine['name'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_state_machines', 'all', e)
            
        return resources

    def _collect_related_resources(self, machine: Dict[str, Any]):
        """Collect resources related to state machine"""
        try:
            # Collect IAM role
            if machine.get('roleArn'):
                role_name = machine['roleArn'].split('/')[-1]
                self.related.collect_iam_role(role_name)
            
            # Parse state machine definition
            definition = json.loads(machine['definition'])
            self._scrape_resources_from_states(definition.get('States', {}))
            
        except Exception as e:
            self.logger.error(f"Error collecting related resources for state machine {machine.get('name')}: {str(e)}")

    def _scrape_resources_from_states(self, states: Dict[str, Any]):
        """Extract and scrape resources from state machine states"""
        for state in states.values():
            try:
                # Task states can invoke AWS services
                if state.get('Type') == 'Task':
                    resource = state.get('Resource', '')
                    
                    # Lambda functions
                    if ':lambda:' in resource:
                        function_name = resource.split(':')[-1]
                        self.related.collect_lambda_function(function_name)
                    
                    # ECS tasks
                    elif ':ecs:' in resource:
                        cluster = state.get('Parameters', {}).get('Cluster')
                        if cluster:
                            self.related.collect_ecs_cluster(cluster)
                    
                    # Step Functions
                    elif ':states:' in resource:
                        self.related.collect_state_machine(resource)
                    
                    # SQS queues
                    elif ':sqs:' in resource:
                        self.related.collect_sqs_queue(resource)
                    
                    # SNS topics
                    elif ':sns:' in resource:
                        self.related.collect_sns_topic(resource)
                    
                    # DynamoDB tables
                    elif ':dynamodb:' in resource:
                        table_name = resource.split('/')[-1]
                        self.related.collect_dynamodb_table(table_name)
                    
                    # Batch jobs
                    elif ':batch:' in resource:
                        job_queue = state.get('Parameters', {}).get('JobQueue')
                        if job_queue:
                            self.related.collect_batch_queue(job_queue)
                
                # Parallel and Map states can have nested states
                elif state.get('Type') in ['Parallel', 'Map']:
                    for branch in state.get('Branches', []):
                        self._scrape_resources_from_states(branch.get('States', {}))
                    
            except Exception as e:
                self.logger.error(f"Error processing state {state.get('Type')}: {str(e)}")

    def _scrape_executions(self, sfn, state_machine_arn: str, resource: Resource):
        """Collect recent executions of state machine"""
        try:
            paginator = sfn.get_paginator('list_executions')
            for page in paginator.paginate(stateMachineArn=state_machine_arn):
                for execution in page['executions']:
                    try:
                        # Get execution details
                        details = sfn.describe_execution(
                            executionArn=execution['executionArn']
                        )
                        
                        # Save execution
                        file_path = self.save_resource(
                            f'stepfunctions/state_machines/{execution["name"]}/executions',
                            execution['executionArn'].split(':')[-1],
                            details
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            resource.depends_on.append(f'stepfunctions:state_machines:{execution["name"]}:executions')
                            
                    except ClientError as e:
                        self.handle_aws_error('process_execution', execution['name'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_executions', state_machine_arn, e) 