from typing import List, Dict, Any
from aws_resource_collector.collectors.base import BaseScraper
from botocore.exceptions import ClientError
from aws_resource_collector.resource_graph.graph import Resource, ResourceType

class KinesisScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape Kinesis streams and their configurations"""
        kinesis = self.get_client('kinesis')
        resources = []
        
        try:
            paginator = kinesis.get_paginator('list_streams')
            for page in paginator.paginate():
                for stream_name in page['StreamNames']:
                    try:
                        # Get stream details
                        stream = kinesis.describe_stream(StreamName=stream_name)['StreamDescription']
                        
                        # Get stream tags
                        tags = kinesis.list_tags_for_stream(StreamName=stream_name)
                        stream['Tags'] = tags['Tags']
                        
                        if self.tag_filter.matches(stream):
                            # Create resource
                            resource = Resource(
                                id=stream_name,
                                type=ResourceType.KINESIS,
                                name=stream_name,
                                env=next((tag['Value'] for tag in stream.get('Tags', []) 
                                        if tag['Key'] == 'Environment'), "Dev"),
                                app_id=next((tag['Value'] for tag in stream.get('Tags', []) 
                                           if tag['Key'] == 'ApplicationId'), "Unknown")
                            )

                            self.related.set_resource(resource)
                            
                            # Collect KMS key if encrypted
                            if stream.get('EncryptionType') == 'KMS':
                                self.related.collect_kms_key(stream['KeyId'])
                            
                            # Save stream data
                            self.save_resource(
                                'kinesis/streams',
                                stream_name,
                                stream
                            )

                            resources.append(resource)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_stream', stream_name, e)
                        
        except ClientError as e:
            self.handle_aws_error('list_streams', 'all', e)
            
        return resources

class GlueScraper(BaseScraper):
    def scrape(self) -> List[Resource]:
        """Scrape Glue resources and their configurations"""
        glue = self.get_client('glue')
        resources = []
        
        try:
            # Scrape databases
            paginator = glue.get_paginator('get_databases')
            for page in paginator.paginate():
                for database in page['DatabaseList']:
                    try:
                        if self.tag_filter.matches(database):
                            # Create resource
                            resource = Resource(
                                id=database['Name'],
                                type=ResourceType.GLUE,
                                name=database['Name'],
                                env=next((tag['Value'] for tag in database.get('Tags', []) 
                                        if tag['Key'] == 'Environment'), "Dev"),
                                app_id=next((tag['Value'] for tag in database.get('Tags', []) 
                                           if tag['Key'] == 'ApplicationId'), "Unknown")
                            )
                            
                            self.related.set_resource(resource)
                            
                            # Save database data
                            self.save_resource(
                                'glue/databases',
                                database['Name'],
                                database
                            )
                            
                            # Scrape tables in database
                            self._scrape_tables(glue, database['Name'], resource)

                            resources.append(resource)
                            
                    except ClientError as e:
                        self.handle_aws_error('process_database', database['Name'], e)
                        
            # Scrape jobs
            self._scrape_jobs(glue, resources)
            
            # Scrape triggers
            self._scrape_triggers(glue, resources)
            
        except ClientError as e:
            self.handle_aws_error('get_databases', 'all', e)
            
        return resources

    def _scrape_tables(self, glue, database_name: str, resource: Resource):
        """Scrape tables in database"""
        try:
            paginator = glue.get_paginator('get_tables')
            for page in paginator.paginate(DatabaseName=database_name):
                for table in page['TableList']:
                    try:
                        if self.tag_filter.matches(table):
                            file_path = self.save_resource(
                                f'glue/databases/{database_name}/tables',
                                table['Name'],
                                table
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                
                            resource.depends_on.append(f"glue:table:{table['Name']}")
                                
                    except ClientError as e:
                        self.handle_aws_error('process_table', table['Name'], e)
                        
        except ClientError as e:
            self.handle_aws_error('get_tables', database_name, e)

    def _scrape_jobs(self, glue, resources):
        """Scrape Glue jobs"""
        try:
            paginator = glue.get_paginator('get_jobs')
            for page in paginator.paginate():
                for job in page['Jobs']:
                    if self.tag_filter.matches(job):
                        # Create resource
                        resource = Resource(
                            id=job['Name'],
                            type=ResourceType.GLUE_JOB,
                            name=job['Name'],
                            env=next((tag['Value'] for tag in job.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in job.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        # Collect related IAM role
                        if job.get('Role'):
                            self.related.collect_iam_role(job['Role'])
                        
                        file_path = self.save_resource(
                            'glue/jobs',
                            job['Name'],
                            job
                        )
                        if file_path:
                            self.collected_files.append(file_path)

                        # Collect related resources
                        self._scrape_related_resources(job, resource)

                        resources.append(resource)
        except ClientError as e:
            self.handle_aws_error('get_jobs', 'all', e)

    def _scrape_triggers(self, glue, resources):
        """Scrape Glue triggers"""
        try:
            paginator = glue.get_paginator('get_triggers')
            for page in paginator.paginate():
                for trigger in page['Triggers']:
                    if self.tag_filter.matches(trigger):
                        # Create resource
                        resource = Resource(
                            id=trigger['Name'],
                            type=ResourceType.GLUE_TRIGGER,
                            name=trigger['Name'],
                            env=next((tag['Value'] for tag in trigger.get('Tags', []) 
                                    if tag['Key'] == 'Environment'), "Dev"),
                            app_id=next((tag['Value'] for tag in trigger.get('Tags', []) 
                                       if tag['Key'] == 'ApplicationId'), "Unknown")
                        )

                        self.related.set_resource(resource)

                        file_path = self.save_resource(
                            'glue/triggers',
                            trigger['Name'],
                            trigger
                        )
                        if file_path:
                            self.collected_files.append(file_path)

                        resources.append(resource)
        except ClientError as e:
            self.handle_aws_error('get_triggers', 'all', e)

    def _scrape_related_resources(self, job: Dict[str, Any], resource: Resource):
        """Scrape resources related to Glue job"""
        try:
            # Collect security configurations
            if job.get('SecurityConfiguration'):
                security_config = self.get_client('glue').get_security_configuration(
                    Name=job['SecurityConfiguration']
                )['SecurityConfiguration']
                
                # Collect KMS keys from security config
                if security_config.get('EncryptionConfiguration'):
                    enc_config = security_config['EncryptionConfiguration']
                    if enc_config.get('S3Encryption'):
                        for s3_enc in enc_config['S3Encryption']:
                            if s3_enc.get('KmsKeyArn'):
                                self.related.collect_kms_key(s3_enc['KmsKeyArn'])
                    if enc_config.get('CloudWatchEncryption', {}).get('KmsKeyArn'):
                        self.related.collect_kms_key(enc_config['CloudWatchEncryption']['KmsKeyArn'])
                    if enc_config.get('JobBookmarksEncryption', {}).get('KmsKeyArn'):
                        self.related.collect_kms_key(enc_config['JobBookmarksEncryption']['KmsKeyArn'])

            # Collect S3 buckets from job parameters
            if job.get('DefaultArguments'):
                for key, value in job['DefaultArguments'].items():
                    if 's3://' in str(value):
                        bucket_name = value.split('/')[2]
                        self.related.collect_s3_bucket(bucket_name)

            # Collect connections
            if job.get('Connections', {}).get('Connections'):
                for conn_name in job['Connections']['Connections']:
                    connection = self.get_client('glue').get_connection(Name=conn_name)['Connection']
                    if connection.get('ConnectionProperties', {}).get('JDBC_CONNECTION_URL'):
                        jdbc_url = connection['ConnectionProperties']['JDBC_CONNECTION_URL']
                        if 'rds.amazonaws.com' in jdbc_url:
                            instance_id = jdbc_url.split('.')[0]
                            self.related.collect_rds_instance(instance_id)

        except Exception as e:
            self.logger.error(f"Error collecting related resources for job {job.get('Name')}: {str(e)}")