from typing import List
from aws_resource_collector.collectors.base import BaseCollector
from boto3.exceptions import ClientError

class TransferCollector(BaseCollector):
    def collect(self) -> List[str]:
        """Collect AWS Transfer Family resources"""
        transfer = self.get_client('transfer')
        
        try:
            # Collect servers
            paginator = transfer.get_paginator('list_servers')
            for page in paginator.paginate():
                for server in page['Servers']:
                    try:
                        if self.tag_filter.matches(server):
                            # Collect related resources
                            if server.get('IdentityProviderDetails', {}).get('Role'):
                                self.related.collect_iam_role(server['IdentityProviderDetails']['Role'])
                            
                            if server.get('LoggingRole'):
                                self.related.collect_iam_role(server['LoggingRole'])
                            
                            # Collect users for this server
                            self._collect_users(transfer, server['ServerId'])
                            
                            # Save server
                            file_path = self.save_resource(
                                'transfer/servers',
                                server['ServerId'],
                                server
                            )
                            if file_path:
                                self.collected_files.append(file_path)
                                
                    except ClientError as e:
                        self.handle_aws_error('process_server', server['ServerId'], e)
                        
        except ClientError as e:
            self.handle_aws_error('list_servers', 'all', e)
            
        return self.collected_files

    def _collect_users(self, transfer, server_id: str):
        """Collect users for a Transfer server"""
        try:
            paginator = transfer.get_paginator('list_users')
            for page in paginator.paginate(ServerId=server_id):
                for user in page['Users']:
                    try:
                        # Get user details
                        user_details = transfer.describe_user(
                            ServerId=server_id,
                            UserName=user['UserName']
                        )['User']
                        
                        # Collect IAM roles
                        if user_details.get('Role'):
                            self.related.collect_iam_role(user_details['Role'])
                        
                        # Save user
                        file_path = self.save_resource(
                            f'transfer/servers/{server_id}/users',
                            user['UserName'],
                            user_details
                        )
                        if file_path:
                            self.collected_files.append(file_path)
                            
                    except ClientError as e:
                        self.handle_aws_error('process_user', f"{server_id}/{user['UserName']}", e)
                        
        except ClientError as e:
            self.handle_aws_error('list_users', server_id, e) 