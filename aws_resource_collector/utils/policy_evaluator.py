from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
import json
from logging import Logger

class PolicyEvaluator:
    """Evaluate IAM policies using policy simulator"""
    
    def __init__(self, logger: Logger):
        self.iam_client = boto3.client('iam')
        self.logger = logger

    def evaluate_policy(self, policy_str: str, actions: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Evaluate a policy string using IAM policy simulator
        
        Args:
            policy_str: JSON string containing IAM policy
            actions: Optional list of actions to evaluate. If None, extracts from policy.
            
        Returns:
            Dictionary containing evaluation results
            
        Example results:
            {
                'allowed': [
                    {
                        'action': 'rds:DescribeDBInstances',
                        'principals': {
                            'roles': ['rds-monitoring-role'],
                            'users': ['admin-user'],
                            'services': ['rds.amazonaws.com']
                        },
                        'conditions': [
                            {
                                'type': 'StringEquals',
                                'key': 'aws:RequestedRegion',
                                'values': ['us-east-1']
                            },
                            {
                                'type': 'Bool',
                                'key': 'aws:SecureTransport',
                                'values': ['true']
                            }
                        ]
                    }
                ],
                'denied': [
                    {
                        'action': 'rds:DeleteDBInstance',
                        'reason': 'implicitDeny',
                        'principals': {
                            'roles': ['app-role'],
                            'users': ['app-user'],
                            'services': []
                        },
                        'conditions': [
                            {
                                'type': 'StringNotLike',
                                'key': 'rds:DatabaseClass',
                                'values': ['db.r5.*']
                            }
                        ]
                    }
                ],
                'errors': [
                    {
                        'action': 'invalid:Action',
                        'error': 'NoSuchAction',
                        'principals': {
                            'roles': [],
                            'users': [],
                            'services': []
                        }
                    }
                ]
            }
        """
        try:
            # Parse policy
            policy = json.loads(policy_str)

            # Extract actions from policy if not provided
            if actions is None:
                actions = []
                for statement in policy.get('Statement', []):
                    if isinstance(statement.get('Action'), str):
                        actions.append(statement['Action'])
                    elif isinstance(statement.get('Action'), list):
                        actions.extend(statement['Action'])

            # Get principals from policy
            principals = self._extract_principals(policy)

            # Simulate policy
            response = self.iam_client.simulate_custom_policy(
                PolicyInputList=[json.dumps(policy)],
                ActionNames=actions,
                CallerArn=principals.get('caller_arn')
            )

            # Process results
            results = {
                'allowed': [],
                'denied': [],
                'errors': []
            }

            for result in response['EvaluationResults']:
                action = result['EvalActionName']
                decision = result['EvalDecision']
                
                # Get principals and conditions
                action_principals = self._get_affected_principals(
                    result.get('MatchedStatements', []),
                    principals
                )
                action_conditions = self._get_conditions(
                    result.get('MatchedStatements', [])
                )
                
                if decision == 'allowed':
                    results['allowed'].append({
                        'action': action,
                        'principals': action_principals,
                        'conditions': action_conditions
                    })
                elif decision == 'implicitDeny' or decision == 'explicitDeny':
                    results['denied'].append({
                        'action': action,
                        'reason': decision,
                        'principals': action_principals,
                        'conditions': action_conditions
                    })
                else:
                    results['errors'].append({
                        'action': action,
                        'error': decision,
                        'principals': action_principals,
                        'conditions': action_conditions
                    })
                    
                # Log results
                if decision != 'allowed':
                    self.logger.warning(
                        f"Action {action} is {decision} for principals: {action_principals}"
                        f" with conditions: {action_conditions}"
                    )

            return results

        except ClientError as e:
            self.logger.error(f"AWS API error evaluating policy: {str(e)}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid policy JSON: {str(e)}")
            raise
        except Exception as e:
            self.logger.error(f"Error evaluating policy: {str(e)}")
            raise

    def evaluate_policy_file(self, policy_file: str) -> Dict[str, Any]:
        """Evaluate policy from a JSON file"""
        try:
            with open(policy_file, 'r') as f:
                policy_str = f.read()
            return self.evaluate_policy(policy_str)
        except FileNotFoundError:
            self.logger.error(f"Policy file not found: {policy_file}")
            raise
        except Exception as e:
            self.logger.error(f"Error reading policy file: {str(e)}")
            raise

    def _extract_principals(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Extract principals from policy statements"""
        principals = {
            'roles': set(),
            'users': set(),
            'services': set(),
            'caller_arn': None
        }
        
        for statement in policy.get('Statement', []):
            if 'Principal' in statement:
                principal = statement['Principal']
                if isinstance(principal, dict):
                    # AWS services
                    if 'Service' in principal:
                        services = principal['Service']
                        if isinstance(services, str):
                            principals['services'].add(services)
                        else:
                            principals['services'].update(services)
                    
                    # AWS accounts/users/roles
                    if 'AWS' in principal:
                        arns = principal['AWS']
                        if isinstance(arns, str):
                            arns = [arns]
                        for arn in arns:
                            if ':role/' in arn:
                                principals['roles'].add(arn.split('/')[-1])
                            elif ':user/' in arn:
                                principals['users'].add(arn.split('/')[-1])
                            else:
                                # Store full ARN as caller_arn if not a role/user
                                principals['caller_arn'] = arn
                                
        # Convert sets to lists
        return {
            'roles': list(principals['roles']),
            'users': list(principals['users']),
            'services': list(principals['services']),
            'caller_arn': principals['caller_arn']
        }

    def _get_affected_principals(self, matched_statements: List[Dict[str, Any]], 
                               principals: Dict[str, Any]) -> Dict[str, List[str]]:
        """Get principals affected by matched policy statements"""
        affected = {
            'roles': [],
            'users': [],
            'services': []
        }
        
        for statement in matched_statements:
            if 'Principal' in statement:
                principal = statement['Principal']
                if isinstance(principal, dict):
                    if 'Service' in principal:
                        affected['services'].extend(
                            [s for s in principals['services'] 
                             if s in principal['Service']]
                        )
                    if 'AWS' in principal:
                        for arn in principal['AWS']:
                            if ':role/' in arn:
                                role = arn.split('/')[-1]
                                if role in principals['roles']:
                                    affected['roles'].append(role)
                            elif ':user/' in arn:
                                user = arn.split('/')[-1]
                                if user in principals['users']:
                                    affected['users'].append(user)
                                    
        return affected 

    def _get_conditions(self, matched_statements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract conditions from matched policy statements"""
        conditions = []
        
        for statement in matched_statements:
            if 'Condition' in statement:
                for condition_type, condition_values in statement['Condition'].items():
                    for key, values in condition_values.items():
                        conditions.append({
                            'type': condition_type,
                            'key': key,
                            'values': values if isinstance(values, list) else [values]
                        })
        
        return conditions 