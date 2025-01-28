from typing import List, Optional
from .exceptions import InvalidResourceTypeError

class ResourceFilter:
    """Filter AWS resources based on resource types"""
    
    VALID_SERVICES = {
        'ec2', 's3', 'dynamodb', 'rds', 'elasticache', 'redshift',
        'cloudwatch', 'xray', 'sns', 'sqs', 'eventbridge', 'lambda',
        'apigateway', 'efs', 'ecr', 'ecs', 'kms'
    }
    
    def __init__(self, resource_types: Optional[List[str]] = None):
        """
        Initialize resource filter
        
        Args:
            resource_types: Optional list of resource types to include
                          Format: service/type (e.g. ec2/instances)
                          
        Raises:
            InvalidResourceTypeError: If resource type format is invalid
        """
        if resource_types:
            self._validate_resource_types(resource_types)
            self.resource_types = set(resource_types)
        else:
            self.resource_types = None
    
    def _validate_resource_types(self, resource_types: List[str]):
        """Validate resource type format"""
        if not isinstance(resource_types, list):
            raise InvalidResourceTypeError("Resource types must be a list")
            
        for resource_type in resource_types:
            if not isinstance(resource_type, str):
                raise InvalidResourceTypeError(
                    f"Resource type must be string, got {type(resource_type)}"
                )
                
            parts = resource_type.split('/')
            if len(parts) > 2:
                raise InvalidResourceTypeError(
                    f"Invalid resource type format: {resource_type}"
                )
                
            service = parts[0]
            if service not in self.VALID_SERVICES:
                raise InvalidResourceTypeError(
                    f"Invalid service: {service}. Must be one of {sorted(self.VALID_SERVICES)}"
                )
    
    def matches(self, resource_type: str) -> bool:
        """
        Check if resource type should be included
        
        Args:
            resource_type: Resource type string (e.g. ec2/instances)
            
        Returns:
            bool: True if resource type should be included
            
        Raises:
            InvalidResourceTypeError: If resource type format is invalid
        """
        if not self.resource_types:
            return True
            
        if not isinstance(resource_type, str):
            raise InvalidResourceTypeError(
                f"Resource type must be string, got {type(resource_type)}"
            )
            
        parts = resource_type.split('/')
        if len(parts) > 2:
            raise InvalidResourceTypeError(
                f"Invalid resource type format: {resource_type}"
            )
            
        service = parts[0]
        if service not in self.VALID_SERVICES:
            raise InvalidResourceTypeError(
                f"Invalid service: {service}. Must be one of {sorted(self.VALID_SERVICES)}"
            )
            
        # Check exact match
        if resource_type in self.resource_types:
            return True
            
        # Check service-level match
        if service in self.resource_types:
            return True
            
        return False
    
    def get_services(self) -> List[str]:
        """
        Get list of services to collect
        
        Returns:
            List of service names (e.g. ['ec2', 's3'])
        """
        if not self.resource_types:
            return []
            
        services = set()
        for resource_type in self.resource_types:
            services.add(resource_type.split('/')[0])
        return sorted(list(services)) 