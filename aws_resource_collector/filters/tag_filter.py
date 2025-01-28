from typing import Dict, Any, Optional
from .exceptions import InvalidTagFormatError
import logging

class TagFilter:
    """Filter AWS resources based on required tags"""
    
    def __init__(self, required_tags: Dict[str, str] = None):
        """
        Initialize tag filter
        
        Args:
            required_tags: Dictionary of tag key-value pairs that must be present
            
        Raises:
            InvalidTagFormatError: If tag format is invalid
        """
        if not required_tags or 'ApplicationID' not in required_tags:
            raise ValueError("ApplicationID tag is required")
        self.required_tags = required_tags
        self.logger = logging.getLogger(__name__)
    
    def _validate_tags(self, tags: Dict[str, str]):
        """Validate tag format"""
        if not isinstance(tags, dict):
            raise InvalidTagFormatError("Tags must be a dictionary")
            
        for key, value in tags.items():
            if not isinstance(key, str):
                raise InvalidTagFormatError(f"Tag key must be string, got {type(key)}")
            if not isinstance(value, str):
                raise InvalidTagFormatError(f"Tag value must be string, got {type(value)}")
            if not key:
                raise InvalidTagFormatError("Tag key cannot be empty")
            if len(key) > 128:
                raise InvalidTagFormatError("Tag key cannot be longer than 128 characters")
            if len(value) > 256:
                raise InvalidTagFormatError("Tag value cannot be longer than 256 characters")
    
    def matches(self, resource: Dict[str, Any]) -> bool:
        """Check if resource has all required tags"""
        if not isinstance(resource, dict):
            raise InvalidTagFormatError("Resource must be a dictionary")
        
        # Get resource tags, handling different tag formats
        resource_tags = {}
        if 'Tags' in resource:
            # Handle list of tag dictionaries
            if isinstance(resource['Tags'], list):
                for tag in resource['Tags']:
                    if isinstance(tag, dict):
                        # Handle both Key/Value and TagKey/TagValue formats
                        if 'Key' in tag and 'Value' in tag:
                            resource_tags[tag['Key']] = tag['Value']
                        elif 'TagKey' in tag and 'TagValue' in tag:
                            resource_tags[tag['TagKey']] = tag['TagValue']
            # Handle dict format
            elif isinstance(resource['Tags'], dict):
                resource_tags = resource['Tags']
        elif 'tags' in resource:  # Some services use lowercase 'tags'
            resource_tags = resource['tags']

        self.logger.debug(f"Processed tags: {resource_tags}")

        # Check ApplicationID tag
        app_id = self.required_tags['ApplicationID']
        # First check direct key match
        if 'ApplicationID' in resource_tags:
            if resource_tags['ApplicationID'] != app_id:
                self.logger.debug(f"ApplicationID value mismatch. Expected {app_id}, got {resource_tags['ApplicationID']}")
                return False
        # Then check values
        elif app_id not in resource_tags.values():
            self.logger.debug(f"Resource missing ApplicationID tag {app_id}, found tags: {resource_tags}")
            return False

        # Check other required tags
        for key, value in self.required_tags.items():
            if key in resource_tags:
                if resource_tags[key] != value:
                    return False
            else:
                # Try to find tag in original format if present
                if isinstance(resource.get('Tags', []), list):
                    found = False
                    for tag in resource['Tags']:
                        if isinstance(tag, dict):
                            tag_key = tag.get('Key', tag.get('TagKey', ''))
                            tag_value = tag.get('Value', tag.get('TagValue', ''))
                            if tag_key == key and tag_value == value:
                                found = True
                                break
                    if not found:
                        return False
                else:
                    return False

        return True
    
    def _get_resource_tags(self, resource: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """
        Extract tags from resource in a consistent format
        
        Args:
            resource: AWS resource dictionary
            
        Returns:
            Dictionary of tag key-value pairs, or None if no tags found
            
        Raises:
            InvalidTagFormatError: If tag format is invalid
        """
        try:
            # Handle different tag formats across services
            if 'Tags' in resource:
                tags = resource['Tags']
                # Handle list of key-value dictionaries
                if isinstance(tags, list):
                    return {tag['Key']: tag['Value'] for tag in tags}
                # Handle direct key-value dictionary
                elif isinstance(tags, dict):
                    return tags
                else:
                    raise InvalidTagFormatError(f"Invalid Tags format: {type(tags)}")
                    
            # Handle inline tags
            elif 'TagList' in resource:
                tags = resource['TagList']
                if not isinstance(tags, list):
                    raise InvalidTagFormatError(f"Invalid TagList format: {type(tags)}")
                return {tag['Key']: tag['Value'] for tag in tags}
                
            # Handle tag sets (e.g. S3)
            elif 'TagSet' in resource:
                tags = resource['TagSet']
                if not isinstance(tags, list):
                    raise InvalidTagFormatError(f"Invalid TagSet format: {type(tags)}")
                return {tag['Key']: tag['Value'] for tag in tags}
                
            return None
            
        except (KeyError, TypeError) as e:
            raise InvalidTagFormatError(f"Invalid tag structure: {str(e)}") 