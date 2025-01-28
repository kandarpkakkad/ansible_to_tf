# AWS Resource Collector

A tool for collecting and documenting AWS resources and their relationships.

## Overview

The AWS Resource Collector helps you:
- Collect AWS resources across multiple services
- Track resource relationships and dependencies
- Document infrastructure configurations
- Maintain resource inventory

## Features

### Resource Collection
- EC2, RDS, Lambda, and other compute resources
- VPC, subnet, and network configurations
- S3, DynamoDB, and storage resources
- Container services (ECS, EKS)
- Security groups and IAM resources
- Monitoring and messaging services

### Relationship Tracking
- Automatically collects related resources
- Maps dependencies between services
- Tracks security group references
- Documents IAM role usage

### Configuration Management
- JSON-based configuration
- Environment variable support
- Tag-based filtering
- Resource organization

## Installation

```bash
pip install aws-resource-collector
```

## Quick Start

1. Create configuration file:
```json
{
    "aws": {
        "region": "us-east-1",
        "profile": "default"
    },
    "collector": {
        "include_global": true,
        "batch_size": 100
    }
}
```

2. Run collection:
```python
from aws_resource_collector import ResourceCollector
from aws_resource_collector.filters import TagFilter

# Initialize collector
collector = ResourceCollector('output', config_file='config.json')

# Add tag filter
collector.add_filter(TagFilter({
    'ApplicationId': 'myapp',
    'Environment': 'prod'
}))

# Collect resources
collector.collect()
```

## Resource Types

### Compute Resources
- EC2 instances and AMIs
- RDS databases
- Lambda functions
- ECS/EKS containers

### Network Resources
- VPCs and subnets
- Security groups
- Route tables
- Load balancers

### Storage Resources
- S3 buckets
- DynamoDB tables
- EFS file systems
- EBS volumes

### Security Resources
- IAM roles and policies
- KMS keys
- Security groups
- Resource policies

### Container Resources
- ECS clusters and services
- EKS clusters and node groups
- ECR repositories
- Fargate profiles

### Monitoring Resources
- CloudWatch metrics and alarms
- Log groups
- EventBridge rules

## Documentation

- [Configuration Guide](configuration.md)
- [Collector Documentation](collectors.md)
- [Examples](examples.md)
- [Security](security.md)

## Best Practices

1. **Resource Organization**
   - Use consistent tagging
   - Group related resources
   - Document relationships

2. **Performance**
   - Configure batch sizes
   - Enable pagination
   - Handle rate limits

3. **Security**
   - Use minimal IAM permissions
   - Track encryption settings
   - Monitor access patterns

4. **Maintenance**
   - Regular collection
   - Version tracking
   - Update documentation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 