# Network Resources

The AWS Resource Collector can collect various network components including VPCs, subnets, and their related resources.

## Subnets

### Collection

Subnets are collected as part of the VPC collection process. For each VPC that matches the tag filters, all associated subnets are collected.

### Data Structure

```json
{
    "SubnetId": "subnet-1234567890abcdef0",
    "VpcId": "vpc-0987654321fedcba0",
    "CidrBlock": "10.0.1.0/24",
    "AvailabilityZone": "us-east-1a",
    "State": "available",
    "MapPublicIpOnLaunch": false,
    "Tags": [
        {
            "Key": "ApplicationId",
            "Value": "myapp"
        },
        {
            "Key": "Name",
            "Value": "private-subnet-1"
        }
    ],
    "RouteTables": [...],
    "NetworkAcls": [...]
}
```

### Configuration

Enable collection of additional subnet configurations:

```json
{
    "collector": {
        "include_global": true
    }
}
```

This will include:
- Route table associations
- Network ACL associations
- Subnet attributes

### Tag Filtering

Subnets must have the required tags to be collected:

```python
from filters import TagFilter

# Filter subnets by tags
tag_filter = TagFilter({
    'ApplicationId': 'myapp',
    'Environment': 'prod',
    'Tier': 'private'
})
```

## Examples

### Basic Subnet Collection

```python
from filters import TagFilter
from collectors import VPCCollector
from config import Settings

# Initialize settings
settings = Settings.load('config.json')

# Initialize tag filter
tag_filter = TagFilter({
    'ApplicationId': 'myapp',
    'Environment': 'prod'
})

# Collect VPCs and subnets
collector = VPCCollector('output', tag_filter, settings)
collector.collect()
```

### Advanced Subnet Configuration

```python
# Enable collection of additional configurations
settings.collector.include_global = True

# Initialize tag filter with subnet-specific tags
tag_filter = TagFilter({
    'ApplicationId': 'myapp',
    'Environment': 'prod',
    'Tier': 'private',
    'Purpose': 'application'
})

# Collect VPCs and detailed subnet configurations
collector = VPCCollector('output', tag_filter, settings)
collector.collect()
```

### Output Organization

Collected subnets are organized under their VPC:
```
output_dir/
├── ec2/
│   └── vpcs/
│       └── vpc-1234567890abcdef0/
│           └── subnets/
│               ├── subnet-1234567890abcdef0.json
│               └── subnet-0987654321fedcba0.json
```

## Related Resources

When `include_global` is enabled, the following related resources are also collected:

### Route Tables
- Main route table
- Custom route tables
- Route table associations

### Network ACLs
- Default network ACL
- Custom network ACLs
- NACL rules and associations

### Internet Gateways
- Attached internet gateways
- Gateway configurations

### NAT Gateways
- NAT gateway details
- Elastic IP associations
- Subnet placement

### Transit Gateways
- Transit gateway attachments
- Transit gateway details
- Routing configurations

## Best Practices

1. **Tagging Strategy**
   - Use consistent tags across VPCs and subnets
   - Tag subnets with their tier (public/private)
   - Include purpose or workload tags

2. **Collection Organization**
   - Enable `include_global` for complete configuration
   - Collect related resources for full context
   - Use specific tags to filter relevant subnets

3. **Resource Management**
   - Group related subnets under the same VPC
   - Maintain consistent CIDR block allocation
   - Document subnet purposes through tags 