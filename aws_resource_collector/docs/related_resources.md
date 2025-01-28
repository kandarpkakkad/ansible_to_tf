# Related Resources

The AWS Resource Collector automatically collects related resources to provide a complete view of your AWS infrastructure.

## Resource Relationships

### EC2 Instances
- VPC
- Subnet
- Security Groups
- KMS Keys (if encrypted)
- IAM Roles (from instance profile)

### VPC Resources
- Subnets
- Route Tables
- Network ACLs
- Internet Gateways
- NAT Gateways
- VPC Endpoints
- VPC Peering Connections
- Transit Gateway Attachments

### Security Groups
- VPC
- Referenced Security Groups
- IAM Roles (from policies)

### KMS Keys
- IAM Roles (from key policies)
- Grants
- Aliases

### IAM Resources
- Roles
- Attached Policies
- Inline Policies
- Service-Linked Roles

## Collection Process

Related resources are collected automatically when:
1. A primary resource references them
2. They are part of the same infrastructure unit
3. They share security or access control configurations

### Example Flow

When collecting an EC2 instance:
```
EC2 Instance
├── VPC
│   ├── Subnets
│   ├── Route Tables
│   └── Network ACLs
├── Security Groups
│   └── Referenced Security Groups
├── KMS Keys
│   └── IAM Roles (from key policies)
└── IAM Instance Profile
    └── IAM Roles
```

## Configuration

Enable collection of additional related resources:

```json
{
    "collector": {
        "include_global": true
    }
}
```

## Examples

### Basic Collection

```python
from collectors import EC2Collector
from filters import TagFilter

# Initialize collector
collector = EC2Collector('output', tag_filter, settings)

# Collect instance and related resources
collector.collect()
```

### Advanced Collection

```python
# Enable collection of global resources
settings.collector.include_global = True

# Initialize collector
collector = EC2Collector('output', tag_filter, settings)

# Collect with full relationships
collected_files = collector.collect()

# Process collected resources
for file_path in collected_files:
    if '/security_groups/' in file_path:
        print(f"Found related security group: {file_path}")
    elif '/subnets/' in file_path:
        print(f"Found related subnet: {file_path}")
    elif '/kms/keys/' in file_path:
        print(f"Found related KMS key: {file_path}")
```

## Output Structure

```
output_dir/
├── ec2/
│   ├── instances/
│   ├── security_groups/
│   ├── vpcs/
│   │   └── vpc-id/
│   │       ├── subnets/
│   │       ├── route_tables/
│   │       └── network_acls/
│   └── vpc_endpoints/
├── kms/
│   └── keys/
└── iam/
    └── roles/
```

## Best Practices

1. **Enable Global Collection**
   - Set `include_global = true` to collect all related resources
   - Helps maintain complete infrastructure view
   - Important for security auditing

2. **Resource Organization**
   - Keep related resources under their parent directory
   - Use consistent naming for resource files
   - Maintain relationship hierarchy

3. **Error Handling**
   - Handle missing related resources gracefully
   - Log relationship collection errors
   - Continue collection on individual resource failures 