# Security Resources

Documentation for collecting AWS security resources including IAM, KMS, and Security Groups.

## Resource Types

### IAM Resources
- Roles and policies
- Users and groups
- Service-linked roles
- Policy versions
- Instance profiles

### KMS Resources
- Customer managed keys
- AWS managed keys
- Key policies
- Grants and aliases
- Key rotation status

### Security Group Resources
- Security group rules
- Inbound/outbound rules
- Referenced groups
- VPC associations

## Collection Process

```python
# Collect IAM resources
iam_collector = IAMCollector('output', tag_filter, settings)
iam_collector.collect()

# Collect KMS resources
kms_collector = KMSCollector('output', tag_filter, settings)
kms_collector.collect()

# Collect security groups
sg_collector = SecurityGroupCollector('output', tag_filter, settings)
sg_collector.collect()
```

## Related Resources

Security resources are collected with their relationships:

### Resource Associations
- EC2 instances
- RDS databases
- Lambda functions
- ECS tasks

### Cross-Service References
- Resource policies
- Service roles
- Key grants
- Security group references

## Output Structure

```
output_dir/
├── iam/
│   ├── roles/
│   ├── policies/
│   └── users/
├── kms/
│   ├── keys/
│   └── aliases/
└── security_groups/
    ├── vpc_groups/
    └── referenced_groups/
```

## Best Practices

1. **Access Management**
   - Role collection
   - Policy versioning
   - Cross-account access

2. **Encryption**
   - Key rotation
   - Grant management
   - Cross-region keys

3. **Network Security**
   - Rule organization
   - Group references
   - VPC boundaries

## KMS Keys

The KMS collector (`KMSCollector`) collects AWS KMS keys and their configurations.

### Collected Data

- Key metadata
- Tags
- Key policies
- Grants (if `include_global` is enabled)

### Example Output

```json
{
    "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
    "KeyMetadata": {
        "AWSAccountId": "123456789012",
        "KeyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
        "Arn": "arn:aws:kms:region:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        "CreationDate": "2023-01-01T00:00:00+00:00",
        "Enabled": true,
        "Description": "Example key",
        "KeyUsage": "ENCRYPT_DECRYPT",
        "KeyState": "Enabled",
        "Origin": "AWS_KMS",
        "KeyManager": "CUSTOMER"
    },
    "Tags": [
        {
            "Key": "ApplicationId",
            "Value": "myapp"
        }
    ],
    "Policy": {
        "Version": "2012-10-17",
        "Statement": [...]
    }
}
```

### Configuration

```json
{
    "resource_types": ["kms/keys"],
    "collector": {
        "include_global": true  // Include policies and grants
    }
}
```

## Security Groups

The Security Group collector (`SecurityGroupCollector`) collects EC2 security groups and their rules.

### Collected Data

- Basic security group information
- Inbound and outbound rules
- Tags
- Referenced security groups (if `include_global` is enabled)

### Example Output

```json
{
    "GroupId": "sg-1234567890abcdef0",
    "GroupName": "my-security-group",
    "Description": "Example security group",
    "VpcId": "vpc-1234567890abcdef0",
    "Tags": [
        {
            "Key": "ApplicationId",
            "Value": "myapp"
        }
    ],
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 80,
            "ToPort": 80,
            "IpRanges": [
                {
                    "CidrIp": "0.0.0.0/0"
                }
            ]
        }
    ],
    "IpPermissionsEgress": [...],
    "Rules": [...]  // Detailed rules if include_global is enabled
}
```

### Configuration

```json
{
    "resource_types": ["ec2/security_groups"],
    "collector": {
        "include_global": true  // Include detailed rules and referenced groups
    }
}
```

## Tag Filtering

Both KMS keys and security groups support tag-based filtering:

```json
{
    "required_tags": {
        "ApplicationId": "myapp",
        "Environment": "prod"
    }
}
```

For KMS keys:
- AWS managed keys are skipped unless `include_global` is enabled
- Customer managed keys must have all required tags

For security groups:
- Groups must have all required tags
- Referenced groups are collected regardless of tags if `include_global` is enabled

## Best Practices

1. **Tag Management**
   - Use consistent tagging across all security resources
   - Tag security groups when created
   - Tag KMS keys when created

2. **Access Control**
   - Ensure the collector has appropriate IAM permissions
   - Use least privilege access
   - Monitor access using CloudTrail

3. **Resource Organization**
   - Group related security resources using tags
   - Use descriptive names and descriptions
   - Document security group rules

## Required IAM Permissions

For KMS collection:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:ListKeys",
                "kms:DescribeKey",
                "kms:ListResourceTags",
                "kms:GetKeyPolicy",
                "kms:ListGrants"
            ],
            "Resource": "*"
        }
    ]
}
```

For security group collection:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSecurityGroupRules",
                "ec2:DescribeTags"
            ],
            "Resource": "*"
        }
    ]
}
``` 