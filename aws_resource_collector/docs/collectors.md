# Resource Collectors

The AWS Resource Collector provides specialized collectors for each AWS service type. Each collector handles resource collection and automatically gathers related resources.

## Core Collectors

### Compute Resources
- **EC2Collector**: Collects EC2 instances and related resources
  - VPC, subnet, security group relationships
  - KMS keys for encrypted volumes
  - IAM roles from instance profiles

### Network Resources
- **VPCCollector**: Collects VPC infrastructure
  - Subnets and their configurations
  - Route tables and NACLs
  - VPC endpoints and peering connections
  - Transit gateway attachments

### Storage Resources
- **S3Collector**: Collects S3 buckets and configurations
  - KMS keys for encrypted buckets
  - IAM roles from bucket policies
- **DynamoDBCollector**: Collects DynamoDB tables
  - KMS keys for encrypted tables
  - IAM roles from table policies

### Database Resources
- **RDSCollector**: Collects RDS instances
  - VPC and subnet relationships
  - Security group configurations
  - KMS keys for encryption
- **ElastiCacheCollector**: Collects ElastiCache resources
  - Clusters and replication groups
  - Subnet groups and security groups
  - User groups and parameter groups

### Security Resources
- **KMSCollector**: Collects KMS keys and policies
  - Key grants and aliases
  - IAM roles from key policies
- **SecurityGroupCollector**: Collects security groups
  - Inbound and outbound rules
  - Referenced security groups

## Monitoring Resources
- **CloudWatchCollector**: Collects CloudWatch resources
  - Metrics and alarms
  - Dashboards
  - Log groups and streams
  - Metric filters
  - Composite alarms

## Resource Relationships

The collectors automatically handle resource relationships through the RelatedResourceCollector:

```python
# Example: EC2 instance collection with relationships
instance = ec2.describe_instances()['Reservations'][0]['Instances'][0]

# Automatically collect related resources
self.related.collect_subnet(instance['SubnetId'])
for sg in instance['SecurityGroups']:
    self.related.collect_security_group(sg['GroupId'])
```

## Configuration

Enable collection of related resources in your config:

```json
{
    "collector": {
        "include_global": true,  // Collect global resources
        "batch_size": 100,       // Resources per batch
        "max_threads": 5         // Concurrent collections
    }
}
```

## Output Organization

Resources are organized by service and type:
```
output_dir/
├── ec2/
│   ├── instances/           # EC2 instances
│   ├── security_groups/     # Security groups
│   └── vpcs/               # VPC resources
│       ├── subnets/        # Subnet configurations
│       └── route_tables/   # Routing information
├── rds/
│   ├── instances/          # RDS instances
│   └── subnet_groups/      # DB subnet groups
└── kms/
    └── keys/               # KMS keys and policies
```

## Best Practices

1. **Resource Collection**
   - Use appropriate tag filters
   - Enable global resource collection when needed
   - Handle pagination for large resource sets

2. **Error Handling**
   - Handle missing resources gracefully
   - Log collection errors appropriately
   - Continue on individual failures

3. **Performance**
   - Use batch processing for large collections
   - Configure appropriate timeouts
   - Monitor API rate limits 