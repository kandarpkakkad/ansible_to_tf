# Storage Resources

Documentation for collecting AWS storage resources including S3, DynamoDB, and EFS.

## Resource Types

### S3 Resources
- Buckets and objects
- Bucket policies
- Encryption settings
- Lifecycle rules
- Replication configurations
- Access points

### DynamoDB Resources
- Tables and indexes
- Global tables
- Backups
- Streams
- DAX clusters
- Auto scaling settings

### EFS Resources
- File systems
- Mount targets
- Access points
- Backup policies
- Lifecycle management
- Replication configurations

## Collection Process

```python
# Collect S3 resources
s3_collector = S3Collector('output', tag_filter, settings)
s3_collector.collect()

# Collect DynamoDB resources with global configs
settings.collector.include_global = True
dynamo_collector = DynamoDBCollector('output', tag_filter, settings)
dynamo_collector.collect()

# Collect EFS resources
efs_collector = EFSCollector('output', tag_filter, settings)
efs_collector.collect()
```

## Related Resources

Storage resources are collected with their relationships:

### Network Resources
- VPC endpoints
- Mount target subnets
- Security groups
- Network ACLs

### Security Resources
- IAM roles and policies
- KMS keys for encryption
- Bucket policies
- Access points

## Output Structure

```
output_dir/
├── s3/
│   ├── buckets/
│   │   ├── policies/
│   │   └── lifecycle/
│   └── access_points/
├── dynamodb/
│   ├── tables/
│   │   └── backups/
│   └── global_tables/
└── efs/
    ├── filesystems/
    ├── mount_targets/
    └── access_points/
```

## Best Practices

1. **Data Organization**
   - Bucket structure
   - Table design
   - Mount point management

2. **Performance**
   - Access patterns
   - Throughput settings
   - Caching strategies

3. **Security**
   - Encryption settings
   - Access controls
   - Network isolation 