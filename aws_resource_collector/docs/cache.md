# ElastiCache Resources

The AWS Resource Collector can collect ElastiCache resources and their related configurations.

## Resource Types

### Cache Clusters
- Standalone cache clusters
- Node configurations
- Engine versions and parameters
- VPC and subnet configurations
- Security group associations

### Replication Groups
- Primary and replica nodes
- Node group configurations
- Multi-AZ settings
- Automatic failover settings
- Global datastore associations

### Subnet Groups
- VPC configurations
- Subnet assignments
- Availability zone distribution
- Network configurations

### User Groups
- User management
- Authentication settings
- Access patterns
- User permissions

### Global Configurations
- Global replication groups
- Reserved nodes
- Parameter groups
- Engine-specific settings

## Collection Process

The ElastiCacheCollector follows this process:

1. **Standalone Clusters**
```python
# Collect standalone clusters
collector = ElastiCacheCollector('output', tag_filter, settings)
collector.collect()
```

2. **Replication Groups**
```python
# Enable global collection for replication groups
settings.collector.include_global = True
collector.collect()
```

## Related Resources

ElastiCache resources are collected with their relationships:

### Network Resources
- VPC configurations
- Subnet assignments
- Security group rules
- Network ACLs

### Security Resources
- IAM roles
- Security groups
- KMS keys (if encryption enabled)

## Output Structure

```
output_dir/
├── elasticache/
│   ├── clusters/                    # Standalone clusters
│   ├── replication_groups/          # Replication groups
│   │   └── members/                 # Member nodes
│   ├── subnet_groups/              # Subnet configurations
│   ├── user_groups/                # User management
│   ├── parameter_groups/           # Parameter settings
│   └── reserved_nodes/             # Reserved capacity
```

## Configuration Options

Enable specific ElastiCache features:

```json
{
    "collector": {
        "include_global": true,      // Collect global resources
        "skip_empty": false,         // Include empty clusters
        "batch_size": 100           // Resources per batch
    }
}
```

## Best Practices

1. **Resource Organization**
   - Group related clusters
   - Maintain consistent naming
   - Use proper tagging

2. **Performance**
   - Use appropriate batch sizes
   - Enable pagination
   - Handle timeouts

3. **Security**
   - Collect security groups
   - Track encryption settings
   - Monitor access patterns

4. **Maintenance**
   - Regular collection
   - Version tracking
   - Parameter monitoring 