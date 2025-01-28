# Compute Resources

Documentation for collecting AWS compute resources including EC2, Auto Scaling, and Batch.

## Resource Types

### EC2 Resources
- Instances and AMIs
- EBS volumes
- Network interfaces
- Placement groups
- Launch templates
- Spot requests

### Auto Scaling Resources
- Auto Scaling groups
- Launch configurations
- Scaling policies
- Lifecycle hooks
- Scheduled actions

### Batch Resources
- Compute environments
- Job queues
- Job definitions
- Jobs and job logs

## Collection Process

```python
# Collect EC2 resources
ec2_collector = EC2Collector('output', tag_filter, settings)
ec2_collector.collect()

# Collect Auto Scaling resources
asg_collector = AutoScalingCollector('output', tag_filter, settings)
asg_collector.collect()

# Collect Batch resources with global configs
settings.collector.include_global = True
batch_collector = BatchCollector('output', tag_filter, settings)
batch_collector.collect()
```

## Related Resources

Compute resources are collected with their relationships:

### Network Resources
- VPCs and subnets
- Security groups
- Network interfaces
- Elastic IPs

### Storage Resources
- EBS volumes
- Instance store volumes
- EFS mounts
- S3 buckets

### Security Resources
- IAM roles
- Instance profiles
- KMS keys
- Security groups

## Output Structure

```
output_dir/
├── ec2/
│   ├── instances/
│   ├── volumes/
│   └── amis/
├── autoscaling/
│   ├── groups/
│   └── configurations/
└── batch/
    ├── compute_environments/
    └── job_queues/
```

## Best Practices

1. **Instance Management**
   - Resource tagging
   - Volume management
   - AMI organization

2. **Scaling**
   - Group configurations
   - Scaling policies
   - Capacity management

3. **Performance**
   - Instance types
   - Placement strategies
   - Network optimization 