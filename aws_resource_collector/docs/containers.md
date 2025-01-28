# Container Resources

Documentation for collecting AWS container resources including ECS and EKS.

## Resource Types

### ECS Resources
- Clusters and services
- Task definitions
- Container instances
- Capacity providers
- Service discovery

### EKS Resources
- Kubernetes clusters
- Node groups
- Fargate profiles
- Add-ons and configurations

## Collection Process

```python
# Collect ECS resources
ecs_collector = ECSCollector('output', tag_filter, settings)
ecs_collector.collect()

# Collect EKS resources
eks_collector = EKSCollector('output', tag_filter, settings)
eks_collector.collect()
```

## Related Resources

Container resources are collected with their relationships:

### Network Resources
- VPC configurations
- Subnet assignments
- Security groups
- Load balancers

### Security Resources
- IAM roles
- Service accounts
- KMS keys
- Security groups

## Output Structure

```
output_dir/
├── ecs/
│   ├── clusters/
│   ├── services/
│   ├── task_definitions/
│   └── container_instances/
└── eks/
    ├── clusters/
    ├── node_groups/
    └── fargate_profiles/
``` 