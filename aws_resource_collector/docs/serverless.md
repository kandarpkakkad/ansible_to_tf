# Serverless Resources

Documentation for collecting AWS serverless resources including Lambda and Step Functions.

## Resource Types

### Lambda Resources
- Functions and versions
- Function configurations
- Layer versions
- Event source mappings
- Function URLs
- Code signing configs

### Step Functions Resources
- State machines
- Executions
- Activities
- Express workflows

## Collection Process

```python
# Collect Lambda resources
lambda_collector = LambdaCollector('output', tag_filter, settings)
lambda_collector.collect()

# Collect Step Functions resources with global configs
settings.collector.include_global = True
sfn_collector = StepFunctionsCollector('output', tag_filter, settings)
sfn_collector.collect()
```

## Related Resources

Serverless resources are collected with their relationships:

### Network Resources
- VPC configurations
- Subnet assignments
- Security groups
- VPC endpoints

### Security Resources
- IAM roles and policies
- KMS keys for encryption
- Code signing configs
- Layer permissions

## Output Structure

```
output_dir/
├── lambda/
│   ├── functions/
│   │   └── versions/
│   ├── layers/
│   └── event_sources/
└── stepfunctions/
    ├── state_machines/
    └── activities/
```

## Best Practices

1. **Function Management**
   - Version tracking
   - Layer organization
   - Memory optimization

2. **Security**
   - IAM role collection
   - VPC access
   - KMS key management 