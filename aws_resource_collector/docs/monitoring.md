# Monitoring Resources

Documentation for collecting AWS monitoring resources including CloudWatch and X-Ray.

## Resource Types

### CloudWatch Resources
- Metrics and alarms
- Dashboards
- Log groups and streams
- Metric filters
- Composite alarms

### X-Ray Resources
- Traces and segments
- Service maps
- Groups
- Sampling rules

## Collection Process

```python
# Collect CloudWatch resources
cw_collector = CloudWatchCollector('output', tag_filter, settings)
cw_collector.collect()

# Collect X-Ray resources
xray_collector = XRayCollector('output', tag_filter, settings)
xray_collector.collect()
```

## Related Resources

Monitoring resources are collected with their relationships:

### Target Resources
- Lambda functions
- EC2 instances
- RDS databases
- SNS topics

### Security Resources
- IAM roles
- KMS keys
- Service accounts

## Output Structure

```
output_dir/
├── cloudwatch/
│   ├── metrics/
│   ├── alarms/
│   ├── dashboards/
│   └── log_groups/
└── xray/
    ├── traces/
    ├── service_maps/
    └── sampling_rules/
``` 