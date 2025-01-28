# Messaging Resources

Documentation for collecting AWS messaging resources including SNS, SQS, and EventBridge.

## Resource Types

### SNS Resources
- Topics and subscriptions
- Message filtering
- Message delivery status
- Cross-region delivery

### SQS Resources
- Standard and FIFO queues
- Dead-letter queues
- Message attributes
- Queue policies

### EventBridge Resources
- Event buses
- Rules and targets
- Archives
- Schemas

## Collection Process

```python
# Collect SNS resources
sns_collector = SNSCollector('output', tag_filter, settings)
sns_collector.collect()

# Collect SQS resources
sqs_collector = SQSCollector('output', tag_filter, settings)
sqs_collector.collect()

# Collect EventBridge resources
events_collector = EventBridgeCollector('output', tag_filter, settings)
events_collector.collect()
```

## Related Resources

Messaging resources are collected with their relationships:

### Target Resources
- Lambda functions
- EC2 instances
- Step Functions
- API destinations

### Security Resources
- IAM roles
- KMS keys
- Security groups

## Output Structure

```
output_dir/
├── sns/
│   ├── topics/
│   └── subscriptions/
├── sqs/
│   ├── queues/
│   └── dead_letter_queues/
└── eventbridge/
    ├── buses/
    ├── rules/
    └── targets/
``` 