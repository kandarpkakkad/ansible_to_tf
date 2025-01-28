# Filters

The AWS Resource Collector uses tag-based filtering to control which resources are collected.

## Tag Filter

The `TagFilter` class filters AWS resources based on their tags. Resources must have all specified tags with matching values to be included.

### Usage

```python
from filters import TagFilter

# Create filter requiring specific tags
filter = TagFilter({
    'ApplicationId': 'myapp',
    'Environment': 'prod'
})

# Check if resource matches
matches = filter.matches(resource)
```

### Tag Formats

The filter handles different AWS tag formats:

- List format: `{'Tags': [{'Key': 'Name', 'Value': 'value'}]}`
- Dictionary format: `{'Tags': {'Name': 'value'}}`
- TagList format: `{'TagList': [{'Key': 'Name', 'Value': 'value'}]}`
- TagSet format: `{'TagSet': [{'Key': 'Name', 'Value': 'value'}]}`

### Required Tags

The ApplicationId tag is required for all resources. Additional tags can be specified as needed:

```python
# Basic tag filter with just ApplicationId
filter = TagFilter({'ApplicationId': 'myapp'})

# Filter with multiple required tags
filter = TagFilter({
    'ApplicationId': 'myapp',
    'Environment': 'prod',
    'CostCenter': '12345'
})
```

### Configuration

Tags can be configured in the settings file:

```json
{
    "required_tags": {
        "ApplicationId": "myapp",
        "Environment": "prod"
    }
}
```

Or via environment variables:
```bash
export REQUIRED_TAG_APPLICATION_ID=myapp
```

Or via command line:
```bash
python -m aws_resource_collector --application-id=myapp
```

See [examples](examples/) for more usage examples. 