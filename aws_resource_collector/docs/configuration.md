# Configuration

The AWS Resource Collector can be configured through a JSON file, environment variables, or command line arguments.

## Configuration File

```json
{
    "aws": {
        "region": "us-east-1",
        "profile": "default",
        "max_retries": 3,
        "timeout": 30
    },
    "collector": {
        "batch_size": 100,
        "max_threads": 5,
        "skip_empty": true,
        "include_global": true
    },
    "required_tags": {
        "ApplicationId": "myapp",
        "Environment": "prod"
    },
    "output_dir": "aws_inventory",
    "log_level": "INFO",
    "log_file": "collector.log"
}
```

## Environment Variables

AWS Settings:
```bash
export AWS_REGION=us-east-1
export AWS_PROFILE=default
export AWS_MAX_RETRIES=3
export AWS_TIMEOUT=30
```

Collector Settings:
```bash
export COLLECTOR_BATCH_SIZE=100
export COLLECTOR_MAX_THREADS=5
export COLLECTOR_SKIP_EMPTY=true
export COLLECTOR_INCLUDE_GLOBAL=true
```

Tag Settings:
```bash
export REQUIRED_TAG_APPLICATION_ID=myapp
```

Output Settings:
```bash
export OUTPUT_DIR=aws_inventory
export LOG_LEVEL=INFO
export LOG_FILE=collector.log
```

## Command Line Arguments

```bash
python -m aws_resource_collector \
    --config config.json \
    --output-dir aws_inventory \
    --application-id myapp \
    --log-level INFO \
    --log-file collector.log
```

## Settings Reference

### AWS Settings

- `region`: AWS region (default: us-east-1)
- `profile`: AWS credential profile (optional)
- `max_retries`: Maximum API retry attempts (1-10)
- `timeout`: API timeout in seconds (1-300)

### Collector Settings

- `batch_size`: Number of items to process in batch (1-1000)
- `max_threads`: Maximum concurrent threads (1-20)
- `skip_empty`: Skip resources with no data
- `include_global`: Include global resource configurations

### Required Tags

- `ApplicationId`: Required application identifier
- Additional tags as needed

### Output Settings

- `output_dir`: Directory for collected resources
- `log_level`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `log_file`: Log file path (optional) 