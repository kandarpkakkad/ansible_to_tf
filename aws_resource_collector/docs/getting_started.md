# Getting Started

## Installation

```bash
git clone https://github.com/yourusername/aws-resource-collector.git
cd aws-resource-collector
pip install -r requirements.txt
```

## Basic Usage

1. Create a configuration file:

```json
{
    "aws": {
        "region": "us-east-1",
        "profile": "default"
    },
    "required_tags": {
        "ApplicationId": "myapp"
    },
    "output_dir": "aws_inventory"
}
```

2. Run the collector:

```bash
python -m aws_resource_collector --config config.json
```

## Using as a Library

```python
from filters import TagFilter
from collectors import EC2Collector, S3Collector
from config import Settings

# Load settings
settings = Settings.load('config.json')

# Initialize tag filter
tag_filter = TagFilter(settings.required_tags)

# Initialize collectors
collectors = [
    EC2Collector('output', tag_filter, settings),
    S3Collector('output', tag_filter, settings)
]

# Collect resources
for collector in collectors:
    collector.collect()
```

## Command Line Options

- `--config`: Path to configuration file
- `--output-dir`: Override output directory
- `--application-id`: Override ApplicationID tag value
- `--log-level`: Override logging level
- `--log-file`: Override log file path

## Next Steps

- See [Configuration](configuration.md) for settings details
- See [Filters](filters.md) for filtering options
- See [Collectors](collectors.md) for available collectors
- See [Examples](examples/) for more examples 