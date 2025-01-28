# AWS Resource Collector

...

## Development

### Code Formatting

This project uses Black for code formatting. To format the code:

1. Install development dependencies:
```bash
pip install -r requirements.txt
```

2. Run the formatter:
```bash
python scripts/format.py
```

Or use Black directly:
```bash
black aws_resource_collector
```

### Pre-commit Hooks

To enable automatic formatting on commit:

1. Install pre-commit:
```bash
pip install pre-commit
```

2. Install the git hooks:
```bash
pre-commit install
```

... 