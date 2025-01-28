#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

def main():
    """Run Black formatter on the codebase"""
    root_dir = Path(__file__).parent.parent
    src_dir = root_dir / "aws_resource_collector"
    
    try:
        subprocess.run(
            ["black", str(src_dir)],
            check=True
        )
        print("Successfully formatted code with Black")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"Error running Black: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 