#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor - Setup Script
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open("requirements.txt") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#"):
            requirements.append(line)

setup(
    name="crown-jewel-monitor",
    version="1.0.0",
    author="Crown Jewel Monitor Team",
    author_email="monitoring-support@company.com",
    description="Agentic Post-Deployment Monitoring and Auto-Remediation System for Java Applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/company/crown-jewel-monitor",
    
    packages=find_packages(),
    
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    
    python_requires=">=3.8",
    install_requires=requirements,
    
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.11.0",
            "pytest-cov>=4.1.0",
            "httpx>=0.24.0",
            "flake8>=6.0.0",
            "black>=23.0.0",
            "mypy>=1.4.0",
        ],
        "ml": [
            "spacy>=3.6.0",
            "textblob>=0.17.0",
            "transformers>=4.30.0",
            "torch>=2.0.0",
            "nltk>=3.8.0",
        ],
    },
    
    entry_points={
        "console_scripts": [
            "crown-jewel-monitor=crown_jewel_monitor.main:cli_main",
        ],
    },
    
    package_data={
        "crown_jewel_monitor": [
            "config/*.yaml",
            "templates/*.j2",
        ],
    },
    
    include_package_data=True,
    zip_safe=False,
    
    keywords="monitoring java application agentic automation remediation",
    
    project_urls={
        "Bug Reports": "https://github.com/company/crown-jewel-monitor/issues",
        "Source": "https://github.com/company/crown-jewel-monitor",
        "Documentation": "https://crown-jewel-monitor.readthedocs.io/",
    },
)