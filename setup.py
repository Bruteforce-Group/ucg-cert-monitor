#!/usr/bin/env python3
"""
UCG Certificate Monitor - Setup and Installation Script
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return f.read()

# Get requirements from requirements.txt
def get_requirements():
    with open('requirements.txt', 'r') as f:
        requirements = f.read().splitlines()
    
    # Filter out comments and empty lines
    requirements = [req.strip() for req in requirements if req.strip() and not req.startswith('#')]
    
    # Remove version specifiers for packages that might cause issues
    clean_requirements = []
    for req in requirements:
        if req.startswith('sqlite3'):
            continue  # sqlite3 is built-in to Python
        if req.startswith('smtplib'):
            continue  # smtplib is built-in to Python
        if req.startswith('ipaddress'):
            continue  # ipaddress is built-in to Python
        clean_requirements.append(req)
    
    return clean_requirements

setup(
    name='ucg-cert-monitor',
    version='1.0.0',
    description='UCG Certificate Monitor - Real-time certificate monitoring and alerting for Universal Customer Gateways',
    long_description=read_file('README.md') if os.path.exists('README.md') else 'UCG Certificate Monitor',
    long_description_content_type='text/markdown',
    author='UCG Certificate Monitor Team',
    author_email='admin@example.com',
    url='https://github.com/example/ucg-cert-monitor',
    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    python_requires='>=3.8',
    install_requires=get_requirements(),
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'pytest-asyncio>=0.20.0',
            'pytest-cov>=4.0.0',
            'black>=22.0.0',
            'flake8>=5.0.0',
            'mypy>=0.991',
        ],
        'dashboard': [
            'flask>=2.0.0',
            'flask-socketio>=5.0.0',
        ]
    },
    entry_points={
        'console_scripts': [
            'ucg-cert-monitor=main:cli',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
    ],
    keywords='certificate monitoring ucg gateway security tls ssl',
    project_urls={
        'Bug Reports': 'https://github.com/example/ucg-cert-monitor/issues',
        'Source': 'https://github.com/example/ucg-cert-monitor',
        'Documentation': 'https://github.com/example/ucg-cert-monitor/docs',
    },
    include_package_data=True,
    package_data={
        '': ['*.yaml', '*.yml', '*.json', '*.md', '*.txt'],
    },
)
