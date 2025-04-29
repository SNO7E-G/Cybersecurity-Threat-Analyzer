#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="cybersecurity-threat-analyzer",
    version="2.0.0",
    author="Mahmoud Ashraf (SNO7E)",
    author_email="mahmoud@sno7e.com",
    description="An advanced network security monitoring and threat detection system with ML integration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/SNO7E-G/Cybersecurity-Threat-Analyzer",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cybersecurity-threat-analyzer=manage:main",
        ],
    },
) 