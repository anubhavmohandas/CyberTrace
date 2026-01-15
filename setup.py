"""Setup script for CyberTrace."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="cybertrace",
    version="1.0.0",
    author="Anubhav Mohandas",
    author_email="",
    description="Multi-Layer OSINT Investigation Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/anubhavmohandas/cybertrace",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "aiohttp>=3.8.0",
        "python-dotenv>=1.0.0",
        "dnspython>=2.2.0",
        "python-whois>=0.8.0",
        "rich>=13.0.0",
    ],
    extras_require={
        "tor": ["PySocks>=1.7.0", "stem>=1.8.0"],
        "dev": ["pytest>=7.0.0", "pytest-asyncio>=0.21.0"],
    },
    entry_points={
        "console_scripts": [
            "cybertrace=cybertrace.cli:main",
        ],
    },
)
