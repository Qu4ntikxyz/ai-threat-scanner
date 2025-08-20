"""
Setup configuration for AI Threat Scanner

Enterprise-grade security analysis for Large Language Models
"""

from setuptools import setup, find_packages
import os
import sys

# Ensure Python 3.8+
if sys.version_info < (3, 8):
    sys.exit("AI Threat Scanner requires Python 3.8 or higher.")

# Read the README for long description
def read_long_description():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read version from __init__.py
def get_version():
    init_file = os.path.join("src", "__init__.py")
    with open(init_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().strip('"').strip("'")
    return "0.2.0"

setup(
    name="ai-threat-scanner",
    version=get_version(),
    author="Qu4ntik Security Research",
    author_email="me@qu4ntik.xyz",
    description="Enterprise-grade security analysis for Large Language Models with multi-turn attack detection",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/Qu4ntikxyz/ai-threat-scanner",
    project_urls={
        "Bug Reports": "https://github.com/Qu4ntikxyz/ai-threat-scanner/issues",
        "Source": "https://github.com/Qu4ntikxyz/ai-threat-scanner",
        "Documentation": "https://github.com/Qu4ntikxyz/ai-threat-scanner/wiki",
        "Changelog": "https://github.com/Qu4ntikxyz/ai-threat-scanner/blob/main/CHANGELOG.md",
        "Discussions": "https://github.com/Qu4ntikxyz/ai-threat-scanner/discussions",
    },
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "ai_threat_scanner": [
            "patterns/*.json",
            "data/*.json",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Zero dependencies! Pure Python implementation
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "pylint>=2.15.0",
            "isort>=5.11.0",
        ],
        "docs": [
            "mkdocs>=1.4.0",
            "mkdocs-material>=9.0.0",
            "mkdocstrings[python]>=0.20.0",
        ],
        "benchmark": [
            "memory-profiler>=0.60.0",
            "line-profiler>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ai-threat-scanner=ai_threat_scanner.cli:main",
            "ats=ai_threat_scanner.cli:main",  # Short alias
        ],
    },
    keywords=[
        "ai",
        "security",
        "llm",
        "threat-detection",
        "prompt-injection",
        "jailbreak",
        "conversation-analysis",
        "constraint-erosion",
        "attack-chains",
        "multi-turn-analysis",
        "ai-safety",
        "vulnerability-scanner",
        "security-testing",
        "red-teaming",
        "adversarial-testing",
    ],
    platforms=["any"],
    zip_safe=False,
    include_package_data=True,
    # Additional metadata
    license="MIT",
    maintainer="Qu4ntik Security Research",
    maintainer_email="me@qu4ntik.xyz",
)