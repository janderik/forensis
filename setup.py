"""Forensis - Digital Forensics Toolkit."""

from pathlib import Path

from setuptools import find_packages, setup

here = Path(__file__).parent

with open(here / "README.md", encoding="utf-8") as f:
    long_description = f.read()

with open(here / "requirements.txt", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="forensis",
    version="1.0.0",
    description="Digital Forensics Toolkit for memory analysis, disk forensics, timeline reconstruction, hashing, and reporting.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Forensis Contributors",
    author_email="forensis@example.com",
    url="https://github.com/forensis/forensis",
    license="MIT",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Legal Practice",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Archiving :: Backup",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "forensis=forensis.cli:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
