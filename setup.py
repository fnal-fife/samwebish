#!/usr/bin/env python
import os
import re

from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))

# read the version without importing version.py
with open(os.path.join(here, "version.py")) as f:
    version = re.search(r'samwebish_version\s*=\s*"([^"]*)"', f.read()).group(1)

setup(
    name="samwebish",
    version=version,
    description="sam-web like API for Rucio/MetaCat/DataDispatcher",
    author="Marc Mengel",
    author_email="mengel@fnal.gov",
    url="https://github.com/marcmengel/samwebish",
    py_modules=["samwebish", "metadata_converter", "version"],
    packages=["query_converter"],
    python_requires=">=3.7",
    install_requires=[
        "fastapi",
        "fastapi-utils",
        "fastapi-cgi",
        "pyparsing",
        "metacat-client",
        "datadispatcher-client",
        "rucio-clients",
    ]
)
