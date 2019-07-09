#!/usr/bin/env python
# Copyright (c) 2017, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""
Description: Build a STIX Indicator document containing a File observable with
an associated hash.
"""

from stix.core import STIXPackage# Imporet the STIX Package API
from stix.report import Report# Import the STIX Report API
from stix.report.header import Header# Import the STIX Report Header API
stix_package = STIXPackage()# Create an instance of STIX
stix_report = Report()# Create a Report instance
stix_report.header = Header()# Create a header for the report
stix_report.header.description = "Getting Started!"# Set the description
stix_package.add(stix_report)# Add the report to our STIX Package
print(stix_package.to_xml())