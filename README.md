# DNS Threat Hunt using Splunk

## Overview

This project documents a DNS threat hunt performed against Zeek DNS logs using Splunk.

## Objectives

- Detect abnormal DNS activity
- Identify DNS beaconing
- Detect DNS tunneling
- Investigate potential C2 traffic

## Tools

- Splunk Enterprise
- SPL
- Zeek DNS Logs

## Findings

Four threat hunts were performed:

- Query Volume Analysis
- NXDOMAIN Analysis
- Beaconing Detection
- DNS Tunneling Detection

One compromised host was identified communicating with `rssfeeds.com` using DNS TXT records consistent with DNS tunneling.

## MITRE ATT&CK

- T1071.004
- T1132
- T1048.003

## Report

See:
