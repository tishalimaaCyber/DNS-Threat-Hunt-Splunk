# DNS Threat Hunt using Splunk

## Overview
This project documents a DNS threat hunt performed against Zeek DNS logs using Splunk. The investigation analyzed ~422,000 DNS events to identify signs of malicious network activity.

## Objectives
- Detect abnormal DNS activity
- Identify DNS beaconing
- Detect DNS tunneling
- Investigate potential C2 traffic

## Tools
- Splunk Enterprise
- SPL (Search Processing Language)
- Zeek DNS Logs (`dns.log.gz`)

## Findings

Four threat hunts were performed:

| Hunt | Result |
|---|---|
| Query Volume Analysis | Benign |
| NXDOMAIN Analysis | Benign |
| Beaconing Detection | Benign |
| DNS Tunneling Detection | **Malicious** |

One compromised host was identified: **`192.168.204.71`**, communicating with **`rssfeeds.com`** using DNS TXT records consistent with DNS tunneling / command-and-control (C2) activity.

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Application Layer Protocol: DNS | T1071.004 |
| Non-Standard Encoding | T1132 |
| Exfiltration Over Alternative Protocol | T1048.003 |
└── evidence/
    └── (Splunk screenshots)
```
