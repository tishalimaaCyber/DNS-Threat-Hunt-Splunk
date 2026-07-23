# DNS Threat Hunt: Detecting DNS Tunneling via Splunk

## Overview

## Scope

This investigation analyzed approximately 422,000 DNS events collected from a Zeek DNS log dataset using Splunk Enterprise. The objective was to identify evidence of DNS-based command-and-control (C2), DNS tunneling, beaconing, or Domain Generation Algorithm (DGA) activity.

Please note that this investigation uses a historical Zeek DNS dataset captured in March 2012. Some NXDOMAIN results are expected due to services that have since been retired or renamed.


| Item | Value |
|------|-------|
| **Platform** | Splunk Enterprise |
| **Language** | SPL |
| **Data Source** | Zeek DNS Logs (`dns.log.gz`) |
| **Dataset Size** | ~422,000 DNS Events |
| **Investigation Type** | DNS Threat Hunting |



# Executive Summary

A proactive DNS threat hunt was conducted to identify evidence of:

- DNS tunneling
- Command-and-Control (C2) communications
- Domain Generation Algorithm (DGA) activity
- DNS beaconing

Four independent hunting techniques were performed:

| Hunt | Result |
|------|--------|
| Query Volume Analysis | Benign |
| NXDOMAIN Analysis | Benign |
| Beaconing Analysis | Benign |
| Long Query Analysis | **Malicious** |

The investigation identified a single compromised host:

- **Host:** `192.168.204.71`
- **Domain:** `rssfeeds.com`
- **Activity:** DNS tunneling / DNS-based C2



# Methodology

| Hunt | Objective |
|------|-----------|
| Query Volume | Identify unusually active DNS clients |
| NXDOMAIN Analysis | Detect DGA-like failed lookups |
| Beaconing Analysis | Detect periodic DNS communication |
| Long Query Analysis | Detect encoded DNS tunneling |



# Hunt Results

## 1. Query Volume Analysis

spl

index=main sourcetype=dns_zeek

| rex field=_raw "^(?<ts>\S+)\t(?<uid>\S+)\t(?<src_ip>\S+)\t(?<src_port>\S+)\t(?<dest_ip>\S+)\t(?<dest_port>\S+)\t(?<proto>\S+)\t(?<trans_id>\S+)\t(?<query>\S+)\t(?<qclass>\S+)\t(?<qclass_name>\S+)\t(?<qtype>\S+)\t(?<qtype_name>\S+)\t(?<rcode>\S+)\t(?<rcode_name>\S+)"

| stats count by src_ip

| sort -count

### Finding

Host:

```
10.10.117.210
```

generated significantly more DNS traffic than any other system.

### Investigation

Follow-up: Reviewed the actual domains queried by this host:

spl
| search src_ip="10.10.117.210"
| stats count by query
| sort -count

Findings: 

All top domains were well-known legitimate services — teredo.ipv6.microsoft.com, tools.google.com, stats.norton.com, liveupdate.symantecliveupdate.com, time.apple.com, www.download.windowsupdate.com. This is consistent with a DNS resolver/gateway machine serving normal endpoint traffic (antivirus check-ins, OS updates, browser services).


### Verdict

**Benign**

The system is consistent with a DNS resolver or gateway rather than malicious activity.



## 2. NXDOMAIN Analysis

spl
index=main sourcetype=dns_zeek
| rex field=_raw "^(?<ts>\S+)\t(?<uid>\S+)\t(?<src_ip>\S+)\t(?<src_port>\S+)\t(?<dest_ip>\S+)\t(?<dest_port>\S+)\t(?<proto>\S+)\t(?<trans_id>\S+)\t(?<query>\S+)\t(?<qclass>\S+)\t(?<qclass_name>\S+)\t(?<qtype>\S+)\t(?<qtype_name>\S+)\t(?<rcode>\S+)\t(?<rcode_name>\S+)"
| search rcode_name="NXDOMAIN"
| stats count by src_ip
| sort -count

### Finding

Result: 49,923 total NXDOMAIN events across 87 unique hosts. Top host: 192.168.202.103 (7,409 failed lookups)

### Investigation

Follow-up: 

Reviewed the specific domains this host failed to resolve:

spl
| search src_ip="192.168.202.103" rcode_name="NXDOMAIN"
| stats count by query
| sort -count

Findings:

All failed domains corresponded to recognizable, legitimate services — api.twitter.com, api.facebook.com, one.ubuntu.com (Ubuntu One, a discontinued cloud service), versioncheck.addons.mozilla.org, www.splunk.com. No randomized or algorithmically-generated domain patterns were observed. Failures are attributable to the age of the dataset (services decommissioned or restructured since 2012), not malicious DGA activity.

Verdict: These failures are consistent with the age of the dataset rather than DGA activity. 


## 3. Beaconing Analysis

spl
index=main sourcetype=dns_zeek
| rex field=_raw "^(?<ts>\S+)\t(?<uid>\S+)\t(?<src_ip>\S+)\t(?<src_port>\S+)\t(?<dest_ip>\S+)\t(?<dest_port>\S+)\t(?<proto>\S+)\t(?<trans_id>\S+)\t(?<query>\S+)\t(?<qclass>\S+)\t(?<qclass_name>\S+)\t(?<qtype>\S+)\t(?<qtype_name>\S+)\t(?<rcode>\S+)\t(?<rcode_name>\S+)"
| eval real_time=tonumber(ts)
| bin real_time span=1h
| stats count by src_ip, query, real_time
| eventstats avg(count) as avg_count stdev(count) as stdev_count count as num_buckets by src_ip, query
| where num_buckets > 3 AND stdev_count < 2
| sort -avg_count

### Finding

2,460 host/domains displayed regular hourly query intervals.

### Investigation

Findings, by category:

Domain Pattern	|Identified As	Verdict
armmf.adobe.com	|Adobe Application Manager update check-in	Benign
1.1.168.192.in-addr.arpa |	Reverse DNS lookup for local gateway (192.168.1.1)	Benign
G.CEIPMSN.COM	| Microsoft Customer Experience Improvement Program telemetry	Benign
dr._dns-sd._udp... / lb._dns-sd._udp...	|Bonjour/DNS-SD local network service discovery	Benign

Verdict: Benign — all regular check-in patterns traced to known legitimate software and protocols.

No malicious beaconing identified.


## 4. Long Query Analysis (DNS Tunneling)

spl
index=main sourcetype=dns_zeek
| rex field=_raw "^(?<ts>\S+)\t(?<uid>\S+)\t(?<src_ip>\S+)\t(?<src_port>\S+)\t(?<dest_ip>\S+)\t(?<dest_port>\S+)\t(?<proto>\S+)\t(?<trans_id>\S+)\t(?<query>\S+)\t(?<qclass>\S+)\t(?<qclass_name>\S+)\t(?<qtype>\S+)\t(?<qtype_name>\S+)\t(?<rcode>\S+)\t(?<rcode_name>\S+)"
| eval qlen=len(query)
| stats max(qlen) as max_len count by src_ip, query
| where max_len > 60
| sort -max_len

### Finding

One host generated repeated long, high-entropy DNS queries.

**Source Host**

```
192.168.204.71
```

**Destination**

```
auth.rssfeeds.com
connect.rssfeeds.com
```

Queries consisted of random-looking encoded subdomains using **TXT** records.

### Indicators

- High-entropy subdomains
- TXT record lookups
- Unique subdomain per request
- Consistent 59–61 second intervals
- Successful `NOERROR` responses
- Repeated `connect` → `auth` communication pattern

### Scope Validation

Another host appeared during wildcard searching:

```
192.168.202.106
```

Further investigation confirmed it was communicating with:

```
rssfeeds.usatoday.com
```

using normal A record lookups.

This was ruled out as a false positive.

### Verdict

**Malicious**

Evidence is consistent with DNS tunneling and DNS-based command-and-control communication.



# Final Assessment

The investigation concludes that:

- **Host:** `192.168.204.71`
- **Status:** Compromised
- **Technique:** DNS Tunneling / DNS C2
- **Infrastructure:** `rssfeeds.com`

The observed behavior is automated and consistent with malware rather than user activity.



# MITRE ATT&CK Mapping

| Technique | ID |
|-----------|----|
| Application Layer Protocol: DNS | T1071.004 |
| Non-Standard Encoding | T1132 |
| Exfiltration Over Alternative Protocol | T1048.003 |



# Indicators of Compromise

| Indicator | Value |
|-----------|-------|
| Compromised Host | `192.168.204.71` |
| Domain | `rssfeeds.com` |
| Subdomains | `auth.rssfeeds.com`, `connect.rssfeeds.com` |
| Query Type | `TXT` |
| Beacon Interval | ~60 seconds |



# Recommendations

- Isolate `192.168.204.71`
- Block `rssfeeds.com` and all subdomains
- Acquire memory and disk images for forensic analysis
- Review authentication and endpoint logs for lateral movement
- Escalate to Incident Response
- Reimage the compromised host after forensic acquisition

# Conclusion

Three independent hunting techniques produced explainable, legitimate DNS activity.

The long-query analysis identified a single host exhibiting multiple indicators of DNS tunneling:

- Encoded TXT queries
- High-entropy subdomains
- Regular beacon intervals
- Successful communication with live C2 infrastructure

Based on these findings, `192.168.204.71` is assessed as compromised and communicating with attacker-controlled infrastructure via DNS.
````
