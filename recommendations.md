# Recommendations

Based on the findings of this investigation, the following response actions are recommended:

| Priority | Recommendation | Purpose |
|----------|----------------|---------|
| 🔴 High | Isolate host `192.168.204.71` from the network immediately. | Prevent further command-and-control communication and potential data exfiltration. |
| 🔴 High | Block `rssfeeds.com` and all associated subdomains at the DNS resolver and firewall. | Disrupt communication with the attacker's infrastructure. |
| 🔴 High | Acquire memory and disk images before remediation. | Preserve forensic evidence for incident response and malware analysis. |
| 🟠 Medium | Review authentication, endpoint, and network logs for signs of lateral movement. | Determine whether the compromise spread to additional systems. |
| 🟠 Medium | Perform a full malware scan and forensic analysis of the affected host. | Identify the malware, persistence mechanisms, and scope of compromise. |
| 🟠 Medium | Escalate the incident to the Incident Response (IR) team. | Coordinate containment, investigation, and recovery efforts. |
| 🟢 Low | Reimage the compromised host after forensic evidence has been collected. | Ensure complete removal of malware and restore the system to a trusted state. |

## Long-Term Improvements

To strengthen detection and response capabilities, consider implementing the following:

- Monitor DNS traffic for unusually long or high-entropy query names.
- Alert on excessive or unexpected **TXT** record queries.
- Baseline normal DNS behavior to identify anomalous beaconing patterns.
- Block known malicious domains using DNS filtering or threat intelligence feeds.
- Integrate Zeek logs with a SIEM (such as Splunk) for continuous threat hunting and automated detection.
- Regularly review DNS logs for indicators of command-and-control activity and data exfiltration techniques.
