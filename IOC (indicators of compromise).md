# Indicators of Compromise (IOCs)

The investigation identified the following indicators associated with the confirmed DNS tunneling and command-and-control (C2) activity.

| IOC Type | Value | Description |
|----------|-------|-------------|
| **Compromised Host** | `192.168.204.71` | Host exhibiting DNS tunneling behavior. |
| **Malicious Domain** | `rssfeeds.com` | Domain used for DNS-based C2 communication. |
| **Malicious Subdomains** | `auth.rssfeeds.com`<br>`connect.rssfeeds.com` | Subdomains used during the C2 communication sequence. |
| **DNS Record Type** | `TXT` | TXT records were used to carry encoded data. |
| **Beacon Interval** | `~59–61 seconds` | Consistent automated beaconing interval. |
| **Response Code** | `NOERROR` | Indicates communication with active attacker infrastructure. |

## Behavioral Indicators

The following behaviors support the assessment of DNS tunneling:

- Repeated **TXT** record queries.
- High-entropy, encoded subdomains.
- Unique subdomain generated for nearly every request.
- Regular beaconing interval of approximately one minute.
- Successful `NOERROR` responses from the remote domain.
- Repeated communication pattern between `connect.rssfeeds.com` and `auth.rssfeeds.com`.

## Detection Summary

| Indicator | Assessment |
|----------|------------|
| High-entropy DNS queries | Suspicious |
| TXT record abuse | Suspicious |
| Automated beaconing | Suspicious |
| Live C2 infrastructure (`NOERROR`) | Confirmed |
| DNS tunneling behavior | Confirmed |

## Overall Assessment

The combination of encoded TXT queries, consistent beaconing intervals, successful responses from the remote infrastructure, and repeated communication with `rssfeeds.com` provides strong evidence of DNS-based command-and-control activity originating from host `192.168.204.71`.
