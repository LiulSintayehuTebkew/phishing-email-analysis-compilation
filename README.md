# Phishing Email Analysis and Investigation

## Overview

A hands-on cybersecurity project focused on phishing detection, email investigation, IOC collection, threat intelligence, and incident response.

## Objectives

- Investigate suspicious and malicious emails.
- Identify phishing indicators and social-engineering techniques.
- Analyze email headers, message bodies, attachments, and URLs.
- Extract and document Indicators of Compromise (IOCs).
- Cross-check findings against threat intelligence sources.
- Classify emails based on evidence.
- Recommend appropriate SOC response actions.

## Investigation Framework

1. **Initial Triage** — Review the sender, subject, message, and attachments.
2. **Header Analysis** — Examine email routing, sender inconsistencies, and SPF, DKIM, and DMARC results when available.
3. **Content Analysis** — Identify suspicious links, impersonation, urgency, and social-engineering techniques.
4. **Attachment and URL Analysis** — Inspect file types, hashes, document structures, and suspicious destinations.
5. **IOC Collection** — Extract relevant email addresses, IP addresses, domains, URLs, and file hashes.
6. **Threat Intelligence** — Cross-check indicators using VirusTotal and other relevant sources.
7. **Evidence Correlation** — Combine findings to determine the most appropriate classification.
8. **Reporting and Response** — Document evidence, explain the verdict, and recommend mitigation or further investigation.

## Investigation Classification

- **Malicious:** Evidence supports a malicious classification.
- **Suspicious:** Indicators raise concerns, but evidence is insufficient for confirmation.
- **Likely Benign:** Available evidence supports a legitimate explanation.


## Tools and Technologies

- kate
- File hashing (SHA-256 and MD5)
- VirusTotal
- Threat intelligence sources


## Skills Demonstrated

- Phishing detection and email triage
- Malware attachment analysis
- IOC extraction and enrichment
- Threat intelligence analysis
- Evidence correlation and classification
- Incident response recommendations
- Technical documentation and analyst reporting

## Disclaimer

This project is for educational and defensive cybersecurity purposes. Findings are limited to the evidence examined. A malicious classification does not, by itself, prove successful execution or system compromise.

Suspicious samples are handled cautiously and should only be analyzed in an isolated environment.
