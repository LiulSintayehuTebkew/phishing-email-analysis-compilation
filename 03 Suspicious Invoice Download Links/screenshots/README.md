# Suspicious Invoice Download Links

**2021-01-27-malspam-1317-UTC**

**Investigation:** Phishing email and suspicious URL triage  
**Role:** SOC Analyst Portfolio Project  
**Tools Used:** Raw email header analysis, MIME inspection, quoted-printable decoding, HTML inspection, URL extraction, static analysis  
**Verdict:** Suspicious email — malicious payload not independently verified  
**Sample Date:** 27 January 2021

---

## 1. Initial Triage

The email claims that an invoice has been sent to the recipient's office and asks the recipient to review electronic versions available for download.

The message contains two links presented as PDF and JPG invoices. Both point to the same external URL on celsius-process.com.

### Email Details

- **Displayed Sender Name:** Akhi
- **From:** Akhil.us@actind.com
- **Return-Path:** Akhil.us@actind.com
- **Recipient:** admin@malware-traffic-analysis.net
- **Subject:** Purchase Order
- **Sending Host:** HQMX01.yamaichi-web.co.jp
- **Observed Intermediate Source IP:** 160.86.251.211
- **Earlier Sending Host:** EC2AMAZ-8QO2RSN
- **Earlier Sending IP:** 34.248.138.107
- **Date:** 27 January 2021, 11:44:36 UTC
- **Message-ID:** <20212701114435F186417915-EB47DBE56F@actind.com>
- **Content-Type:** multipart/alternative
- **Attachment:** No separate MIME attachment shown in the supplied message
- **Linked Domain:** celsius-process.com

### Initial Observations

- The subject uses a purchase-order theme that may be relevant to business or finance teams.
- The message claims an invoice has been sent but directs the recipient to an external website.
- Two purported invoice links lead to the same URL.
- The sender domain differs from the domain hosting the download links.
- The email includes a business signature claiming to represent MTS Systems (China) Co., Ltd.
- The message passed through an EC2-hosted system before reaching the receiving mail server.
- The supplied headers do not establish SPF, DKIM, or DMARC validation results.

**Initial Decision:** Treat the message as suspicious and investigate the URL and sender infrastructure. Do not open the links or download files on a production workstation.

---

## 2. Email Header Analysis

### Extracted Headers

- **Return-Path:** Akhil.us@actind.com
- **From:** "Akhi" <Akhil.us@actind.com>
- **To:** admin@malware-traffic-analysis.net
- **Subject:** Purchase Order
- **Date:** 27 January 2021, 11:44:36 UTC
- **Message-ID:** <20212701114435F186417915-EB47DBE56F@actind.com>
- **Intermediate Mail Server:** HQMX01.yamaichi-web.co.jp
- **Intermediate Server IP:** 160.86.251.211
- **Earlier Sending Host:** EC2AMAZ-8QO2RSN
- **Earlier Sending IP:** 34.248.138.107
- **Earlier Server Software:** Postfix
- **Earlier Connection:** ESMTPA
- **Content-Type:** multipart/alternative
- **MIME-Version:** 1.0

### Findings

**1. Sender and Return-Path**

The visible sender and Return-Path both use actind.com.

This consistency does not prove that the message is legitimate. The sender address could belong to a compromised account, or the message could have been sent through infrastructure authorized to use the domain.

The available headers do not establish which explanation applies.

**2. Multiple Mail Servers**

The supplied Received headers show the following sequence:

1. An EC2-hosted system at 34.248.138.107 connected to HQMX01.yamaichi-web.co.jp.
2. The message was processed by Postfix on the receiving mail server.
3. The receiving infrastructure recorded the message at 160.86.251.211.
4. The message was subsequently delivered to the analysis mailbox.

The EC2 hostname includes eu-west-1, which is associated with an AWS European region naming convention. The IP ownership and historical infrastructure should be confirmed independently before making attribution claims.

The presence of an EC2 host is not inherently malicious. Cloud infrastructure can be used by legitimate senders and attackers alike.

**3. Date and Message-ID**

The Date header reports:

Wed, 27 Jan 2021 11:44:36 +0000

The Message-ID contains a timestamp-like sequence that does not cleanly match the Date header's formatting. Message-ID values are not necessarily reliable timestamps, so this discrepancy alone does not establish manipulation.

The supplied Received timestamps also use different time zones and are not sufficient on their own to establish a sender-side timeline.

**4. Authentication Results**

No explicit SPF, DKIM, or DMARC authentication results are included in the supplied headers.

The absence of these results from the excerpt does not prove that authentication failed. Authentication should be checked using the complete original email and relevant DNS records.

### Assessment

The routing path provides useful investigation leads, particularly the EC2-hosted sending system and the intermediate mail server. However, neither the routing path nor the sender/Return-Path consistency independently establishes whether the message is legitimate.

---

## 3. Email Body Analysis

The email contains English text interspersed with Chinese characters. After decoding the quoted-printable content, the central message translates approximately to:

The message provides two download options:

- Download PDF-format electronic invoice.
- Download JPG-format electronic invoice.

The signature identifies the sender as Michelle Zhang and claims an association with MTS Systems (China) Co., Ltd.

### Observations

- The greeting is generic and does not identify the recipient by name.
- The message claims that an invoice has already been sent.
- The recipient is prompted to access an electronic version for confirmation.
- Both download options use the same external destination.
- The signature contains company details, a telephone number, a fax number, an email address, and a physical address.
- The supplied email does not include a separate invoice attachment.
- The body includes a historical office-relocation notice.

### Assessment

Purchase orders and invoices are common business-email pretexts because recipients may expect financial documents or supplier correspondence.

The two download options may create the impression that the recipient can choose between standard document formats. However, both options resolve to the same destination, and the message does not provide a direct invoice attachment.

These characteristics justify investigation, but the authenticity of the claimed business relationship has not been independently established.

---

## 4. MIME and HTML Analysis

### MIME Structure

The message declares:

- **MIME-Version:** 1.0
- **Content-Type:** multipart/alternative
- **Boundary:** 1AfQYroaKCmd2KN=_drJtdg2M7NAxXrElp
- **Plain-Text Part:** text/plain; charset="utf-8"
- **HTML Part:** text/html; charset="utf-8"
- **Transfer Encoding:** quoted-printable

The message contains both plain-text and HTML representations of the email body.

No separate MIME attachment is present in the supplied message.

### Static Inspection

**1. Quoted-printable encoding**

The body uses quoted-printable encoding, a standard MIME mechanism for representing text. The encoded Chinese characters were reviewed to understand the message content.

The encoding itself is not a malicious indicator.

**2. HTML download links**

The HTML body contains two anchor elements that point to the same external URL.

The displayed link labels suggest that the destination provides PDF and JPG versions of an electronic invoice.

**3. Sender signature**

The signature claims an association with MTS Systems (China) Co., Ltd. and includes contact information.

A copied or fabricated signature can be used to make a phishing message appear legitimate. The signature should be compared with independently obtained corporate contact information before drawing conclusions.

**4. No embedded executable identified**

The supplied HTML excerpt does not establish the presence of executable code or an embedded malware payload.

The actual content served by the download URL remains unexamined.

### Assessment

The MIME and HTML inspection identifies the external URL as the primary artifact requiring further analysis. The supplied email alone does not establish whether the destination serves a legitimate invoice, a phishing page, or a malicious file.

---

## 5. URL Analysis

### Extracted URL

Both the plain-text and HTML portions contain the following destination:

https://www.celsius-process.com/in/?email=admin@malware-traffic-analysis.net

### URL Components

- **Scheme:** HTTPS
- **Hostname:** www.celsius-process.com
- **Domain:** celsius-process.com
- **Path:** /in/
- **Query Parameter:** email
- **Query Value:** admin@malware-traffic-analysis.net

### Findings

**1. Shared destination**

The PDF and JPG invoice links point to the same URL.

This means the displayed file-format options do not correspond to distinct destinations in the supplied HTML. The server could potentially choose what content to return based on server-side logic, query parameters, or other request attributes.

The actual response has not been retrieved or verified.

**2. Email address in the URL**

The URL includes the recipient's email address as a query parameter.

This may allow the destination to associate the request with the intended recipient or track access to the message. It can also expose the address to systems that log or process the URL.

The exact purpose of the parameter is unknown.

**3. Domain mismatch**

The sender address uses actind.com, while the download link uses celsius-process.com.

A difference between sender and destination domains is not proof of maliciousness, since legitimate organizations may use third-party document services. However, the relationship between these domains should be verified.

**4. HTTPS**

The destination uses HTTPS. This encrypts the connection when configured correctly, but it does not prove that the destination is trustworthy.

### Assessment

The URL is the principal investigation priority because it is the mechanism used to access the purported invoice.

The presence of a recipient-specific query parameter and the use of a separate destination domain warrant investigation. No claim is made that the URL is confirmed malicious without independent reputation or behavioral evidence.

---

## 6. Threat-Intelligence Analysis

The supplied email does not include verified VirusTotal results, a URL detection ratio, a downloaded-file hash, or confirmed malware-family attribution.

No such results are inferred in this report.

### Indicators for Investigation

- **Sender Domain:** actind.com
- **Intermediate Mail Server:** yamaichi-web.co.jp
- **Intermediate Server IP:** 160.86.251.211
- **Earlier Sending IP:** 34.248.138.107
- **Download Domain:** celsius-process.com
- **Download URL Path:** /in/
- **URL Query Parameter:** email=admin@malware-traffic-analysis.net

### Recommended Reputation Checks

- Search the exact URL and domain in reputable threat-intelligence services.
- Review historical DNS records for celsius-process.com.
- Investigate historical abuse reports associated with the two observed IP addresses.
- Determine whether the domain hosted invoice-themed phishing pages or suspicious downloads around January 2021.
- Search for related messages containing the same URL structure.
- Verify whether the claimed sender organization has a legitimate relationship with the sending infrastructure.
- If the URL returns a file, preserve it safely and calculate its SHA-256 hash.

### Interpretation

The email contains suspicious characteristics consistent with a possible invoice-themed phishing attempt. The supplied evidence does not independently confirm the destination's behavior or identify a specific malware family.

---

## 7. Indicators of Compromise (IOCs)

The following indicators were extracted from the supplied message. They should be treated as investigation indicators rather than automatically confirmed malicious infrastructure.

### Email Indicators

- **Sender:** Akhil.us@actind.com
- **Displayed Name:** Akhi
- **Return-Path:** Akhil.us@actind.com
- **Recipient:** admin@malware-traffic-analysis.net
- **Subject:** Purchase Order
- **Message-ID:** <20212701114435F186417915-EB47DBE56F@actind.com>
- **Intermediate Server:** HQMX01.yamaichi-web.co.jp
- **Intermediate IP:** 160.86.251.211
- **Earlier Sending Host:** EC2AMAZ-8QO2RSN
- **Earlier Sending IP:** 34.248.138.107
- **Sample Date:** 27 January 2021

### URL Indicators

- **URL:** https://www.celsius-process.com/in/?email=admin@malware-traffic-analysis.net
- **Domain:** celsius-process.com
- **Path:** /in/
- **Query Parameter:** email
- **Displayed Link Options:** PDF invoice and JPG invoice

### Content Indicators

- **Theme:** Purchase order and electronic invoice
- **Claimed Sender Identity:** Michelle Zhang
- **Claimed Organization:** MTS Systems (China) Co., Ltd.
- **Recipient-Specific URL Value:** admin@malware-traffic-analysis.net

### IOC Notes

- The sender and Return-Path match, but this does not authenticate the sender.
- The EC2-hosted source IP requires historical reputation analysis.
- The two invoice links use the same destination.
- The query string contains the recipient's email address.
- No separate attachment or downloadable payload was supplied for hashing.
- No confirmed malware family or successful compromise has been established.

---

## 8. Investigation Actions Completed

Based on the supplied raw email:

- Reviewed the email headers and routing information.
- Recorded sender, Return-Path, recipient, subject, and Message-ID.
- Identified the two IP addresses present in the Received headers.
- Reviewed the sending hostnames and Postfix routing entries.
- Inspected the MIME structure.
- Reviewed the quoted-printable message body.
- Identified the invoice-themed pretext.
- Extracted both external download links.
- Confirmed that both links use the same URL in the supplied content.
- Recorded the URL's hostname, path, and query parameter.
- Documented the absence of a separate MIME attachment.
- Recorded the primary investigation indicators.
- Identified the remaining verification requirements.

---

## 9. Recommended Next Steps

### A. Further Email Authentication Analysis

- Obtain the complete original .eml file.
- Check SPF, DKIM, and DMARC results using the original message and relevant DNS records.
- Verify whether actind.com was authorized to send the message through the observed infrastructure.
- Review the complete Received-header chain and relevant mail-server logs.
- Compare the claimed sender and signature against independently verified company contact information.

### B. URL and Download Analysis

- Check the exact URL and domain against reputable threat-intelligence sources.
- Review historical DNS and domain reputation records.
- Retrieve the destination only in a controlled analysis environment.
- Record redirects, HTTP response headers, response content type, and retrieval time.
- Determine whether the response is an invoice, login page, redirect, or downloadable file.
- If a file is returned, calculate its SHA-256 hash and inspect its file signature.
- Examine suspicious documents or executables using appropriate static-analysis tools.

### C. Controlled Behavioral Analysis

If the URL serves suspicious content, analyze it in a disposable, isolated virtual machine.

Monitor:

- Browser redirects and network requests.
- File downloads and attempted execution.
- Process creation and child processes.
- File-system and registry modifications.
- DNS queries and outbound network connections.
- Any additional payloads retrieved during the session.

Do not use real credentials or a production workstation.

### D. Incident Response

If the email reached an organization:

- Identify all recipients of the message.
- Determine whether the download link was clicked.
- Review proxy, DNS, browser, and endpoint security logs.
- Determine whether a file was downloaded or executed.
- Investigate any suspicious processes or outbound connections.
- Preserve the original email and associated artifacts.

Do not conclude that a system was compromised without supporting evidence.

---

## 10. Final Assessment

- **Classification:** Suspicious invoice-themed email; phishing not independently confirmed
- **Confidence:** Moderate that the message warrants investigation
- **Primary Concern:** External invoice-download links pointing to celsius-process.com
- **Observed Technique:** Purchase-order and invoice pretext with recipient-specific URL parameter
- **Sending Infrastructure:** EC2-hosted system at 34.248.138.107, followed by HQMX01.yamaichi-web.co.jp
- **Potential Impact:** Possible credential harvesting, deceptive downloads, or malicious file delivery, depending on destination behavior
- **Malware Attribution:** Not established
- **Analysis Status:** Header review, MIME inspection, message-body review, and URL extraction completed

### Analyst Handover

The email titled Purchase Order claims that an invoice has been sent and asks the recipient to download PDF or JPG versions from celsius-process.com.

Both links point to the same destination and include the recipient's email address as a query parameter. The message also contains a business signature claiming to represent MTS Systems (China) Co., Ltd., but that association has not been independently verified.

The next priority is to investigate the destination domain, establish the sender's authenticity, and determine what content the URL served at the time of delivery.

**No claim is made that the link delivered malware, stole credentials, or resulted in a compromised system.**

---

## Disclaimer

This report documents a defensive email and URL triage investigation based on the supplied message. Findings are limited to the available evidence and should not be interpreted as proof of successful phishing, malware execution, or system compromise.
