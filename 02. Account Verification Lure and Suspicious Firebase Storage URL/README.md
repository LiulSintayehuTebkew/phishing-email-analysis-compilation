# Account Verification Lure and Suspicious Firebase Storage URL

**S2021-01-25-malspam-0720-UTC** 

**Investigation:** Phishing email and URL threat-intelligence triage  
**Role:** SOC Analyst Portfolio Project  
**Tools Used:** Email header analysis, HTML inspection, URL analysis, VirusTotal, threat-intelligence correlation  
**Verdict:** Suspicious phishing email with a credential-verification lure  
**Sample Date:** 25 January 2021

---

## 1. Initial Triage

A suspicious email impersonating an email service's account-verification process was identified. The message claims that verification is required to continue using the recipient's email account.

The email contains a Verify Now link pointing to a Firebase Storage URL that serves an HTML resource.

### Email Details

- **Subject:** Session Expired For admin@malware-traffic-analysis.net
- **From:** admin@malware-traffic-analysis.net
- **Return-Path:** asa_partner@yahoo.com
- **Recipient:** admin@malware-traffic-analysis.net
- **Observed Sending Host:** slot0.hktul.asia
- **Observed Source IP:** 109.248.144.12
- **Embedded URL Domain:** firebasestorage.googleapis.com
- **Referenced Resource:** /v0/b/pvtr-25f6f.appspot.com/o/index2pvt.htm
- **Email Format:** HTML
- **Attachment:** None observed in the supplied email content

### Initial Observations

- The Return-Path differs from the displayed sender address.
- The message uses an account-expiration or session-expiration theme to encourage action.
- The email requests verification even though no independent evidence establishes that the account has expired.
- The verification button links to a resource hosted on Google Firebase Storage.
- The message uses HTML formatting to present a clickable verification button.
- Threat-intelligence information associates the domain with phishing reports and other suspicious activity, although the domain is also legitimate shared infrastructure.

**Initial Decision:** Treat the email and embedded URL as suspicious. Continue with header analysis, URL inspection, and threat-intelligence correlation.

---

## 2. Email Header Analysis

The following header information was visible in the supplied email screenshot.

- **From:** malware-traffic-analysis.net <admin@malware-traffic-analysis.net>
- **Return-Path:** asa_partner@yahoo.com
- **Delivered-To:** admin@malware-traffic-analysis.net
- **Received Host:** slot0.hktul.asia
- **Source IP:** 109.248.144.12
- **Subject:** Session Expired For admin@malware-traffic-analysis.net
- **Date:** 25 January 2021, 07:19:58 -0800
- **Received Timestamp:** 25 January 2021, 07:20:01 +0000
- **Message-ID:** <2021012507...@malware-traffic-analysis.net> (partially obscured in the screenshot)
- **MIME Version:** 1.0
- **Content-Type:** text/html
- **Content-Transfer-Encoding:** quoted-printable

### Findings

**1. Sender and Return-Path inconsistency**

The displayed sender is admin@malware-traffic-analysis.net, while the Return-Path is asa_partner@yahoo.com.

This discrepancy is suspicious and warrants further investigation. However, it does not independently prove spoofing or malicious intent, since legitimate forwarding and third-party mail services can also produce different sender and return-path values.

**2. Sending infrastructure**

The Received header identifies slot0.hktul.asia and the IP address 109.248.144.12.

The sending host should be investigated using historical DNS, IP reputation, and available mail-server logs. The supplied evidence does not establish who controlled the server or whether it was compromised.

**3. Authentication results**

The screenshot does not show sufficient information to establish SPF, DKIM, or DMARC results.

These checks should be performed against the original message and its complete authentication headers where available.

**4. Timestamp interpretation**

The message Date header indicates 07:19:58 -0800, corresponding to 15:19:58 UTC. The Received header indicates 07:20:01 +0000.

These timestamps differ by more than eight hours. This may indicate a sender clock or header configuration issue, but the discrepancy should be verified against the original raw message before drawing conclusions.

### Assessment

The sender inconsistency, sending infrastructure, and account-verification theme justify treating the message as suspicious. Additional authentication and infrastructure evidence is required to determine the precise delivery mechanism.

---

## 3. Email Body Analysis

### Observations

- The message claims that email verification is mandatory.
- It warns that messages may not be delivered unless the recipient takes action.
- The verification button is visually emphasized using HTML styling.
- The message does not provide a verifiable support case, administrative notice, or independent account-status confirmation.
- The HTML contains an external link to a Firebase Storage resource.
- The message uses urgency and the possibility of email disruption to encourage the recipient to click.

### Assessment

The email uses an account-verification pretext consistent with phishing techniques. The threat of interrupted email delivery may pressure the recipient into following the embedded link without independently checking the request.

The sender address alone does not establish that the message was sent by a legitimate administrator.

The email body supports classifying the message as suspicious, but the supplied evidence does not show whether the destination page collected credentials or performed any malicious action.

---

## 4. URL and HTML Analysis

The email is HTML-based and contains a styled anchor element labeled Verify Now.

### Extracted URL

**Host:**
firebasestorage.googleapis.com

**Resource path:**
/v0/b/pvtr-25f6f.appspot.com/o/index2pvt.htm

**Query parameters observed:**

- alt=media
- token — a resource access token
- An email-address-related parameter or text associated with the recipient

The full URL contains additional query-string data. For defensive reporting, the resource path and host are recorded separately from the complete URL.

### URL Characteristics

**1. Use of a legitimate hosting platform**

Google Firebase Storage is a legitimate cloud storage service. Its presence does not, by itself, indicate that a URL is malicious.

However, legitimate hosting platforms can be abused to distribute phishing pages, malicious files, and other unwanted content.

**2. HTML resource**

The linked resource ends in .htm, suggesting that the destination is an HTML document. The extension alone does not establish the actual content or functionality of the resource.

**3. Resource token**

The URL contains a token parameter commonly used in Firebase Storage download URLs.

The token may grant access to the referenced resource. It should be treated as potentially sensitive and not unnecessarily redistributed.

**4. Recipient-specific context**

The recipient's email address appears in the link context. This may support recipient-specific tracking or page customization, but the exact behavior cannot be established from the email HTML alone.

**5. No confirmed credential harvesting**

The supplied screenshot shows the link embedded in the email, not the destination page's source code or network behavior.

Therefore, credential collection, browser exploitation, file downloading, or malware execution has not been independently demonstrated.

### Assessment

The URL is suspicious in the context of the email's verification lure. The hosting domain is legitimate infrastructure, so classification must consider the specific resource, historical reputation, and observed behavior rather than the domain name alone.

---

## 5. VirusTotal and Threat-Intelligence Analysis

The supplied VirusTotal screenshot reports the following information for firebasestorage.googleapis.com.

### Observed Reputation Information

- **Domain:** firebasestorage.googleapis.com
- **Detection Ratio:** 1 out of 92 security vendors flagged the domain as malicious
- **Registrar:** MarkMonitor Inc.
- **Domain Age:** Approximately 22 years, according to the displayed result
- **Last Analysis:** Approximately one hour before the screenshot was captured
- **Popularity Indicator:** Top 10K
- **Community Information:** 28+ community indicator shown in the interface

These values are observations from the supplied screenshot. The analysis timestamp is relative to the screenshot's capture time, not the present date.

### Threat-Intelligence Associations

The screenshot also contains community comments and related graph entries mentioning:

- **Threat Type:** botnet_c2
- **Malware Family:** RedLineRAT
- **IOC Name:** Threatnet
- **IOC Value:** firebasestorage.googleapis.com
- **Reported Confidence:** 100% in the cited community entry
- **Related Labels:** CVE-2017-11882, TrojanKeylogger, Keyer, and whats.apk
- **Related Report:** Fake copyright complaints push RedLine malware using Yandex Forms
- **Report Publication Date:** 6 May 2022

The screenshot also shows associations with phishing reports and historical malware-related graph entries.

### Interpretation

**Domain reputation and resource reputation must be distinguished.**

The domain firebasestorage.googleapis.com is part of Google's legitimate infrastructure. A detection ratio of 1/92 does not establish that the entire domain is malicious, nor does it establish that the particular URL in this email is safe.

The community entry associates the domain with RedLineRAT and a botnet command-and-control classification. This is relevant threat-intelligence context, but the supplied evidence does not prove that the specific URL in this email was used by RedLineRAT.

Similarly, graph entries involving CVE-2017-11882, Android APKs, and other malware families may represent separate files, campaigns, or infrastructure relationships. Their appearance in the same graph is not sufficient to attribute this email to those threats.

The report about fake copyright complaints and RedLine malware provides historical context for malware-distribution campaigns. It does not independently establish a connection to this particular message.

### Evidence Links

- [VirusTotal domain analysis](https://www.virustotal.com/gui/domain/firebasestorage.googleapis.com)
- [ThreatNet IOC reference](https://threatline.abuse.ch/ioc/2784182/)
- [ThreatNet file reference](https://www.threatnet.org/file/0d794ee3921b)
- [BleepingComputer report on RedLine malware distribution](https://www.bleepingcomputer.com/news/security/fake-copyright-complaints-push-redline-malware-using-yandex-forms/)

These links provide investigation leads and historical context. Their current contents and the exact relationship to the email should be verified before using them as evidence of attribution.

---

## 6. Indicators of Compromise (IOCs)

The following indicators were extracted from the supplied email and reputation screenshot.

### Email Indicators

- **Sender:** admin@malware-traffic-analysis.net
- **Return-Path:** asa_partner@yahoo.com
- **Recipient:** admin@malware-traffic-analysis.net
- **Subject:** Session Expired For admin@malware-traffic-analysis.net
- **Observed Source IP:** 109.248.144.12
- **Observed Sending Host:** slot0.hktul.asia
- **Message Date:** 25 January 2021

### URL Indicators

- **Domain:** firebasestorage.googleapis.com
- **Firebase Bucket:** pvtr-25f6f.appspot.com
- **Resource Name:** index2pvt.htm
- **URL Path:** /v0/b/pvtr-25f6f.appspot.com/o/index2pvt.htm
- **URL Parameter:** alt=media
- **Additional Parameter:** Resource access token

### Threat-Intelligence Indicators

- **Reported Malware Association:** RedLineRAT
- **Reported Threat Type:** botnet_c2
- **Related Vulnerability Reference:** CVE-2017-11882
- **Reported Phishing Association:** Historical community comments identify the domain in phishing-related contexts.

### IOC Notes

- The sender and Return-Path can be spoofed or affected by legitimate mail-routing arrangements.
- The source IP and hostname require independent reputation and historical infrastructure checks.
- The Firebase domain is shared infrastructure and should not automatically be blocked organization-wide based on this email alone.
- The full URL may contain a resource token and should be handled carefully.
- Malware-family associations are leads for investigation, not confirmed attribution.
- No attachment hash was available in the supplied email evidence.
- No SHA-256 or MD5 hash has been calculated for the linked resource.

**Recommended handling:** Preserve the original email and its complete URL in the investigation record. Apply targeted blocking or detection to the specific resource when supported by further validation, rather than treating all Firebase Storage traffic as malicious.

---

## 7. Investigation Actions Completed

Based on the supplied email screenshot and extracted VirusTotal information, the following analysis was completed:

- Reviewed the visible email headers.
- Identified the sender and Return-Path inconsistency.
- Recorded the sending hostname and source IP.
- Examined the HTML email body.
- Identified the account-verification pretext.
- Extracted the visible Firebase Storage host and resource path.
- Reviewed the available domain reputation information.
- Recorded relevant community threat-intelligence associations.
- Identified the RedLineRAT association as an unverified investigative lead.
- Documented the available indicators of compromise.
- Distinguished direct observations from third-party reputation claims.
- Identified additional evidence required to validate the destination's behavior.

### Investigation Limitations

The following activities have not been demonstrated by the supplied evidence:

- Retrieval and inspection of the actual HTML resource.
- Confirmation that the linked page was malicious at the time of delivery.
- Validation of credential-harvesting functionality.
- Confirmation that the destination downloaded or executed malware.
- Independent confirmation of the RedLineRAT association.
- Verification of SPF, DKIM, and DMARC results.
- Calculation of file hashes for the linked resource.
- Confirmation that a recipient clicked the link or suffered compromise.

---

## 8. Recommended Next Steps

### A. Further Email Analysis

- Obtain the original .eml file and preserve its cryptographic hash.
- Review all Received headers to reconstruct the message's delivery path.
- Inspect Authentication-Results and other available SPF, DKIM, and DMARC evidence.
- Verify the source IP and sending hostname against historical reputation sources.
- Check whether the same sender, subject, or URL appeared in other messages.

### B. URL and Web-Resource Analysis

- Search for the exact URL and resource path in reputable threat-intelligence sources.
- Retrieve the linked resource only in a controlled analysis environment.
- Record the retrieval timestamp, HTTP status, response headers, and content hash.
- Inspect the HTML source for credential forms, JavaScript redirects, obfuscated scripts, external resources, and suspicious data-submission destinations.
- Compare the resource with historical reports and samples associated with the same Firebase bucket.
- Determine whether the resource remains accessible and whether its current content differs from the content available in January 2021.

Do not assume that a current response represents the content served when the email was originally received.

### C. Controlled Behavioral Analysis

If static inspection is insufficient, analyze the resource in a disposable, isolated virtual machine.

Observe:

- Browser redirects and requests to external domains.
- Credential-submission endpoints.
- Downloaded files and their hashes.
- Process creation and unexpected child processes.
- DNS requests and network connections.
- Attempts to execute scripts or exploit browser vulnerabilities.

Use controlled network access and avoid entering real credentials or using production accounts.

### D. Threat-Intelligence Correlation

- Investigate the ThreatNet reference and the reported RedLineRAT association.
- Determine whether the exact Firebase bucket, object path, or token appears in historical campaign reporting.
- Review the reported botnet_c2 classification and its supporting evidence.
- Investigate the relationship, if any, between this resource and the RedLine malware campaign described in the referenced report.
- Treat graph relationships and community comments as leads until independently corroborated.

### E. Incident Response

If the message reached an organization:

- Identify the recipients of the email.
- Determine whether anyone clicked the verification link.
- Review secure web gateway, DNS, proxy, browser, and endpoint logs.
- Check for credential submissions, suspicious downloads, or related process activity.
- If credentials were submitted, follow the organization's account-compromise response procedures, including credential resets and session revocation where appropriate.
- Preserve the email and relevant logs for further investigation.

Do not conclude that an endpoint was compromised solely because the email was received or the URL was present.

---

## 9. Final Assessment

- **Classification:** Suspicious phishing email
- **Confidence:** High that the email uses a suspicious account-verification lure; malicious behavior of the destination has not been independently verified.
- **Primary Concern:** An embedded verification link hosted on Google Firebase Storage.
- **Observed Delivery Technique:** HTML email containing a prominent account-verification link.
- **Potential Objective:** Credential harvesting or redirection to malicious content; neither objective has been confirmed.
- **Threat-Intelligence Context:** Historical community reporting associates the hosting domain with phishing and other malware-related activity.
- **RedLineRAT Attribution:** Unconfirmed for this specific email and URL.
- **Potential Impact:** Credential compromise or further malicious activity if the destination is confirmed to be harmful and the recipient interacts with it.
- **Analysis Status:** Initial email triage, HTML inspection, URL extraction, and reputation review completed.

### Analyst Handover

The email titled Session Expired For admin@malware-traffic-analysis.net claims that account verification is required to prevent interruption of email delivery. It includes a Verify Now link pointing to an HTML resource hosted on firebasestorage.googleapis.com.

The displayed sender and Return-Path differ, and the message uses urgency to encourage the recipient to follow the link. These characteristics justify treating the email as suspicious and conducting further investigation.

The supplied threat-intelligence screenshot reports one detection out of 92 vendors for the domain and includes community associations with phishing and RedLineRAT-related activity. Because Firebase Storage is legitimate shared infrastructure, these observations do not establish that the specific URL is malicious or that RedLineRAT was delivered through this email.

The next priority is to inspect the exact HTML resource, validate its historical and current behavior, and correlate its identifiers with independent threat-intelligence evidence.

**No claim is made that the link successfully collected credentials, delivered malware, or resulted in a compromised system.**

---

## Disclaimer

This report documents a defensive email and URL triage investigation based on the supplied screenshot and extracted threat-intelligence information. Findings are limited to the available evidence. Third-party labels and community comments are not equivalent to independent technical validation, and the report should not be interpreted as proof of malware execution, successful credential theft, or system compromise.
