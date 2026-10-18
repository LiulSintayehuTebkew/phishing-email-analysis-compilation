# Phishing Email Analysis — Malicious RTF Attachment

**2021-01-22-malspam-0157-UTC.eml**

**Investigation:** Phishing email and attachment triage  
**Role:** SOC Analyst Portfolio Project  
**Tools Used:** Python email parsing, file hashing, static inspection, VirusTotal  
**Verdict:** Malicious attachment  
**Sample Date:** 22 January 2021

## 1. Initial Triage

Received a suspicious email with a job application theme.

- **Subject:** Human Resources Officer vacancy
- **From:** Walaa Qasem <walaaqasem10@yahoo.com>
- **Return-Path:** bankalerts@kotak.com
- **Observed Sending IP:** 45.82.177.208
- **Attachment:** Walaa-Qasem-resume(2).doc

### Initial Observations

- The sender address and Return-Path do not match.
- The sending server hostname does not obviously match the displayed sender.
- The email contains an unexpected document attachment.
- The message uses a job application as its pretext.
- The attachment has a .doc extension but contains RTF-formatted content.

**Initial Decision:** Treat the attachment as suspicious and continue with static analysis and reputation checks. Do not open it on a normal workstation.

## 2. Email Header Analysis

- **From:** Walaa Qasem <walaaqasem10@yahoo.com>
- **Return-Path:** bankalerts@kotak.com
- **Received Host:** vm1777187.2ssd.had.wf
- **Source IP:** 45.82.177.208
- **Subject:** Human Resources Officer vacancy
- **Date:** 22 January 2021, 01:57:37 -0800
- **Message-ID:** 20210122015737.CA907AA6C4968B7B@yahoo.com
- **Content-Type:** multipart/mixed

### Findings

The displayed sender and Return-Path are inconsistent. The received server information also deserves further investigation.

Possible explanations include spoofing, compromised email infrastructure, or third-party mail routing. The available evidence does not establish which explanation applies.

I did not establish SPF, DKIM, or DMARC results from the inspected header data.

## 3. Email Body Analysis

The message states that the sender is applying for an HR Officer vacancy and has attached a personal resume.

### Observations

- The message is short and generic.
- No specific company or job reference is included in the inspected body.
- The attachment is presented as a resume, encouraging the recipient to open it.
- No obvious phishing URL was identified in the inspected body.

### Assessment

The job application theme may be a social-engineering pretext used to encourage the recipient to open a malicious attachment.

This assessment is based on the message and attachment findings. The sender's identity and motive have not been independently established.

## 4. Attachment Analysis

- **Filename:** Walaa-Qasem-resume(2).doc
- **MIME Type:** application/msword
- **Detected Content Format:** RTF-like content
- **File Size:** Approximately 300.55 KB
- **SHA-256:** d994f6056feaeaa9417b384ebfa6fad79af8cac013e6f044a23d64b52a5021f9
- **MD5:** a16fcf40928723827ab9b7d9de5ad0cc

### Static Inspection

The decoded attachment begins with an RTF signature.

The following RTF markers were observed:

- \object
- \objdata
- \objautlink

These markers indicate that embedded object and linked-object functionality should be investigated further.

No obvious plain-text HTTP or HTTPS URL was identified in the initial raw-byte inspection.

The presence of these markers alone does not prove that the document exploits a vulnerability.

## 5. VirusTotal Analysis

**Detection Ratio:** 39 out of 61 security vendors flagged the file as malicious.

VirusTotal displayed the following information:

- **Threat Category:** Trojan
- **Popular Threat Label:** trojan.obfobjdat/cve201711882
- **Related Labels:** obfobjdat and cve201711882
- **Vendor Detection Themes:** RTF exploitation and CVE-2017-11882
- **Displayed File Tags:** ole-autolink, calls-wmi, exploit, executes-dropped-file

### Interpretation

The detection ratio and vendor labels strongly support classifying the attachment as malicious.

CVE-2017-11882 is associated with a vulnerability in Microsoft's Office Equation Editor that can potentially allow code execution when a specially crafted document is opened by a vulnerable application.

The VirusTotal labels suggest an exploit-related file, but the exact exploit structure has not yet been independently validated in this investigation.

### Evidence Link

[View the file on VirusTotal](https://www.virustotal.com/gui/file/d994f6056feaeaa9417b384ebfa6fad79af8cac013e6f044a23d64b52a5021f9/relations)

## 6. Indicators of Compromise (IOCs)

- **SHA-256:** d994f6056feaeaa9417b384ebfa6fad79af8cac013e6f044a23d64b52a5021f9
- **MD5:** a16fcf40928723827ab9b7d9de5ad0cc
- **Filename:** Walaa-Qasem-resume(2).doc
- **Sender:** walaaqasem10@yahoo.com
- **Return-Path:** bankalerts@kotak.com
- **Observed Source IP:** 45.82.177.208
- **Subject:** Human Resources Officer vacancy

### IOC Notes

- The hashes identify this specific file sample.
- Filenames and email subjects can be changed easily.
- Sender addresses can be spoofed or compromised.
- The sending IP should be investigated in context before making blocking decisions.

## 7. Investigation Actions Completed

- Parsed the email and inspected available headers.
- Reviewed the email body.
- Extracted the attachment from the email.
- Calculated the attachment's SHA-256 and MD5 hashes.
- Inspected the attachment's file signature.
- Identified RTF object-related markers.
- Checked the file's VirusTotal reputation.
- Recorded relevant indicators of compromise.
- Documented the initial assessment and remaining investigation questions.

## 8. Recommended Next Steps

### Further Static Analysis

- Extract and inspect the embedded objects with rtfobj from oletools.
- Check whether the file contains a crafted Equation Editor object.
- Look for embedded shellcode, commands, scripts, or external references.
- Determine whether the CVE-2017-11882 classification is supported by the file's actual structure.

### Controlled Behavioral Analysis

If static inspection is insufficient, analyze the sample only in a disposable, isolated virtual machine.

Observe process creation, file modifications, registry changes, DNS requests, and network connections. Do not use a production workstation or allow uncontrolled outbound access.

### Incident Investigation

If this email reached an organization, determine who received it and whether the attachment was opened. Review available endpoint and email security logs for evidence of execution or follow-on activity.

Do not conclude that a system was compromised without supporting evidence.

## 9. Final Assessment

- **Classification:** Malicious attachment
- **Confidence:** High that the file is malicious, based on VirusTotal detections and observed file characteristics
- **Primary Concern:** RTF/OLE object abuse, with vendor labels referencing CVE-2017-11882
- **Possible Delivery Technique:** Job application-themed email attachment
- **Potential Impact:** Code execution on a vulnerable host and possible subsequent malicious activity
- **Analysis Status:** Email triage, initial static inspection, and reputation checks completed

### Analyst Handover

The email contains an attachment named Walaa-Qasem-resume(2).doc. Although the filename suggests a conventional Word document, the extracted file contains RTF-formatted content and object-related markers.

VirusTotal reported 39 detections out of 61, with multiple labels referencing RTF exploitation and CVE-2017-11882.

The next priority is to inspect the embedded object and validate the exploit hypothesis. No claim is made that the file successfully executed or that a victim system was compromised.

## Disclaimer

This project documents a defensive email and malware-triage investigation. Findings are limited to the evidence examined and should not be interpreted as proof of successful exploitation or compromise.
