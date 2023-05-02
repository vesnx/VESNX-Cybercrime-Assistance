# C.A.R.E. Knowledge Base Entry Structure

This document provides an overview of the structure of a C.A.R.E. (Cybersecurity and Legal Repository) knowledge base entry. This information is relevant for data entry professionals, cybersecurity experts, and legal professionals who contribute to the knowledge base. The knowledgebase will match possible exploits based on:
1. The whole URL
2. The partial URL with the longest match first
3. The file extension
4. The query string

For socket exploits:
1. HoneyPot Service
2. HoneyPot Credentials
3. Geographical Location
4. DNS Name
5. Stream Content

For operating system exploits:
1. Mitre Technique
2. Canary file access

This allows the most restrictive match to trigger before a less restrictive match is made, providing the most restrictive answer on an exploit.

## Knowledge Base Entry Fields

Below, you can find a brief explanation of the possible values and context of the knowledge base entries.

### Title Field

This field should contain a short title for the entry explaining why it's malicious:
- Do not use more than 6 to 8 words, maximum 50 characters
- Keep it short for readability on mobile devices
- Be descriptive, the best will be if it's a 50 character representation of the answer field but without the URL

### Id Field

This is a unique identifier (GUID) for the knowledge base entry, it's read-only and part of the unique identifier for technical comparison.

### BlockingReasons

This field is an enumerable representation of a set of reasons as described in [FirewallBlockReasons](https://github.com/vesnx/VESNX-Cybercrime-Assistance/blob/main/Src/FirewallBlockReasons.md):
- Select 1 or more reasons why the URL is considered malicious
- These reasons are used to generate abuse reports and can be used to prioritize legislation
- Sometimes the options do not really match what you think, if so have a look at the glossary and perhaps propose a new value

### Table Field

The Table field indicates where the abuse metadata is stored and how the key is matched to a URL for an exploit, after an entry is created this value is read-only.

Possible values for web-based exploits are:
- *FullPath*: Full path, this exploit is valid only when comparing the whole URL
- *FileExtensions*: The knowledge base entry is based on an extension filter, so URI endings in .bak, .cmd, ps1, .php, .aspx
- *PartialPath*: The knowledge base entry is based on the 'partial path' feature, so the value /db/ would be triggered on /db/site.bak
- *QueryString*: The knowledge base entry is based on a query string, helpful for SQL injection detection

Possible values for socket-based exploits are:
- *HoneyPotService*: The port being accessed/scanned
- *HoneyPotCredentials*: Canary credentials leaked to persistent probes to match "vulnerability brokers" or "cyber weapons dealers" with hackers using the exploits
- *GeographicalLocation*: Locations that are not allowed to be accessed (this will always be empty as this is instance related)
- *DNSName*: DNS names from where access is always blocked, this can contain wildcards like *tor* to block all access from known tor nodes
- *StreamContent*: Applicable when a proxy service is used like VESNX "Look who is talking" this can look in plain and SSL encrypted communication and look for exfiltration of key words like credit card, or complex data like login credentials, documents, canary-crypto-wallet keys

Possible values for operating system exploits are:
- *MitreTechnique*: The MITRE technique or sub Technique ID
- *CanaryFile*: Access or interaction with canary files, canary files are files that contain an interesting name and fake content that will get malicious users interested enough that they read, encrypt, upload, or want to use it.

### Key Field

Key is an internal structure that will be used to match a URI. In the editor, you enter a URI and a Table, and the knowledge base editor will capture the key for you.

Key points of interest:
- The domain name for the URI is ignored
- The key must be unique in a table; the keys are compared longest to shortest, so you can have detailed error messages and generic error messages based on the URI you provide
- Technical key will be used when replicating or importing from other knowledge databases
- After an entry is created, this value is read-only

### Answer Field

The standard answer generated for an exploit, typically created by the security expert of VESNX and will give an answer that can be used in email reports.

Things to consider when generating the answer:
- Explain why the exploit was detected
- Explain why it's an exploit and not a valid request
- Explain what the attacker is trying to achieve by probing the system with an exploit
- Use the {path} placeholder when you would like to have the actual URL in the generated output

### UserUpdatedAnswer Field

If you are updating an existing answer, this field will get populated. Please consider all requirements for generating an answer when providing updated text.

Additional things to consider when updating the answer:
- Make sure the answer is relevant to your organization
- Make sure the Mitre list is updated
- If set, this value will be returned instead of the authoritative answer
- Users can revert to the original authoritative answer if a change is made, which means deleting the UserUpdatedAnswer field

### IsDisabled Field

If your application triggers a knowledge base entry on an endpoint (URL) and you can't change the endpoint, you can disable the entry.

Things to consider when disabling:
- The fact that the knowledge base triggers is a good indicator that you're exposed to known attack vectors, and you should consider changing your application
- Disabling the knowledge base entry will service a replication or merge with another knowledge base
- You can re-enable the entry once you have been able to update your web application or service

### CreatedUtc Field

This field will contain the UTC date and time when the entry was created.
- The field is read-only
- It is in UTC date so we can understand which field came last in case of a replication or merger with another knowledge base

### LastUpdateUtc Field

This will contain the last change made to this entry by setting an updated answer.
- MITRE and Applicable Law changes do not generate an updated timestamp
- The UTC date and time when the last change was recorded
- The previous UTC change date is lost when updating

### LastUpdatedBy Field

This will allow you to identify who created or updated the entry.
- Entries created by or updates by VESNX are marked with the name VESNX-SUBSCRIPTION
- You can use the name and change date to compare merge conflicts and choose whose version to keep

### Mitre Field

This small data list contains the MITRE ATT&CK® entries using the key and a relevant text as to why the key is applicable.

When adding items:
- Use the map to explain why the exploit is relevant to the MITRE key and include a short text
- Use the MITRE knowledge base technique(s) associated with the abuse
- Consider that MITRE is a living community; data will get updated, and your contributions will help the community to be more knowledgeable

### ApplicableLaw Field

This is a small data list that contains the applicable law entries for the exploitation, using the key and a relevant text as to why the key is applicable.

When adding items:
- Use the map to explain why the exploit is relevant to the law and include a short text
- Use the applicable law knowledge base entry that's associated with the abuse
- Consider that the applicable law knowledge base is a living community; data will get updated, and your contributions will help the community to be more knowledgeable


## Project CARE Knowledge Base Editor

You can get a knowledge base editor when purchasing a business version of IDPS. See https://www.vesnx.com for more details or contact support at support@vesnx.com. Please note that the Project CARE Knowledge Base Editor and Viewer will work on Windows 10 / Windows Server 2016 or later only.


## Glossary

### FullPath

The FullPath value will match the entire URL. For example, if an entry exists for "/exploit/index.php" then "/exploit/index.php" will be matched but not "/exploit/index.php?id=1".

### PartialPath

The PartialPath value will match a part of the URL. For example, if an entry exists for "/exploit/" then "/exploit/index.php", "/exploit/somepage.html", and "/exploit/subdir/page.php" will all be matched.

### FileExtensions

The FileExtensions value will match a URL based on the file extension. For example, if an entry exists for ".php", then any URL ending with ".php" will be matched.

### QueryString

The QueryString value will match a URL based on its query string. For example, if an entry exists for "?id=1", then any URL containing "?id=1" will be matched.

### HoneyPotService

The HoneyPotService value will match socket-based exploits based on the port being accessed or scanned.

### HoneyPotCredentials

The HoneyPotCredentials value will match socket-based exploits based on canary credentials leaked to persistent probes.

### GeographicalLocation

The GeographicalLocation value will match socket-based exploits based on locations that are not allowed to be accessed.

### DNSName

The DNSName value will match socket-based exploits based on DNS names from where access is always blocked.

### StreamContent

The StreamContent value will match socket-based exploits based on the content of the stream, either in plain or encrypted communication.

### MitreTechnique

The MitreTechnique value will match operating system exploits based on the MITRE technique or sub-technique ID.

### CanaryFile

The CanaryFile value will match operating system exploits based on access or interaction with canary files.
