
# The AbuseReport Data Exchange: ReasonFlag Enumerable Values

This document provides context regarding the values used in the [AbuseReport Data Exchange](AbuseReport.schema.json), based on a 64-bit integer value from the FirewallBlockReasons enum found in the [Walter.BOM nuget package](https://www.nuget.org/packages?q=walter.bom). The Walter SDK (Website Automated Layered Threat Evaluation and Response) is a comprehensive framework for integrating web application security in .NET applications, developed by [VESNX](https://www.vesnx.com).

## FirewallBlockReasons

The FirewallBlockReasons enum is a flags-based enumeration that combines various violation reasons into a reputation score, representing the level of malicious activity performed by a malicious actor. Each value in the enum corresponds to a specific type of security violation or suspicious behavior detected by the firewall. By aggregating these values, the firewall can make informed decisions on whether to block a request or take other appropriate actions to protect the system and its data.

The glossary guide below will assist you in understanding the reasons for assigning a particular flag, offering insights into each violation type.


### None

No reason was set, doesn't mean there wasn't one, just indicates that it wasn't set.

### DeliberateManipulation

Deliberate manipulation refers to attempts by a malicious actor to manipulate data, such as system-provided values, cyphers, hashes, or IDs, with the intention of compromising the system or gaining unauthorized access. This type of attack may include attempts to tamper with or forge authentication tokens, alter database records, or modify encrypted data. MITRE ATT&CK techniques related to deliberate manipulation include [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) and [T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/). However, it is important to note that these techniques are not an exhaustive list and other techniques may also be relevant in different scenarios.

### HoneyPotTrap

A honey pot trap is a security measure designed to deceive and detect hackers by presenting seemingly vulnerable resources or systems that are actually isolated and monitored. When an attacker interacts with a honey pot trap, their actions are logged, and security teams can analyze their behavior to gain insights into their tactics, techniques, and procedures. The MITRE ATT&CK technique [T1523: Evading Analysis Environment](https://attack.mitre.org/techniques/T1523/) is related to the concept of a honey pot trap, as attackers may try to detect and avoid these traps. 

### HeaderManipulations

Header manipulations occur when a malicious actor tampers with HTTP headers in a request to bypass security measures, perform unauthorized actions, or gain access to sensitive information. This can include modifying header names or values, adding unauthorized headers, or removing required headers. MITRE ATT&CK techniques related to header manipulations include [T1100: Web Shell](https://attack.mitre.org/techniques/T1100/) and [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/). It is important to understand that these techniques are not an exhaustive list, and other techniques may also be relevant depending on the specific scenario.

### UserEncryptionManipulations

User encryption manipulations involve attempts by a malicious actor to tamper with encrypted data or encryption keys. This can include using incorrect encryption keys, trying to decrypt data using unauthorized methods, or forging encrypted messages. Relevant MITRE ATT&CK techniques for user encryption manipulations include [T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) and [T1556: Modify Authentication Process](https://attack.mitre.org/techniques/T1556/). As with other categories, these techniques are not an exclusive mapping, and various other techniques may apply in different situations.

### UserSessionManipulations

User session manipulations refer to attempts by a malicious actor to tamper with or hijack user sessions. This can involve actions like cross-site scripting, cookie poisoning, or stealing session tokens. The goal of these attacks is typically to gain unauthorized access to user accounts or perform actions on behalf of the user without their knowledge or consent. MITRE ATT&CK techniques related to user session manipulations include [T1506: Web Session Cookie](https://attack.mitre.org/techniques/T1506/) and [T1200: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1200/). As always, it is important to consider that these techniques are not an exhaustive list and other techniques may also be relevant in specific scenarios.

### PageRereshFishing

Page refresh fishing occurs when a malicious actor continuously refreshes a web page in an attempt to obtain different outcomes, manipulate the system, or exploit vulnerabilities. This behavior can lead to increased server load or be used to trigger specific conditions or errors. MITRE ATT&CK techniques such as [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) and [T1499: Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) may be relevant to page refresh fishing attacks.

### CookieManipulations

Cookie manipulations involve tampering with or forging HTTP cookies to bypass security restrictions, gain unauthorized access to user accounts, or perform actions on behalf of users without their consent. Some MITRE ATT&CK techniques associated with cookie manipulations include [T1506: Web Session Cookie](https://attack.mitre.org/techniques/T1506/) and [T1539: Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/). Keep in mind that other techniques might be applicable depending on the specific context of the attack.

### ProxyUser

Proxy user detection occurs when a request is made through a proxy server, which can be used to hide the true origin of the request or bypass network restrictions. Proxy users might be attempting to bypass geolocation restrictions, evade IP-based security measures, or conduct malicious activities without revealing their true identity. MITRE ATT&CK techniques such as [T1090: Proxy](https://attack.mitre.org/techniques/T1090/) and [T1095: Standard Application Layer Protocol](https://attack.mitre.org/techniques/T1095/) are examples of techniques related to the use of proxy servers.

### PenetrationAttempt

A penetration attempt involves a malicious actor trying to exploit vulnerabilities, gain unauthorized access, or disrupt a system's normal functioning. Penetration attempts can include various techniques such as brute-force attacks, SQL injection, cross-site scripting, or remote code execution. MITRE ATT&CK techniques such as [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1216: Signed Script Proxy Execution](https://attack.mitre.org/techniques/T1216/), and [T1505: Server Software Component](https://attack.mitre.org/techniques/T1505/) are examples of techniques related to penetration attempts. It's important to note that these techniques can vary depending on the specific context, attack surface, and targeted vulnerabilities.

### RepeatedBlockedRequest

Repeated blocked requests occur when a user or system persistently attempts to access resources or perform actions despite being previously blocked by security measures. This behavior may indicate a determined attacker probing for weaknesses, attempting to bypass security controls, or automating malicious activities. MITRE ATT&CK techniques such as [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/), [T1205: Traffic Signaling](https://attack.mitre.org/techniques/T1205/), and [T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046/) can be associated with repeated blocked requests. As with other flags, the specific techniques involved may vary based on the attacker's goals, methods, and the target system's defenses.

### NoAccessFromRegion

No access from region indicates an attempt to access a resource from a geographic location that is not allowed by the system's security policy. Geofencing, IP-based restrictions, or other location-based access controls can be used to enforce regional access limitations. Malicious actors may try to bypass these restrictions using proxy servers, VPNs, or other techniques to conceal their true location. MITRE ATT&CK techniques such as [T1090: Proxy](https://attack.mitre.org/techniques/T1090/), [T1095: Standard Application Layer Protocol](https://attack.mitre.org/techniques/T1095/), and [T1018: Remote System Discovery](https://attack.mitre.org/techniques/T1018/) may be relevant in cases where attackers attempt to bypass regional access controls.



### WrongUserGroup

The WrongUserGroup flag is triggered when a user is identified as belonging to an incorrect user group, which prevents them from accessing specific resources. User group-based access control enforces segregation of duties, ensuring that users only have access to the resources required for their role. Attackers may try to impersonate or escalate their privileges to a higher user group to gain unauthorized access. MITRE ATT&CK techniques such as [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/), [T1136: Create Account](https://attack.mitre.org/techniques/T1136/), and [T1548: Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/) could be relevant in situations involving user group manipulation. However, the specific techniques used may vary based on the attacker's objectives and the target system's access control mechanisms.

### ScrubbingDetected

ScrubbingDetected is a flag that indicates a user is suspected of trying to remove or obscure sensitive information, metadata, or other identifying characteristics from data before sharing or using it. Scrubbing can be done for various reasons, including concealing the source of the data, evading detection, or circumventing data usage restrictions. Attackers might employ techniques like data anonymization or steganography to achieve their goals. MITRE ATT&CK techniques such as [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/), [T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/), and [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) may be associated with data scrubbing activities. The specific techniques involved can vary depending on the attacker's intent and the nature of the data being manipulated.

### UserIdFaulty

The UserIdFaulty flag indicates that a user identifier is either faulty, manipulated, mismatched, or not generated by the system or firewall. Attackers may manipulate or forge user identifiers to bypass authentication or impersonate legitimate users. They might also exploit weaknesses in the identifier generation process or leverage stolen credentials to access resources. MITRE ATT&CK techniques such as [T1087: Account Discovery](https://attack.mitre.org/techniques/T1087/), [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/), and [T1550: Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) can be related to UserIdFaulty situations. The specific techniques used may vary depending on the attacker's goals and the target system's authentication mechanisms.

### WrongUserId

The WrongUserId flag is triggered when an incorrect user identifier is provided during an attempt to access a resource. This could indicate an attacker trying to gain unauthorized access using stolen or guessed credentials, or a user unintentionally providing incorrect information. MITRE ATT&CK techniques such as [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/), [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/), and [T1550: Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/) can be related to situations where the wrong user identifier is provided. The specific techniques involved may vary based on the attacker's intent and the target system's authentication mechanisms.



### SimulatedDevice 
The SimulatedDevice flag indicates that a user is using a simulated device or masquerading as a device that might be given access. This could be an attacker attempting to bypass security measures by emulating a trusted device. MITRE ATT&CK techniques such as [T1497: Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497/) and [T1480: Execution Guardrails](https://attack.mitre.org/techniques/T1480/) may be relevant in situations involving simulated devices. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms. 

### DataValidationError 
The DataValidationError flag indicates that the submitted data is invalid and would be incorrect when reading or writing data from an untrusted source. This could be a sign of an attacker attempting to exploit vulnerabilities in data validation, or it could be an unintentional error by a user. MITRE ATT&CK techniques such as [T1193: Spearphishing Attachment](https://attack.mitre.org/techniques/T1193/) and [T1214: Credentials in Registry](https://attack.mitre.org/techniques/T1214/) may be related to situations involving data validation errors. The specific techniques involved can vary based on the attacker's intent and the target system's data validation mechanisms. 

### DataExfiltration 
The DataExfiltration flag indicates that an attempt or actual data theft, unauthorized removal, or movement of data from a device has been detected. This could be a sign of an attacker trying to steal sensitive information or intellectual property. MITRE ATT&CK techniques such as [T1020: Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) and [T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/) may be relevant in situations involving data exfiltration. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms. 

### UserGeneratedRejection 
The UserGeneratedRejection flag indicates an application-specific violation, ad-hoc reason, or proprietary blocking reason that does not fit into known attack patterns. This could be a sign of an attacker attempting to exploit unknown vulnerabilities or using novel techniques to evade detection. Since this flag represents a wide range of potential scenarios, it is difficult to associate specific MITRE ATT&CK techniques without more information about the particular case. 

### AddhockFileAccessDetected 
The AddhockFileAccessDetected flag indicates that an ad-hoc file access attempt has been detected, representing a security violation. This could be a sign of an attacker attempting to access sensitive files or unauthorized resources. MITRE ATT&CK techniques such as [T1083: File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) and [T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/) may be relevant in situations involving ad-hoc file access. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.


### CrossSiteRequestRejected 
The CrossSiteRequestRejected flag indicates that a cross-site request has been rejected as a security measure. This could be a sign of an attacker attempting to perform a cross-site request forgery (CSRF) attack. MITRE ATT&CK techniques such as [T1156: .bash_history](https://attack.mitre.org/techniques/T1156/) and [T1106: Execution through API](https://attack.mitre.org/techniques/T1106/) may be relevant in situations


### DataSubscription

The DataSubscription flag indicates that an unauthorized attempt to access data protected behind a paywall or subscription service has been detected. This could be a sign of an attacker trying to bypass access controls to gain unauthorized access to restricted content. MITRE ATT&CK techniques such as [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) and [T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197/) may be relevant in situations involving data subscription violations. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### MaliciousUser

The MaliciousUser flag indicates that an individual exhibiting malicious behavior or intent when interacting with a web application or system has been detected. This could be a sign of an attacker attempting to exploit vulnerabilities or gain unauthorized access to sensitive information. MITRE ATT&CK techniques such as [T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) and [T1095: Standard Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/) may be relevant in situations involving malicious users. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### DeveloperTools

The DeveloperTools flag indicates that a specific group of users has been blocked as a security measure. This could be a sign of an attacker using developer tools to probe for vulnerabilities, reverse-engineer components, or perform other malicious activities. MITRE ATT&CK techniques such as [T1057: Process Discovery](https://attack.mitre.org/techniques/T1057/) and [T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) may be relevant in situations involving developer tools. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### BlockedUserGroup

The BlockedUserGroup flag indicates that a specific group of users has been blocked as a security measure. This could be a sign of an attacker attempting to use compromised accounts, social engineering, or other techniques to gain unauthorized access to a system. MITRE ATT&CK techniques such as [T1078: Valid Accounts](https://attack.mitre.org/techniques/T1078/) and [T1192: Spearphishing Link](https://attack.mitre.org/techniques/T1192/) may be relevant in situations involving blocked user groups. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.


### MaximumViolationsDetected

The MaximumViolationsDetected flag indicates that the maximum number of violations or warnings for a user has been detected, triggering a security measure. This could be a sign of an attacker persistently attempting to breach a system or perform malicious activities. MITRE ATT&CK techniques such as [T1110: Brute Force](https://attack.mitre.org/techniques/T1110/) and [T1108: Redundant Access](https://attack.mitre.org/techniques/T1108/) may be relevant in situations involving maximum violations detected. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### PhishyRequest

The PhishyRequest flag indicates a security violation that occurs when a hacker attempts to probe a web application or system for vulnerabilities using requests that are designed to mimic legitimate requests. These requests can include probing for endpoints such as login pages, configuration files, or other resources that may be vulnerable to attack. MITRE ATT&CK techniques such as [T1043: Commonly Used Port](https://attack.mitre.org/techniques/T1043/) and [T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046/) may be relevant in situations involving phishy requests. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### AgentsConsideredMalicious

The AgentsConsideredMalicious flag indicates that a suspicious request designed to mimic legitimate requests in an attempt to probe for vulnerabilities has been detected. This could be a sign of an attacker trying to gain unauthorized access to a system or exploit its weaknesses. MITRE ATT&CK techniques such as [T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071/) and [T1095: Standard Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/) may be relevant in situations involving agents considered malicious. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### NoAccessOutsideofRenderedLinks

The NoAccessOutsideofRenderedLinks flag indicates a security measure that prevents a user from accessing resources that were not rendered during a normal request pipeline. This can include attempts to access hidden or restricted pages, scripts, or other resources that were not explicitly made available through the application interface. MITRE ATT&CK techniques such as [T1100: Web Service](https://attack.mitre.org/techniques/T1100/) and [T1105: Remote File Copy](https://attack.mitre.org/techniques/T1105/) may be relevant in situations involving no access outside of rendered links. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### DenialOfService

The DenialOfService flag indicates a security attack designed to disrupt or deny access to a web application or system by overwhelming it with traffic or requests. This can include the use of automated tools, bots, or other means to flood the system with requests, causing it to slow down or become unresponsive. MITRE ATT&CK techniques such as [T1498: Network Denial of Service](https://attack.mitre.org/techniques/T1498/) and [T1499: Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) may be relevant in situations involving denial of service attacks. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### DenySystemAccess

The DenySystemAccess flag indicates a security measure that prevents a user from accessing any service on a server or network due to previous security detections or violations. This can include attempts to access restricted or unauthorized resources, violations of security policies, or other suspicious activity. MITRE ATT&CK techniques such as [T1091: Replication Through Removable Media](https://attack.mitre.org/techniques/T1091/) and [T1102: Web Service](https://attack.mitre.org/techniques/T1102/) may be relevant in situations involving deny system access. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.


### AttemptOnPluginConfiguration

The AttemptOnPluginConfiguration flag indicates a security violation that occurs when a user attempts to read or write to plugins or plugin configuration files on a system. This can include attempts to access plugins that are not intended to be accessed by regular users or make changes to plugin configurations that could potentially compromise the security of the system. MITRE ATT&CK techniques such as [T1061: Graphical User Interface](https://attack.mitre.org/techniques/T1061/) and [T1518: Software Discovery](https://attack.mitre.org/techniques/T1518/) may be relevant in situations involving attempts on plugin configuration. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### AttemptToAccessSiteUsingTheTechnologyStack

The AttemptToAccessSiteUsingTheTechnologyStack flag indicates a security violation that occurs when a user attempts to access an application, API, or web service using a technology stack that is not intended for that use case. This can include attempts to access a service using software tools such as NMAP, Ping, Postman, Excel, or using a protocol or interface that is not supported by the application or system. MITRE ATT&CK techniques such as [T1219: Remote Access Tools](https://attack.mitre.org/techniques/T1219/) and [T1506: Web Service](https://attack.mitre.org/techniques/T1506/) may be relevant in situations involving attempts to access site using the technology stack. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### AttemptToAccessSiteBackup

The AttemptToAccessSiteBackup flag indicates a security violation that occurs when a user attempts to access backups of an application, API, or web service. This can include attempts to access backup files that contain sensitive information, application or system configurations, or other resources that could be used to exploit vulnerabilities or gain unauthorized access to the system. MITRE ATT&CK techniques such as [T1005: Data from Local System](https://attack.mitre.org/techniques/T1005/) and [T1083: File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) may be relevant in situations involving attempts to access site backup. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.



### RequestPoisoningDetected 
The RequestPoisoningDetected flag indicates a security violation that occurs when a user or system sends malformed or intentionally crafted requests to a web application or API in an attempt to disrupt or compromise its normal operation. This can include attempts to inject malicious code or data, manipulate input fields or parameters, or exploit vulnerabilities in the system or its components. MITRE ATT&CK techniques such as [T1102: Web Service](https://attack.mitre.org/techniques/T1102/) and [T1216: Signed Script Proxy Execution](https://attack.mitre.org/techniques/T1216/) may be relevant in situations involving request poisoning. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms. 

### HoneyPotSocketDetected
The HoneyPotSocketDetected flag indicates a security violation that occurs when a user attempts to access a honey pot socket or port. A honey pot socket or port is a decoy or trap that is designed to detect and deflect unauthorized access attempts. MITRE ATT&CK techniques such as [T1043: Commonly Used Port](https://attack.mitre.org/techniques/T1043/) and [T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046/) may be relevant in situations involving honey pot socket detection. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms. 
 
### CommonVulnerabilitiesExposuresExploitDetected 
The CommonVulnerabilitiesExposuresExploitDetected flag indicates a security violation that occurs when a user or system attempts to exploit a known vulnerability in an application, system or service that has been identified and documented in the CVE database. MITRE ATT&CK techniques such as [T1068: Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) and [T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) may be relevant in situations involving CVE exploit attempts. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms. 

### PortScan 
The PortScan flag indicates a security violation that occurs when a user or system attempts to scan a network or system for  open ports or vulnerabilities. MITRE ATT&CK techniques such as [T1043: Commonly Used Port](https://attack.mitre.org/techniques/T1043/) and [T1046: Network Service Scanning](https://attack.mitre.org/techniques/T1046/) may be relevant in situations involving port scanning. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms. ### UnsafeDevice The UnsafeDevice flag indicates a security violation that occurs when a user or system attempts to access a network or system from a device that is known or suspected to be compromised or unsafe. MITRE ATT&CK techniques such as [T1031: Modify Existing Service](https://attack.mitre.org/techniques/T1031/) and [T1090: Connection Proxy](https://attack.mitre.org/techniques/T1090/) may be relevant in situations involving unsafe devices. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms.

### QueryStringManipulation

The QueryStringManipulation flag indicates a security violation that occurs when a user or system attempts to modify or manipulate the parameters in a query string to bypass security restrictions, gain unauthorized access, or execute malicious code. MITRE ATT&CK techniques such as [T1059: Command-Line Interface](https://attack.mitre.org/techniques/T1059/) and [T1500: Compile After Delivery](https://attack.mitre.org/techniques/T1500/) may be relevant in situations involving query string manipulation. The specific techniques involved can vary based on the attacker's intent and the target system's security mechanisms. Detection of a query string manipulation attempt is an indication of potential security threats and may require further investigation or action to prevent unauthorized access or data breaches.
