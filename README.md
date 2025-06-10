# Characterizing JavaScript Security Code Smells
JavaScript has been consistently among the most popular programming languages in the past decade. However, its dynamic, weakly-typed, and asynchronous nature can make it challenging to write maintainable code for developers without in-depth knowledge of the language. Consequently, many JavaScript applications tend to contain code smells that adversely influence program comprehension, maintenance, and debugging. Due to the widespread usage of JavaScript, code security is an important matter. While JavaScript code smells and detection techniques have been studied in the past, current work on security smells for JavaScript is scarce. Security code smells are coding patterns indicative of potential vulnerabilities or security weaknesses. Identifying security code smells can help developers to focus on areas where additional security measures may be needed. We present a set of 24 JavaScript security code smells, map them to a possible security awareness defined by Common Weakness Enumeration (CWE), explain possible refactoring, and explain our detection mechanism. We implement our security code smell detection on top of an existing open source tool that was proposed to detect general code smells in JavaScript.



[JSNose](https://github.com/saltlab/JSNose) is a JavaScript code smell detector tool written in Java. We have extended the tool to detect security code semlls in JavaScript:


| **Security Code Smell**            | **Common Weakness Enumerator** [MITRE](https://cwe.mitre.org/)                    | **OWASP Top 10** [OWASP](https://owasp.org/)               |
|------------------------------------|----------------------------------------------------------------------------------|------------------------------------------------------------|
| Large Object                       | CWE-1120 (Excessive Code Complexity), CWE-1093 (Excessively Complex Data Representation), CWE-1080 (Source Code File with Excessive Number of Lines of Code) | Insecure Direct Object References                           |
| Long Method/Function               | CWE-1080 (Source Code File with Excessive Number of Lines of Code), CWE-1120 (Excessive Code Complexity) | Insecure Direct Object References                           |
| Long Parameter List                | CWE-1120 (Excessive Code Complexity), CWE-1093 (Excessively Complex Data Representation) | Injection                                                   |
| Empty Catch Blocks                 | CWE-703 (Improper Check or Handling of Exceptional Conditions), CWE-1069 (Empty Exception Block), CWE-1071 (Empty Code Block) | Improper Error Handling                                     |
| Unused/dead code                   | CWE-561 (Dead Code), CWE-1164 (Irrelevant Code)                                    | Injection                                                   |
| Nested Callback                    | CWE-1124 (Excessively Deep Nesting)                                                | Security Misconfiguration                                   |
| Excessive Global Variables         | CWE-1108 (Excessive Reliance on Global Variables)                                  | Insecure Direct Object References                           |
| Coupling between JS and HTML       | CWE-116 (Improper Encoding or Escaping of Output), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) | Cross-Site Scripting                                        |
| Hard-coded Sensitive Information   | CWE-798 (Use of Hard-coded Credentials), CWE-259 (Use of Hard-coded Passwords), and CWE-693 (Protection Mechanism Failure) | Identification and Authentication Failures                  |
| Missing Default in Case Statement  | CWE-478 (Missing Default Case in Switch Statement)                                 | Insecure Direct Object References, Injection                |
| Use of Weak Cryptography           | CWE-326 (Inadequate Encryption Strength), CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-328 (Use of Weak Hash), CWE-1240 (Use of a Risky Cryptographic Primitive) | Cryptographic Failures                                      |
| HTTP without SSL/TLS               | CWE-319 (Cleartext Transmission of Sensitive Information)                          | Cryptographic Failures                                      |
| Unverified Cross-Origin Communications | CWE-345 (Insufficient Verification of Data Authenticity)                          | Broken Access Control                                       |
| Active Debugging Code              | CWE-489 (Active Debug Code), CWE-215 (Insertion of Sensitive Information Into Debugging Code) | Sensitive Data Exposure                                     |
| Dynamic Code Execution             | CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code), CWE-77 (Command Injection), CWE-20 (Improper Input Validation) | Injection                                                   |
| Insecure DOM Manipulation          | CWE-79 (Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)) | Injection                                                   |
| Unvalidated Redirect               | CWE-20 (Improper Input Validation), CWE-601 (URL Redirection to Untrusted Site (Open Redirect)) | Broken Access Control                                       |
| JSON Injection                     | CWE-74 (Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)), CWE-116 (Improper Encoding or Escaping of Output), CWE-77 (Command Injection) | Injection                                                   |
| Unprotected Cookies                | CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute), CWE-315 (Cleartext Storage of Sensitive Information in a Cookie), CWE-311 (Missing Encryption of Sensitive Data), CWE-565 (Reliance on Cookies without Validation and Integrity Checking) | Insecure Design, Security Misconfiguration                  |
| Long Prototype Chain               | CWE-1074 (Class with Excessively Deep Inheritance)                                 | Injection                                                   |
| Prototype Pollution                | CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)) | Cross-Site Scripting                                        |
| Insecure Dependencies              | CWE-1395 (Dependency on Vulnerable Third-Party Component), CWE-1104 (Use of Unmaintained Third Party Components) | Vulnerable and outdated components                          |
| Logging Sensitive Information      | CWE-532 (Insertion of Sensitive Information into Log File), CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor), CWE-312 (Cleartext Storage of Sensitive Information) | Security Logging and Monitoring Failures                    |
| Insecure File Handling             | CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-646 (Reliance on File Name or Extension of Externally-Supplied File) | Insecure Data Storage                                       |
| Error Handling Disclosure          | CWE-209 (Generation of Error Message Containing Sensitive Information), CWE-497 (Exposure of Sensitive System Information to an Unauthorized Control Sphere) | Improper Error Handling                                     |


# Paper
V. Kambhampati, N. H. Mohammed, A. Milani Fard., ["Characterizing JavaScript Security Code Smells”](https://arxiv.org/pdf/2411.19358), arXiv preprint arXiv:2411.19358, 2024.


# Citation
```
@article{2024characterizing,
author={Kambhampati, Vikas and Mohammed, Nehaz Hussain and Milani Fard, Amin},
title={Characterizing JavaScript Security Code Smells},
journal={arXiv preprint arXiv:2411.19358},
year = {2024}
}
```


Original JSNose Paper
-----
A. Milani Fard, A. Mesbah, ["JSNose: Detecting JavaScript Code Smells”](https://people.ece.ubc.ca/aminmf/SCAM2013.pdf), 13th IEEE International Conference on Source Code Analysis and Manipulation (SCAM 2013), Eindhoven, The Netherlands, 2013

Usage
-----------------

Run it trough the Main class in JSNose/src/main/java/com/crawljax/examples/JSNoseExample.java

The core smell detection process and thresholds are located in JSNose/src/main/java/codesmells/SmellDetector.java
