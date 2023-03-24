# Project 3 - Infrastructure pentesting
## Security Raport
### Subject
Penetration testing of machine: Vulnnet: Intranet - https://tryhackme.com/room/vulnnetinternal
### Date
11-03-2023 - 12-03-2023
### Location
Somewhere in Poland
### Auditors
Rafał Deptuch
### Version
1.0

## Executive summay
This document is a summary of work proceeded by Group od SDA. The subject of the tests were to gather all flags using all posssible tools and knowledge.
The machine is under address: https://tryhackme.com/room/vulnnetinternal
The tests were carried out by using greybox - ip address was delivered.

The most severe vulnerability identified during the assessment were:
- XSS - possibility to inject python code to obtain shell with root privileges 

The security tests were carried out in accordance with generally accepted methodologies, including: OWASP TOP10 (in a selected range), OWASP ASVS as well as wide knowledge absorbed form SDA course.

As a part of the testing, an approach based on manual tests (using the above-mentioned methodologies) was used, supported by a number of automatic tools, i.a. enum4linux, redis-cli, ssh-keygen, nmap, grep, rsync, ssh, wget, telnet.

The vulnerabilities are described in detail in further parts of the report. 

## Risk classification 
Vulnerabilities are classified in a five-point scale reflecting both the probability of exploitation of the
vulnerability and the business risk of its exploitation. Below is a short description of meaning of each
of severity levels. 
 
- CRITICAL - exploitation of the vulnerability makes it possible to compromise the server
or network device or makes it possible to access (in read and/or write mode) to data with
a high degree of confidentiality and significance. The exploitation is usually
straightforward, i.e. the attacker need not gain access to systems that are difficult to
achieve and need not perform any kind of social engineering. Vulnerabilities marked
CRITICAL must be fixed without delay, especially if they occur in production environment. 
- HIGH - exploitation of the vulnerability makes it possible to access sensitive data (similar
to CRITICAL level), however the prerequisites for the attack (e.g. possession of a user
account in an internal system) makes it slightly less likely. Alternatively: the vulnerability
is easy to exploit but the effects are somehow limited. 
- MEDIUM - exploitation of the vulnerability might depend on external factors (e.g.
convincing the user to click on a hyperlink) or other conditions that are difficult to achieve.
Furthermore, exploitation of the vulnerability usually allows access only to a limited set of
data or to data of a lesser degree of significance. 
- LOW - the exploitation of the vulnerability results in little direct impact on the security of
the application or depends on conditions that are very difficult to achieve practically (e.g.
physical access to the server). 
- INFO - issues marked as INFO are not security vulnerabilities per se. They aim to point
out good practices, whose implementation will result in increase of general security level
of the system. Alternatively: the issues point out some solutions in the system (e.g. from
an architectural perspective) that might limit the negative effects of other vulnerabilities.

## CVSS - Common Vulnerability Scoring System
CVSS is broken down into 8 different metrics. In this section, we’ll explore each one and how to pick the right choice when filing a submission on HackerOne.

- Attack Vector - This metric tells the security team how this vulnerability can be exploited. The Score increases the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component. Describing deeply the 4 scenarios, we can have: a Remote attack when the exploit can be delivered over the Internet, an Adjacent attack vector when the malicious actor is inside the same intranet of the victim, a Local scenario is when the issue lies at operating system accounts level, and finally a Physical attack vector is when you can physically access the victim’s device.
- Attack Complexity - Attack Complexity describes the conditions beyond your control that must be met in order for the vulnerability to be exploited. For example, does it require additional information about the target such as unguessable IDs, a certain configuration or settings, valid credentials (e.g. for MFA issues), or some other conditions in order for your exploit to work?
- Privileges Required - This metric indicates the type of privileges an attacker must achieve before successfully exploiting the vulnerability. This Score increases as fewer privileges are required. For example, if the vulnerable component is within an admin panel, we recommend setting the requirement to “High” versus a vulnerability where you need to be invited to an organization by an admin (where as self registration is not possible) we recommend privileges to be as low.
- User Interaction - This metric captures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component. This metric determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user (or user-initiated process) must participate in some manner. The Score is highest when no user interaction is required since it increases a further step in the exploitability of the attack.
- Scope - Does a successful attack impact a component other than the vulnerable component? If so, the Score increases and the Confidentiality, Integrity and Authentication metrics should be scored relative to the impacted component.
- Confidentiality - This metric measures the impact on the confidentiality of the information resources managed by a software due to a successfully exploited vulnerability. Confidentiality refers to limiting information access and disclosure to only authorized users, as well as preventing access by, or disclosure to, unauthorized. In the context of bug bounties, think of this as how sensitive is the data which is exposed due to this vulnerability.
- Integrity - This metric measures the impact to the integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.
- Availability - This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. It refers to the loss of availability of the impacted component itself, such as a networked service (e.g., web, database, email). Since availability refers to the accessibility of information resources, attacks that consume network bandwidth, processor cycles, or disk space all impact the availability of an impacted component.

## Estimated threat using CVSS calculator
![](https://github.com/farixus/projekt3/blob/main/screenshots%20VulnNet%20Internal/CVSS.png)


## Table of content

[TOCM]

[TOC]

## Change history

2023-03-24 version 1.0 Final version of the report after carried tests out.

## Process of gathering flags

### Summary
The aim of this tasks is to find several flag across the system. The main issue

As a result of exploration the system, we obtain following flags:
1. What is the services flag? (services.txt) THM{0a09d51e488f5fa105d8d866a497440a}
2. What is the internal flag? ("internal flag") THM{ff8e518addbbddb74531a724236a8221}
3. What is the user flag? (user.txt) THM{da7c20696831f253e0afaca8b83c07ab}
4. What is the root flag? (root.txt) THM{e8996faea46df09dba5676dd271c60bd}

### Prerequisites for the attack
An IP address

### Technical details (Proof of concept)
Here are the steps that we were able to retrieve interesting information above.

1. Nmap scanning
First we had to scan the machite to find interesting open ports and services. At the same time we try to discover names of applications, version and vulnerabilites connected with them as well as operating system and kernel version

```
sudo nmap -sSCV -T4 -A --script=default,vuln -oA nmap_scan 10.10.77.37
```


