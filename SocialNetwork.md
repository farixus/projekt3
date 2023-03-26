# Project 3 - Infrastructure pentesting
## Security Raport
### Subject
Penetration testing of machine: [BOREDHACKERBLOG: SOCIAL NETWORK](https://www.vulnhub.com/entry/boredhackerblog-social-network,454/)
### Date
11-03-2023 - 12-03-2023
### Location
Somewhere in Poland
### Auditors
Rafał Deptuch, Przemysław Stachurski, Krzysztof Konkol
### Version
1.0

## Executive summay
### Scope and assumptions
This document is a summary of work proceeded by Group od SDA. The main subject of the tests were to obtain root privileges. The test focuses on security issues leading to compromise victim's machine.
The machine exists as a virtual machine (Virtualbox -OVA), which can be downloaded form [this link](https://www.vulnhub.com/entry/boredhackerblog-social-network,454/)
The tests were carried out by using blackbox - network access is to discover.

### Most severe vulnerabilites idenifies

[CVE-2021-4034](https://nvd.nist.gov/vuln/detail/CVE-2021-4034)
NIST: NVD
Base Score: 7.8 HIGH
Vector:  CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.


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

## Change history

2023-03-26 version 1.0 Final version of the report after carried tests out.

## Process of exploiting machine

### Summary
During the process some technics were used to get finnaly root privileges. Despite docker technology was used, root privileges has been gain as a result of misconfiguration, poorly password protection and use of documented vulnerability. Methods and technics were used:
-port scanning
-webapp attacks
-code injection
-pivoting
-exploitation
-password cracking
-brute forcing

### Prerequisites for the attack
Local internet access

### Technical details (Proof of concept)
First of all we needed to discover ip address of victim. Therefor we used nmap.
```
nmap -sP 192.168.10.0/24 -oA network_scan
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-12 08:59 CET
Nmap scan report for 192.168.10.x
Host is up (0.0051s latency).
Nmap scan report for 192.168.10.x
Host is up (0.038s latency).
Nmap scan report for 192.168.10.x
Host is up (0.00050s latency).
Nmap scan report for 192.168.10.x
Host is up (0.00028s latency).
Nmap scan report for 192.168.10.104
Host is up (0.00026s latency).
Nmap scan report for 192.168.10.108
Host is up (0.00024s latency).
Nmap done: 256 IP addresses (6 hosts up) scanned in 2.36 seconds
```
![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/01.host_discover.png)

Victim's IP address: 192.168.10.108

Detailed scan showed services on machine.
```
nmap -sSCV -T4 -A --script=default,vuln -oA nmap_scan 192.168.10.108

22/tcp   open  ssh     OpenSSH 6.6p1 Ubuntu 2ubuntu1 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.15)
```
We so, that http service is running on machine. Try to access via browser.
Default page:
![](https://github.com/farixus/projekt3/blob/main/screenshots_Social_Network/02.start_page_5000.png)

### Recommendation
