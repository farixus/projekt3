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
