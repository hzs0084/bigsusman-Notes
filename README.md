# Cybersecurity Notes
A compilation of all I have done in Cybersecurity.

From CTFs, Interview Prep, to helpful online resources

I want this repository to be a hub of resources. I've often run into an issue when working on a CTF problem, or preparing for an interview, or tackling a box, where I have to look up what tool would be the best to use and sometimes there are those annoying Steg challenges that require you to know certain tools to get the flag. 

When I was also preparing for an interview, there was no specific structure for Cybersecurity Interviews, so I want this repo to be a resource for anyone preparing for interviews or a quick read on some topics.

I'm also going to organize the interviews and those experiences by company because each  MAANG company has its own unique way of interviewing.

Security Engineers have no structure for interviews. While the official title could be a Security Engineer, you need to study and prepare for multiple aspects during the interview. When compared to SWE interviews, you can grind LeetCode, study system design, and land the job, but for us, it's a different story. 

I am not saying that SWE interviews are easy but there are clear benchmarks for Software Devs than for security engineers, and there are many aspects that a security engineer needs to know and prepare for during an interview.

 
## By bigsusman

### Contents

- [OSINT](#osint)
- [Forensics](#forensics)
- [Web Application](#web-application)
- [Cloud Security](#infrastructure-prod--cloud-virtualisation)
- [Reverse Engineering](#reverse-engineering)
- [Cryptography](#cryptography)
- [Threat Detection](#threat-detection)
- [Bug Bounty](#bug-bounty)
- [Cybersecurity Pathways/Roadmaps](#career-pathways-or-roadmaps)
- [Books to Read](#books-to-read)
- [Exploits](#exploits)
- [Threat Modeling](#threat-modeling)
- [Interview Experiences](#interview-experiences)
- [Platforms to Upskill](#learning-platforms)
- [Amazing Research-Papers](#research-papers)
- [List of Cheatsheets](#cheatsheets)
- [Online tools for CTF](#ctf-tools)
- [Resources from Reddit and more](#helpful-resources)

# OSINT

[WhatsMyName Web](https://whatsmyname.app/) Incredible way to find someone if you know their username or have their username from a platform.

[OSINT Framework](https://osintframework.com/) Helps you visualize how to use OSINT to track/build a profile on someone

[Sourcing Games](https://sourcing.games/) This site helps you pratice and learn with challenges that can help you build OSINT skills.

[Data Broker Sites](https://www.aura.com/learn/how-to-remove-yourself-from-data-broker-sites) This article I think is a MUST read to understand why having your personal information out in the open is bad.

[OWASP Favicon DB](https://owasp.org/www-community/favicons_database) Recon tools like Shodan, FOFA, and Censys use favicon hashes to quickly identify web services.

[Certificate Search](https://crt.sh/) Ever curious to learn more about a certificate about a website? Fear not, as this site will helps you look at the nitty gritty details about a certificate, one of the ways I use it is take the hash of that certificate and click search

[Reverse Image Search](https://tineye.com/) This was incredibly helpful before google added the reverse image search but it can still come in handy.

[Name Checker](https://www.namecheckr.com/) Trying to learn where a username is available and being used, this can serve as a unique way to peek into where a person may be using the same username

[Shodan](https://www.shodan.io/) Imagine if you could go to a website and learn about it's IP, ports, and services that are open. Now what if you can also see the vulns that exist on that website. Yeah, that's shodan. There's also an extension available for it.

[Censys Search Engine](https://search.censys.io/) Just like shodan but better in my opinion

[WappAlyzer](https://www.wappalyzer.com/) An extension that helps you learn what frameworks, and how the site is built. The extension comes in very handy.

[AbuseIPDB](https://www.abuseipdb.com/) AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. You can report an IP address associated with malicious activity, or check to see if an IP address has been reported

[OSINT4ALL](https://start.me/p/L1rEYQ/osint4all) aims to provide practical & easy OSINT toolkit for researchers of all level to use.

[Wigle.net](https://wigle.net/index) Information about all SSIDs that are found by war drivers. 

# Forensics 

- [StegOnline](https://georgeom.net/StegOnline/upload) Runs a couple of CTF checklist from different images
- [AperiSolve] (https://www.aperisolve.com/) Aperi'Solve is an online platform which performs layer analysis on image. The platform also uses zsteg, steghide, outguess, exiftool, binwalk, foremost and strings for deeper steganography analysis. The platform supports the following images format: .png, .jpg, .gif, .bmp, .jpeg, .jfif, .jpe, .tiff...

- Wireshark 
    - 


# Web Application 

- How does SSL/TLS Cert work?
    - 1) User Creates his own Certificate Authority (rootCA and CA private key)
    - 2) Generate Server Private Key
    - 3) Use Server Private Key to Create CSR (Certificate Signing Request) with required info
    - 4) Use CSR and CA certs to generate SSL
    - 5) Use self signed certificate with the application
    - 6) Install user rootCA in browser or OS

- [HTTPS, SSL, TLS & CA Explained](https://www.youtube.com/watch?v=EnY6fSng3Ew&t=2014s) This is a god tier explanation of how HTTPS works and why we need certificates

- [PenTester Lab](https://pentesterlab.com/) Learn by exploiting real-world CVEs and analyzing vulnerabilities at the code level.

- PortSwigger Academy

- OWASP Juice Shop

- A guide on [SSRF](https://www.intigriti.com/researchers/blog/hacking-tools/ssrf-a-complete-guide-to-exploiting-advanced-ssrf-vulnerabilities#5-exploiting-second-order-ssrfs)

- SQLMap for SQL Injections

- [PicoCTF](https://play.picoctf.org/practice) I practiced a ton of Web Exp here but there's other categories as well!


# Infrastructure (Prod / Cloud) Virtualisation 
 
[Awesome Cloud Security Repo](https://github.com/4ndersonLin/awesome-cloud-security) A curated list of awesome cloud security related resources.

[Cloud Security Labs](https://github.com/iknowjason/Awesome-CloudSec-Labs)A list of free cloud native security learning labs. Includes CTF, self-hosted workshops, guided vulnerability labs, and research labs.

# Reverse Engineering

[Repo with RE Resources](https://github.com/wtsxDev/reverse-engineering) This is a collection of resources focused towards Reverse Engineering, it includes, books, challenges, dissassemblers, and many more cool stuff

[RE CTF](https://github.com/InfectedCapstone/Reverse_Engineering_CTFs) A list of beginner friendly reverse engineering CTF challenges to start off with reverse engineering tools and techniques

[More RE Resources](https://bbinfosec.medium.com/reverse-engineering-resources-beginners-to-intermediate-guide-links-f64c207505ed)


## Binary Exploitation

Add some Binary Exploitation resources here

# Cryptography

- [Cipher Identifier and Analyzer](https://www.boxentriq.com/code-breaking/cipher-identifier)Stuck with a cipher or cryptogram? This tool will help you identify the type of cipher, as well as give you information about possibly useful tools to solve it.
- [DCode Cipher Identifier](https://www.dcode.fr/cipher-identifier) There's tons of tools available on D Code as well but they also have a nice cipher identifier

# Threat Detection

[Awesome Threat Detection](https://github.com/0x4D31/awesome-threat-detection) I found this repository that goes into the deep end of threat detection. 

# Bug Bounty

[Bug Bounty Repo](https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters) This repo focuses on resources that anyone wants to dive in on how to get started with Big Bounty, very beginner friendly

There's a HackTheBox Pathway as well

HackerOne Bug Bounty


# Career Pathways or Roadmaps

- [Cyber Career Pathways Tool](https://niccs.cisa.gov/workforce-development/cyber-career-pathways-tool) This tool presents a new and interactive way to explore the updated work roles within the Workforce Framework for Cybersecurity (NICE Framework). It depicts the Cyber Workforce according to five distinct, yet complementary, skill communities. It also highlights core attributes among each of the 52 work roles and offers actionable insights for employers, professionals, and those considering a career in Cyber.

- [Security Certification Roadmap by Paul Jerimy](https://pauljerimy.com/security-certification-roadmap/) This can look a little overwhelming but it's a great resource on finding a domain of cybersecurity that you are interested in an understand where it stands and the cost of getting that cert.

- [TCM Security](https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course) This will take you to a Ethical Hacking course by TCM but have heard good things about it and it's less expensive than SANS, especially PJPT is one of their famous certs to get. 

- [CS 50 by Harvard](https://cs50.harvard.edu/cybersecurity/2023/) This is the online course of Intro to Cybersecurity by Harvard. Course presents both high-level and low-level examples of threats, providing students with all they need know technically to understand both. Assignments inspired by real-world events.


# Books to Read

- [Book Reviews](https://icdt.osu.edu/cybercanon/bookreviews) I am not aware of how the decision gets made but Ohio State University has this site where there are always interesting and fun books to read 


# Exploits

- [ExploitDB] (https://www.exploit-db.com/) Need an exploit? Search the service and it's version. Tons of great scripts to exploit a vulnerability.

# Threat Modeling

- [Excellent talk](https://www.youtube.com/watch?v=vbwb6zqjZ7o) on "Defense Against the Dark Arts" by Lilly Ryan (contains *many* Harry Potter spoilers)

# Interview Experiences

These are some of resources that I found for big tech companies to help prepare for interviews and their expeirences, it can obviously vary from role to role

### Microsoft

### Google

    ##Google Interview Resources

        - Apply your Coding Knowledge Series
            - [Part 1](https://www.youtube.com/watch?v=9EM6wRNVjBs)

### Meta

### Apple

### Amazon

### Netflix


# Learning Platforms

 - HackTheBox

 - TryHackMe

 - HackerOne

 - PicoCTF

 - OverTheWire

# Research Papers

A list of research papers that I think are cool and a must read

# Cheatsheets

Blue Team Cheatsheet

Nmap Cheatsheet

Red Team Cheatsheet

# CTF Tools

- Password Cracking Tools
    - [Hashes.com](https://hashes.com/en/decrypt/hash)
    - [Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/)
    - [Hash Analyzer by Hashes.com](https://hashes.com/en/tools/hash_identifier)
    - [NTLM Encrypt & Decrypt](https://md5decrypt.net/en/Ntlm/)
    - [Crackstation](https://crackstation.net/)
    - [Hash Identifier](https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master) Your own cli tool to help you identify hashes

- [Password Wordlists](https://weakpass.com/) Weakpass.com is a collection of password lists for various purposes from penetration testing to improving password security.
- [SecLists](https://github.com/danielmiessler/SecLists) More Password Wordlists
- [Base64 Encoding/Decoding](https://appdevtools.com/base64-encoder-decoder)

- [WPScan](https://wpscan.com/) Need to scan a WordPress Site for Vulns, fear not for WPScan targets common vulns present in WP sites.

- [LinPeas](https://github.com/rebootuser/LinEnum) Enumerate a Linux Box for vulnerabilties and then you can either harden them or exploit them

- [WinPeas](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) Enumerate a Windows Box for vulnerabilties and then you can either harden them or exploit them

- [Payloads of All Things](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) Check out the other lists as well, there's so much useful content here

- [SysMon](https://github.com/SwiftOnSecurity/sysmon-config) This is a Microsoft Sysinternals Sysmon configuration file template with default high-quality event tracing.
The file should function as a great starting point for system change monitoring in a self-contained and accessible package. This configuration and results should give you a good idea of what's possible for Sysmon. Note that this does not track things like authentication and other Windows events that are also vital for incident investigation.

- [GTFOBins](https://gtfobins.github.io/) GTFOBins is a curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems.
The project collects legitimate functions of Unix binaries that can be abused to get the f**k break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

- [DenCode] (https://dencode.com/en/) Tons of encoding and decoding tools

- [JWT Decode](https://jwt.io/) Paste a JWT below that you'd like to decode, validate, and verify.

- [JS Obfuscator](https://codebeautify.org/javascript-obfuscator)

- [JS Deobfuscator](https://obf-io.deobfuscate.io/)

- [HTTP Security Headers](https://securityheaders.com/) Scans for missing security headers by Snyk

- [MITRE ATT&CK](https://attack.mitre.org/) 

- [Quip Quip](https://quipqiup.com/) Runs frquency analysis on ciphers and quipqiup is a fast and automated cryptogram solver by Edwin Olson.

- [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express) A tool to find XSS vulns


# Helpful Resources 

- [Interview Study Notes by Nolang](https://github.com/gracenolan/Notes) on GitHub. I have borrowed the idea of notes, while this repo by nolang talks about what helped them prepare for interview. I want to take this a step further. I WOULD HIGHLY SUGGEST going through this as there might be some overlap for concepts but that repo goes into more detail than mine will.

- [Security Engineer Interviews at MAANG](https://www.teamblind.com/post/I-did-85-security-engineer-on-sites-with-top-tech-companies%E2%80%A6a-prep-guide-LyANPVE6) This is another good read to get an insight as they did multiple on-site interviews at big tech companies.

- [RegEx](https://regexone.com/) Learn RegEx in a fun way, this comes very handy when you are working on bash, powershell, or Python Scripts

- [Piping](https://www.linuxjournal.com/article/2156) Understand how piping actually works in terminal

- [ICS/OT Youtube Channel](https://www.youtube.com/@utilsec) There are some really cool videos on ICS if anyone is interested

- [DNS Dumpster](https://dnsdumpster.com/) DNSDumpster.com is a FREE domain research tool that can discover hosts related to a domain. Finding visible hosts from the attackers perspective is an important part of the security assessment process.

- [Awesome Annual Reports](https://github.com/jacobdjwilson/awesome-annual-security-reports) This list aims to cut through the noise by providing a vendor-neutral resource for the latest security trends, tools, and partnerships. It curates information from trusted sources, making it easier for security leaders to make informed decisions.

- [Hacking Google](https://www.youtube.com/watch?v=5nEyjYn9_LI&list=PL590L5WQmH8dsxxz7ooJAgmijwOz0lh2H) This is a YouTube series about Google and gives a good insight on how the security works at Google and the big major teams at Google

- [TCP Handshake](https://www.youtube.com/watch?v=F27PLin3TV0) This video for me personally does a really good explantation on what happens during the three-way handshake and it also goes into the Wireshark pcap at the end to see it in action. 

- [Networking Tutorial Playlist](https://www.youtube.com/playlist?list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW) A great playlist to get information and cover a lot of information on what you need to know about networks as you get started

- Podcasts
    - Darknet Diaries
    - Shared Secrets

- [CTF Time](https://ctftime.org/) You can always find an online CTF to participate and upskill

- [DFIR Report](https://thedfirreport.com/) Real Intrusions by Real Attackers, The Truth Behind the Intrusion

- [DNSSec] (https://howdnssec.works/) How DNSSEC works