Cybersecurity Vulnerability Assessment - Nmap & Wireshark

Overview
This project highlights some essential penetration testing techniques to evaluate the security of the website http://testphp.vulnweb.com/, aiming to discover vulnerabilities and propose steps to improve the security posture. The three main tasks performed include scanning for open ports using Nmap, directory brute-forcing with Dirb, and intercepting network traffic with Wireshark to capture unencrypted credentials.

1. Find All Open Ports on the Website
Tools Required:

Nmap (Network Mapper)
Terminal or Command Prompt
Steps to Reproduce: To identify open ports on the website, run an Nmap scan:

bash
Copy
Edit
nmap testphp.vulnweb.com
Results: The Nmap scan reveals the following open ports on testphp.vulnweb.com:

Port 53 (TCP): Domain Name System (DNS) – Used for domain name resolution.
Port 80 (TCP): HTTP (HyperText Transfer Protocol) – Used for serving web pages over an unencrypted connection.
Mitigation Steps:

Restrict Open Ports: Close unused ports by using firewalls or security groups.
Use Strong Passwords: Secure services like SSH with strong, unique passwords and key-based authentication.
Regular Scans: Conduct periodic scans to identify new vulnerabilities.
Update Systems: Keep software and systems updated to patch known vulnerabilities.
2. Brute Force the Website and Find Directories
Attack Name: Directory Brute Forcing

Tools Required:

Dirb (Directory Brute-Forcing Tool)
Terminal or Command Prompt
Steps to Reproduce:

Install Dirb.
Run a directory brute-force scan on the website:
bash
Copy
Edit
dirb http://testphp.vulnweb.com/
Severity:

Unauthorized Access: 7.2 (High)
Information Exposure: 5.6 (Medium)
Reconnaissance Risk: 6.5 (Medium-High)
Impact:

Disclosure of Information: Hidden directories may contain important files like configurations or backups.
Unauthorized Access: Attackers may discover and exploit admin panels or logging pages.
System Vulnerability: Exposing directories could reveal system weaknesses that attackers may exploit.
Mitigation Steps:

Restrict Directory Access: Use .htaccess or similar techniques to protect sensitive directories.
Hide Directory Listings: Disable directory indexing in server configurations.
Develop Strong Directory Names: Avoid easily guessable names like /admin or /backup.
Apply Authentication: Secure important directories with login mechanisms.
Monitor Suspicious Activity: Regularly review logs and deploy Web Application Firewalls (WAF) to block brute-force attempts.
3. Intercept Network Traffic and Find Credentials
Attack Name: Man-in-the-Middle (MitM) Attack on Unencrypted HTTP Traffic

Severity:

High (CVSS Score: 7.4)
Steps to Reproduce:

Start Wireshark: Open Wireshark and select your network interface (Wi-Fi or Ethernet).
Login to the Website: Go to http://testphp.vulnweb.com/ and log in using the credentials (username: abcd, password: password123).
Capture HTTP Traffic: Apply a filter for HTTP traffic in Wireshark by typing http in the filter bar.
Identify Credentials: Look for the HTTP POST request containing the credentials in the captured traffic.
Impact:

Intercepting HTTP Traffic: Login credentials are transmitted in clear text, exposing sensitive information.
Credential Theft: Attackers can easily steal usernames and passwords without bypassing any security mechanisms.
Security Breach: Once credentials are stolen, attackers can gain unauthorized access and compromise user accounts.
Mitigation Steps:

Use HTTPS: Encrypt communication with SSL/TLS to protect sensitive data in transit.
Implement Strong Authentication: Encourage multi-factor authentication (MFA) for additional security.
Educate Users: Promote the importance of using secure (HTTPS) connections, especially on public networks.
Use Secure Cookies: Ensure session data is transmitted securely by using the Secure and HttpOnly flags for cookies.
Monitor and Audit: Continuously monitor network traffic for suspicious activity and perform regular security audits.
Resources Used
Nmap: A tool for discovering open ports and services on a network, helping identify vulnerable services.
Wireshark: A network protocol analyzer used to capture and inspect network traffic, critical for detecting unencrypted data transmission.
