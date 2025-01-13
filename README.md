1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging & Monitoring Failures
10. Server-Side Request Forgery (SSRF)

# Broken Access Control
Broken Access Control is a security issue where a system fails to properly restrict the activities that authenticated users are allowed to perform. 
This vulnerability can lead to unauthorized access to sensitive data or functions beyond the user’s permissions.

Scenario:
A user with a regular account can change their role to an admin in the URL, and suddenly gain access to sensitive admin functions without proper authorization.

Impact:
	a) Data Breach: Unauthorized access to sensitive data, leading to data theft or leakage.
	b) Functionality Misuse: Users performing actions outside of their intended permissions, potentially causing operational disruptions.
	c) Elevation of Privilege: Attackers gaining higher-level privileges, which could lead to full system compromise.

Prevention:
	a. Least Privilege Principle: Users should only have the minimum level of access required to perform their tasks.
	b. Access Control Lists (ACLs): Implementing ACLs to define who can access what resources in the system.
	c. Role-Based Access Control (RBAC): Assigning permissions based on roles within the organization.
	d. Regular Audits: Conducting regular security audits to ensure access controls are working as intended.
	e. Automated Testing: Using automated tools to test for access control issues during development and deployment.

List of vulns:
	a. Insecure Direct Object References (IDOR): This occurs when an application provides direct access to objects based on user-supplied input. As a result, attackers can bypass authorization and access data and functions directly.
	b. Insufficient Authentication: When applications do not enforce strong authentication mechanisms, attackers can gain unauthorized access by exploiting weak or stolen credentials.
	c. CORS Misconfiguration: Incorrectly configured Cross-Origin Resource Sharing (CORS) can allow attackers to access APIs from unauthorized domains.
	d. Force Browsing: Attackers can access restricted pages by modifying the URL to access files or directories that they should not have access to.
	e. Elevation of Privilege: This allows users to gain higher privileges than they are entitled to, potentially leading to full system compromise.
	f. Metadata Manipulation: Tampering with tokens, cookies, or other metadata can lead to privilege escalation or unauthorized actions.
	g. Missing Function Level Access Control: Sometimes, applications do not properly protect functions that require a higher privilege level, allowing lower-privileged users to execute these functions.
	h. Bypassing Access Control Checks: Attackers may change the request to bypass the access control checks and gain unauthorized access to functionalities.

# Cryptographic Failures
A cryptographic failure refers to any vulnerability arising from the misuse (or lack of use) of cryptographic algorithms for protecting sensitive information. Web applications require cryptography to provide confidentiality for their users at many levels.
For example, a secure email application:
	• When you are accessing your email account using your browser, you want to be sure that the communications between you and the server are encrypted. That way, any eavesdropper trying to capture your network packets won't be able to recover the content of your email addresses. When we encrypt the network traffic between the client and server, we usually refer to this as encrypting data in transit.
	• Since your emails are stored in some server managed by your provider, it is also desirable that the email provider can't read their client's emails. To this end, your emails might also be encrypted when stored on the servers. This is referred to as encrypting data at rest.

Scenario:
Sending passwords or credit card details over HTTP instead of HTTPS, leaving the data vulnerable to eavesdropping.

Impact:
	a) Compromised Data: Sensitive information may be exposed or stolen.
	b) Loss of Trust: Users trust in the application or service can be severely damaged.
	c) Regulatory Penalties: Non-compliance with data protection laws can result in hefty fines.
	d) Security Breaches: Weaknesses in cryptography can be exploited by attackers to gain unauthorized access to 
	
Prevention:
	a. Strong Encryption: Use strong and current encryption algorithms to protect data in transit and at rest.
	b. Key Management: Implement robust key management practices, including key rotation and secure key storage.
	c. Randomness: Ensure that cryptographic randomness requirements are met to strengthen the encryption.
	d. Authentication: Properly authenticate parties in a cryptographic exchange to prevent man-in-the-middle attacks.
	e. Regular Updates: Stay updated with the latest cryptographic standards and best practices to avoid dependence on obsolete methods
	
List of vulns:
	a) Use of Hard-coded Password (CWE-259): This involves the use of hard-coded passwords, which can be easily discovered and exploited.
	b) Broken or Risky Crypto Algorithm (CWE-327): This refers to the use of weak or broken cryptographic algorithms that can be easily cracked.
	c) Insufficient Entropy (CWE-331): This occurs when the randomness used for cryptographic purposes does not meet the required cryptographic standards.
	d) Weak Encryption: Using an encryption algorithm no longer considered secure, such as DES or RSA with a small key size, can make it relatively easy for an attacker to decrypt the information.
	e) Improper Key Management: Failing to protect or rotate encryption keys adequately can compromise sensitive information.
	f) Inadequate Randomness: Some cryptographic algorithms, such as generating session keys, require a source of valid random numbers. Using a Pseudo Random Number Generator instead can weaken the encryption.
	g) Inadequate Authentication: Failing to authenticate parties properly in a cryptographic exchange can lead to man-in-the-middle attacks, where an attacker intercepts and alters communications.
	h) Dependence on Obsolete Standards: Such as SSL V2 and SSL V3, which had critical vulnerabilities exploited in the wild.
	
	
# Injection
When a user controlled input is interpreted as actual commands or parameters by the application. Injection attacks depend on what technologies are being used and how exactly the input is interpreted by these technologies. 

Scenario:
An attacker inputs SQL commands like '; DROP TABLE users;-- in a login form, which might result in the deletion of a database table.

Impact:
	a) Access, Modify and Delete information in a database when this input is passed into database queries. This would mean that an attacker can steal sensitive information such as personal details and credentials.
	b) Execute Arbitrary system commands on a server that would allow an attacker to gain access to users’ systems. This would enable them to steal sensitive data and carry out more attacks against infrastructure linked to the server on which the command is executed.
	c) Unauthorized data access.
	d) Compromised data integrity and availability.
	e) Complete host takeover.
	f) Disclosure of sensitive information.
	g) Data loss or corruption
	
Prevention:
	a. Using an allow list: when input is sent to the server, this input is compared to a list of safe input or characters. If the input is marked as safe, then it is processed. Otherwise, it is rejected and the application throws an error.
	b. Stripping input: If the input contains dangerous characters, these characters are removed before they are processed.
	c. Using safe APIs that avoid using the interpreter entirely.
	d. Employing parameterized queries or ORM (Object Relational Mapping) tools.
	e. Implementing positive server-side input validation.
	f. Applying least privilege principles to minimize the potential impact
	

List of vulns:
	a. Command Injection: This occurs when user input is passed to system commands. As a result, an attacker is able to execute arbitrary system commands on application servers.
	b. SQL Injection: This occurs when user controlled input is passed to SQL queries. As a result, an attacker can pass in SQL queries to manipulate the outcome of such queries.
	c. NoSQL Injection: Similar to SQL Injection but targets NoSQL databases.
	d. LDAP Injection: Manipulates LDAP statements used for directory services.
	e. Expression Language Injection: Abuses weaknesses in template engines or expression interpreters.
	f. XML External Entities (XXE) Injection (CWE-611): Exploits XML processors to interfere with application processing.
	g. Cross-Site Scripting (XSS) (CWE-79): Injects malicious scripts into content served to end-users.
	h. ORM Injection: Targets vulnerabilities in Object Relational Mapping (ORM) tools.
	i. XPath Injection: Manipulates XPath queries used in XML databases.
	j. Header Injection: Injects malicious header content, often leading to response splitting attacks.

# Insecure Design
Risks related to design and architectural flaws of software development. These vulnerabilities occur when an improper threat modelling (identify valuable data like user info, define security requirements based on data) is made during the planning phases of the application and propagate all the way up to your final app.

Scenario: 
	a. An application allowed users to reset their forgotten passwords by sending them a 6-digit code to their mobile number via SMS for validation. For prevention they applied rate limit on same IP, but bypassed by using X-forwarded-for.
	b. Forgot password feature has simple security questions like favourite colour and after giving correct answer it will give new password result in account takeover.

Impact:
	a) Functionality failures.
	b) Data breaches.
	c) Violation of business policies.
	d) Tarnished reputations.
	e) Exploitation by threat actors who can bypass authentication, modify URL parameters, access sensitive information, or assume legitimate user accounts
	
Prevention:
	a. To avoid password-guessing attacks, ensure the application enforces a strong password policy. 
	b. To avoid brute force attacks, ensure that the application enforces an automatic lockout after a certain number of attempts. This would prevent an attacker from launching more brute-force attacks.
	c. Implement Multi-Factor Authentication. If a user has multiple authentication methods, for example, using a username and password and receiving a code on their mobile device, it would be difficult for an attacker to get both the password and the code to access the account.
	
List of vulns:
	a) Brute force attacks: If a web application uses usernames and passwords, an attacker can try to launch brute force attacks that allow them to guess the username and passwords using multiple authentication attempts. 

# Security Misconfiguration
Improper configuration of security settings, permissions, and controls that can lead to vulnerabilities and unauthorized access.

Scenario:
A web server that is left with default settings or has excessive permissions, such as leaving sensitive files or directories publicly accessible (e.g., exposed admin interfaces or database backups).

Impact:
	a) Security misconfigurations can lead to unauthorized access, data leaks, and system compromise.
	b) Attackers may exploit these weaknesses to gain access to sensitive information or manipulate the application.
	c) Default credentials giving you access to sensitive data, XML External Entities (XXE) or command injection on admin pages.
	
Prevention:
	a. Implement secure installation processes:
	b. Automate repeatable hardening processes (closing potential attack vector and routinely updating systems to avoid being exploit)for consistent deployment.
	c. Configure development, QA, and production environments identically with different credentials.
	d. Maintain a minimal platform without unnecessary features or frameworks.
	e. Regularly review and update configurations based on security notes, updates, and patches.
	f. Automate verification of configurations in all environments.
	
List of vulns:
	a) Default accounts and passwords remaining enabled and unchanged.
	b) Unrestricted HTTP Methods: A web server is configured to allow HTTP methods like PUT or DELETE without proper authentication. This can allow attackers to modify or delete resources on the server.
	c) Error handling revealing overly informative error messages or stack traces to users.
	d) Missing security headers or directives from the server.
	e) Improperly set security settings in application servers, frameworks, libraries, and databases
	f) Poorly configured permissions on cloud services, like S3 buckets.
	g) Having unnecessary features enabled, like services, pages, accounts or privileges.

# Vulnerable and Outdated Components
Vulnerable and outdated components refer to software libraries, frameworks, or other third-party components that have known security vulnerabilities or are no longer actively maintained. These components can be found in various parts of a software system, including the operating system, web/application servers, databases, and client-side libraries

Scenario:
An application uses an outdated version of a JavaScript library like jQuery, which contains a known cross-site scripting (XSS) vulnerability.

Impact:
	a) Security Breaches: Attackers can exploit known vulnerabilities to gain unauthorized access, steal data, or take control of the system.
	b) System Instability: Outdated components may not be compatible with newer software, leading to crashes or other operational issues.
	c) Compliance Issues: Using unsupported software can lead to non-compliance with industry regulations and standards.
	
Prevention:
	a. Patch Management: Regularly update and patch all components. Implement a process to ensure timely updates.
	b. Inventory Management: Maintain an inventory of all software components, including their versions and dependencies.
	c. Vulnerability Scanning: Use tools like OWASP Dependency-Check or Snyk to scan for known vulnerabilities in your components.
	d. Secure Sources: Only download components from official and secure sources. Prefer signed packages to reduce the risk of tampered components.
	e. Monitoring and Alerts: Subscribe to security bulletins and alerts for the components you use to stay informed about new vulnerabilities
	
List of vulns:
	a) Unpatched Libraries: Libraries like jQuery, AngularJS, or ReactJS that have known vulnerabilities but haven’t been updated.
	b) Outdated Frameworks: Web application frameworks such as Ruby on Rails, Django, or Spring that are not updated to the latest secure versions.
	c) Operating System Vulnerabilities: Unpatched vulnerabilities in operating systems, such as the Windows SMB vulnerability (EternalBlue).
	d) Web Server Vulnerabilities: Outdated versions of web servers like Apache or IIS that have known security issues.
	e) Database Management Systems: Vulnerabilities in outdated versions of database management systems (DBMS) like MySQL or PostgreSQL.
	f) Third-Party Components: Use of unmaintained third-party components that may have security flaws.
	g) Nested Dependencies: Vulnerabilities in nested dependencies that are not directly visible but are part of the software stack.
	
# Identification and Authentication Failures
If an attacker is able to find flaws in an authentication mechanism, they might successfully gain access to other users' accounts. This would allow the attacker to access sensitive data (depending on the purpose of the application). 

Scenario:
An app that allows users to reset their password by only asking for their username and email, but does not ask for additional security questions, making it easy for an attacker to reset the password and take over the account.

Impact:
	a) Unauthorized Access: Attackers can bypass authentication mechanisms, gaining entry to sensitive resources.
	b) Data Exposure: Sensitive data may be exposed due to weak authentication controls.
	c) Session Hijacking: Attackers can take over active user sessions.
	d) Brute Force Attacks: Repeated login attempts can compromise accounts.
	e) Credential Stuffing: Attackers reuse stolen credentials across multiple services
	
	
Prevention:
	a. Implement multi-factor authentication (MFA) to prevent automated attacks.
	b. Avoid shipping or deploying with default credentials (especially for admin users).
	c. Enforce strong password policies based on modern guidelines (e.g., NIST 800-63b).
	d. Harden registration, credential recovery, and API pathways against account enumeration attacks.
	e. Limit failed login attempts without causing denial of service.
	f. Use secure, server-side session management with random session IDs and proper invalidation.
	
List of vulns:
	a. Brute force attacks: If a web application uses usernames and passwords, an attacker can try to launch brute force attacks that allow them to guess the username and passwords using multiple authentication attempts. 
	b. Use of weak credentials: Web applications should set strong password policies. If applications allow users to set passwords such as "password1" or common passwords, an attacker can easily guess them and access user accounts.
	c. Weak Session Cookies: Session cookies are how the server keeps track of users. If session cookies contain predictable values, attackers can set their own session cookies and access users' accounts. 
	
# Software and Data Integrity Failures
This vulnerability occurs when software or data is used without integrity checks, allowing attackers to modify data or software, causing unexpected consequences. There are two main types:
	a) Software Integrity Failures
		
		Example: Including jQuery from an external server without verification:
			<script src="https://code.jquery.com/jquery-3.6.1.min.js"></script>
		- 
		- Risk: If the jQuery repository is hacked, malicious code could be injected into the file, affecting users visiting your site.
		- Solution: Use Subresource Integrity (SRI) to include an integrity hash, ensuring the file has not been tampered with:
		
		- The correct way to insert the library in your HTML code would be to use SRI and include an integrity hash so that if somehow an attacker is able to modify the library, any client navigating through your website won't execute the modified version.
			<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>
		
	b) Data Integrity Failures
		- Example: A webmail app might assign a cookie with a username. If an attacker modifies the cookie, they could impersonate another user.	
		- Solution: Use JSON Web Tokens (JWTs). JWTs contain a header, payload, and a signature that ensures data integrity. If the payload is tampered with, the signature won't match, preventing unauthorized changes:
			§ Header: Contains metadata and algorithm info.
			§ Payload: Contains the data.
			§ Signature: Verifies the payload's integrity using a secret key.
In both cases, integrity checks like SRI and JWTs help prevent unauthorized modifications and maintain security.

Impact:
	a) Unauthorized Modification: Attackers can alter data or code, compromising system integrity.
	b) Data Exposure: Sensitive information may be accessed or tampered with.
	c) System Compromise: Malicious code introduced via insecure pipelines can compromise the entire system
	
Prevention:
	a. Digital Signatures: Verify software/data from expected sources using digital signatures.
	b. Trusted Repositories: Use trusted repositories for libraries and dependencies.
	c. Code Review: Minimize malicious code by reviewing changes.
	d. CI/CD Security: Ensure proper segregation, configuration, and access control in pipelines.
	e. Integrity Checks: Don’t send unsigned or unencrypted serialized data to untrusted clients
	
List of vulns:
	a. Compromised Pre-installed Software

# Security Logging & Monitoring Failures

Security logging and monitoring failures occur when an application cannot effectively log security events and monitor those logs, which leads to delayed detection of security incidents, making it easier for attackers to remain undetected.
	- The information stored in logs should include the following:
		i) HTTP status codes
		ii) Time Stamps
		iii) Usernames
		iv) API endpoints/page locations
		v) IP addresses

Logs should be stored securely and should have multiple copies at different locations.

	- Common examples of suspicious activity include:
		i) Multiple unauthorised attempts for a particular action (usually authentication attempts or access to unauthorised resources, e.g. admin pages)
		ii) Requests from unusual IP addresses or locations: while this can indicate that someone else is trying to access a particular user's account, it can also have a false positive rate.
		iii) Use of automated tools: particular automated tooling can be easily identifiable, e.g. using the value of User-Agent headers or the speed of requests. This can indicate that an attacker is using automated tooling.
		iv) Common payloads: in web applications, it's common for attackers to use known payloads. Detecting the use of these payloads can indicate the presence of someone conducting unauthorised/malicious testing on applications.

Impact:
	a) Breaches may remain undetected, allowing attackers to exploit vulnerabilities.
	b) Delayed response increases the risk of data compromise and system damage.
	c) Log login failures, access control issues, and input validation failures.
	
Prevention:
	a. Use log formats compatible with log management solutions.
	b. Encode log data correctly to prevent attacks.
	c. Establish an audit trail for critical transactions.
	d. Set up effective monitoring and alerting mechanisms.
	e. Have an incident response plan in place.
	
List of vulns:
	a. Insufficient logging: Failing to log relevant security events.
	b. Unclear log messages: Logs lacking context or meaningful information.
	c. Lack of monitoring: Inadequate surveillance of logs for suspicious activity.
	d. Ineffective response processes: Delays in detecting and responding to incidents.
	e. Improper output neutralization for logs: Vulnerabilities related to log data.
	f. Omission of security-relevant information: Missing critical details in logs.
	
# Server-Side Request Forgery (SSRF)

SSRF is an attack where an application is manipulated to interact with internal/external networks or the local machine due to mishandled URLs, allowing attackers to forge requests.
Examples include fetching images from external servers, custom webhooks, or internal requests to other services.

Impact:
	a) Access to sensitive resources (e.g., databases, APIs, internal systems).
	b) Data leakage, unauthorized access, and service disruption.

Prevention:
	a. Case 1 (Allowlist Approach):
		• Identify trusted applications for communication.
		• Consider network segmentation to limit SSRF impact
	b. Case 2 (No Allowlist):
		• Validate user input carefully to prevent malicious URLs.
		• Use URL parsers to extract hostnames and IPs.
		

NOTE: Whitelisting is more secure as it restrict the access to only what is allowed while blacklisting is easy to implement but less effective as attackers may find ways to bypass it.

List of vulns:
	a. Cloud Server Meta-data: Cloud services like AWS provide a REST interface at http://169.254.169.254/, where important configuration and sometimes authentication keys can be extracted.
	b. Database HTTP Interfaces: NoSQL databases (e.g., MongoDB) may have REST interfaces on HTTP ports. If the database is expected to be internal-only, authentication might be disabled, allowing attackers to extract data.
	c. Internal REST Interfaces: Attackers can target internal services that aren’t directly exposed on the internet.
	d. Files: Using file:// URIs, attackers may read files from the server
