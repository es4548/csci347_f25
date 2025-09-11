# CSCI 347 Quiz Banks - Weeks 3-9 (Updated Fall 2025)

**Quiz Format**: 5 True/False + 7 Multiple Choice + 1 Short Answer = 13 points total  
**Time Limit**: 15 minutes  
**Alignment**: Questions match revised assignment content focusing on analysis rather than building

---

## Week 3: PKI & Certificate Analysis

### True/False Questions (15 total - Canvas will select 5)

1. **T/F**: X.509 certificates contain both public keys and digital signatures.  
   **Answer**: TRUE

2. **T/F**: A certificate's "Not Before" date indicates when the certificate was actually issued by the CA.  
   **Answer**: FALSE (It indicates when the certificate becomes valid, which may be different from issuance)

3. **T/F**: In a certificate chain, each certificate is signed by the private key of the certificate above it in the chain.  
   **Answer**: TRUE

4. **T/F**: Self-signed certificates are always less secure than CA-signed certificates.  
   **Answer**: FALSE (Security depends on how the public key is distributed and verified)

5. **T/F**: Certificate revocation lists (CRLs) must be checked every time a certificate is validated.  
   **Answer**: FALSE (CRL checking is optional in many implementations, though recommended)

6. **T/F**: The Subject Alternative Name (SAN) extension allows one certificate to be valid for multiple domain names.  
   **Answer**: TRUE

7. **T/F**: Certificate fingerprints are calculated using the certificate's private key.  
   **Answer**: FALSE (Fingerprints are hash values of the certificate's public data)

8. **T/F**: A certificate with "Digital Signature" key usage can be used for both authentication and encryption.  
   **Answer**: FALSE (Digital Signature usage is for signing/authentication only)

9. **T/F**: Certificate transparency logs help detect fraudulent certificates issued by compromised CAs.  
   **Answer**: TRUE

10. **T/F**: The certificate chain validation process stops when it reaches any trusted root CA certificate.  
    **Answer**: TRUE

11. **T/F**: Wildcard certificates (*.example.com) can secure unlimited subdomains of example.com.  
    **Answer**: FALSE (They only secure first-level subdomains, not nested subdomains)

12. **T/F**: Certificate pinning prevents man-in-the-middle attacks even when the attacker has a valid certificate.  
    **Answer**: TRUE

13. **T/F**: The Common Name (CN) field in a certificate is always required for SSL/TLS validation.  
    **Answer**: FALSE (SAN extension can be used instead of CN)

14. **T/F**: Certificate validation failures always indicate a security attack.  
    **Answer**: FALSE (Can be due to expired certificates, clock skew, or configuration issues)

15. **T/F**: OCSP (Online Certificate Status Protocol) provides more timely revocation information than CRLs.  
    **Answer**: TRUE

### Multiple Choice Questions (15 total - Canvas will select 7)

1. **MC**: Which field in an X.509 certificate identifies who the certificate was issued to?
   a) Issuer  
   b) Subject  
   c) Authority Key Identifier  
   d) Serial Number  
   **Answer**: b) Subject

2. **MC**: What is the primary purpose of the certificate chain validation process?
   a) To verify the certificate has not expired  
   b) To establish trust from a leaf certificate to a trusted root CA  
   c) To check if the certificate has been revoked  
   d) To verify the certificate's cryptographic algorithms  
   **Answer**: b) To establish trust from a leaf certificate to a trusted root CA

3. **MC**: In certificate validation, what does it mean when a certificate is "self-signed"?
   a) The certificate was signed by the subject's private key  
   b) The certificate issuer and subject are the same entity  
   c) The certificate does not require validation  
   d) The certificate was generated automatically  
   **Answer**: b) The certificate issuer and subject are the same entity

4. **MC**: Which certificate extension is most important for web server certificates?
   a) Basic Constraints  
   b) Key Usage  
   c) Subject Alternative Name (SAN)  
   d) Authority Information Access  
   **Answer**: c) Subject Alternative Name (SAN)

5. **MC**: What happens when a certificate validation fails due to an untrusted root CA?
   a) The connection is automatically secured with a different certificate  
   b) The application should reject the connection  
   c) The certificate is automatically added to the trust store  
   d) The validation process continues with weaker security  
   **Answer**: b) The application should reject the connection

6. **MC**: Which of the following is NOT typically included in a certificate fingerprint calculation?
   a) Subject name  
   b) Public key  
   c) Private key  
   d) Signature algorithm  
   **Answer**: c) Private key

7. **MC**: What is the main security risk of accepting expired certificates?
   a) The certificate may have been revoked  
   b) The private key may have been compromised  
   c) The cryptographic algorithms may be outdated  
   d) All of the above  
   **Answer**: d) All of the above

8. **MC**: In Python's cryptography library, which method is used to load a PEM-formatted certificate?
   a) x509.load_pem_certificate()  
   b) x509.parse_certificate()  
   c) x509.read_pem_certificate()  
   d) x509.decode_certificate()  
   **Answer**: a) x509.load_pem_certificate()

9. **MC**: What is the primary advantage of OCSP over Certificate Revocation Lists (CRLs)?
   a) OCSP uses stronger cryptography  
   b) OCSP provides real-time revocation status  
   c) OCSP is more widely supported  
   d) OCSP certificates never expire  
   **Answer**: b) OCSP provides real-time revocation status

10. **MC**: Which key usage indicates that a certificate can be used for SSL/TLS server authentication?
    a) Digital Signature only  
    b) Key Encipherment only  
    c) Both Digital Signature and Key Encipherment  
    d) Certificate Signing  
    **Answer**: c) Both Digital Signature and Key Encipherment

11. **MC**: What is the most likely cause of a hostname verification failure?
    a) The certificate has expired  
    b) The certificate was revoked  
    c) The server name doesn't match the certificate's subject or SAN  
    d) The certificate uses weak cryptography  
    **Answer**: c) The server name doesn't match the certificate's subject or SAN

12. **MC**: In a certificate chain, intermediate certificates:
    a) Are optional and only used for backward compatibility  
    b) Must be included in the certificate validation process  
    c) Are automatically downloaded by all clients  
    d) Cannot be revoked  
    **Answer**: b) Must be included in the certificate validation process

13. **MC**: Which of the following certificate validation errors is most likely to indicate a security attack?
    a) Certificate expired yesterday  
    b) Unknown certificate authority  
    c) Certificate issued for wrong hostname  
    d) Certificate chain incomplete  
    **Answer**: c) Certificate issued for wrong hostname

14. **MC**: What is the purpose of certificate transparency logs?
    a) To store private keys securely  
    b) To publicly record all issued certificates  
    c) To automatically revoke compromised certificates  
    d) To encrypt certificate data  
    **Answer**: b) To publicly record all issued certificates

15. **MC**: When analyzing a certificate, what does a "Basic Constraints" extension of "CA:TRUE" indicate?
    a) The certificate is self-signed  
    b) The certificate can be used to sign other certificates  
    c) The certificate is a root certificate  
    d) The certificate uses basic encryption only  
    **Answer**: b) The certificate can be used to sign other certificates

### Short Answer Questions (5 total - Canvas will select 1)

1. **SA**: Explain how certificate pinning helps prevent man-in-the-middle attacks, and describe one potential drawback of implementing certificate pinning.  
   **Answer**: Certificate pinning associates a specific certificate or public key with a host, so connections are only accepted if the presented certificate matches the pinned one. This prevents attacks even with valid certificates from other CAs. One drawback is that pinning can cause service outages if certificates are updated without updating the pinned values.

2. **SA**: Why might a security analyst prefer OCSP over CRL for checking certificate revocation status, and what is one limitation of OCSP?  
   **Answer**: OCSP provides real-time revocation status instead of potentially outdated CRL information, and responses are smaller/more efficient. One limitation is that OCSP requires an active network connection to the CA's OCSP responder, creating a dependency and potential privacy concern.

3. **SA**: Describe the difference between a certificate's "Subject" and "Issuer" fields, and explain why this distinction is important for certificate validation.  
   **Answer**: The Subject identifies who/what the certificate was issued to, while the Issuer identifies the CA that signed the certificate. This distinction is crucial because validation requires verifying that the Issuer's signature is valid and that there's a trust chain from the Subject certificate to a trusted root CA.

4. **SA**: Explain why the Subject Alternative Name (SAN) extension is often more important than the Common Name (CN) field for modern web certificates.  
   **Answer**: SAN allows one certificate to be valid for multiple domain names and is the preferred method for hostname verification in modern browsers. Many browsers now ignore the CN field entirely and only check SAN, making SAN essential for multi-domain or wildcard certificates.

5. **SA**: What information can an attacker potentially gather from certificate transparency logs, and why do security experts still consider CT logs beneficial despite this potential information disclosure?  
   **Answer**: Attackers can see all domains/subdomains an organization uses, potentially revealing infrastructure details. However, CT logs are beneficial because they enable detection of fraudulent certificates issued by compromised CAs, and the infrastructure information was likely discoverable through other means anyway.

---

## Week 4: Multi-Factor Authentication Analysis

### True/False Questions (15 total - Canvas will select 5)

1. **T/F**: Multi-factor authentication requires at least two different types of authentication factors.  
   **Answer**: TRUE

2. **T/F**: SMS-based two-factor authentication is more secure than TOTP-based authentication.  
   **Answer**: FALSE (SMS is vulnerable to SIM swapping and interception)

3. **T/F**: TOTP (Time-based One-Time Password) codes are generated using a shared secret and current time.  
   **Answer**: TRUE

4. **T/F**: Backup codes should be stored in plaintext in the database for quick verification.  
   **Answer**: FALSE (They should be hashed like passwords)

5. **T/F**: The "something you know" factor includes passwords and PINs.  
   **Answer**: TRUE

6. **T/F**: Biometric authentication is considered a "something you have" factor.  
   **Answer**: FALSE (It's "something you are")

7. **T/F**: HOTP (HMAC-based One-Time Password) uses a counter value instead of time.  
   **Answer**: TRUE

8. **T/F**: MFA completely eliminates the risk of account compromise.  
   **Answer**: FALSE (It reduces risk but doesn't eliminate it entirely)

9. **T/F**: The TOTP algorithm typically uses a 30-second time window for code generation.  
   **Answer**: TRUE

10. **T/F**: Hardware tokens are always more secure than software-based authenticators.  
    **Answer**: FALSE (Security depends on implementation and threat model)

11. **T/F**: Push notifications for authentication approval are immune to phishing attacks.  
    **Answer**: FALSE (Users can approve malicious requests if deceived)

12. **T/F**: bcrypt is appropriate for hashing passwords due to its computational cost.  
    **Answer**: TRUE

13. **T/F**: The shared secret for TOTP must be different for each user but the same across all their devices.  
    **Answer**: TRUE

14. **T/F**: MFA bypass codes should never expire to ensure account recovery is always possible.  
    **Answer**: FALSE (They should have expiration dates for security)

15. **T/F**: QR codes used for authenticator setup contain the shared secret in plaintext form.  
    **Answer**: TRUE (The secret is base32 encoded but not encrypted in the QR code)

### Multiple Choice Questions (15 total - Canvas will select 7)

1. **MC**: Which three categories represent the classic authentication factors?
   a) Username, password, and email  
   b) Something you know, something you have, something you are  
   c) Password, token, and certificate  
   d) Local, remote, and biometric  
   **Answer**: b) Something you know, something you have, something you are

2. **MC**: What is the primary vulnerability of SMS-based two-factor authentication?
   a) Users forget their phone numbers  
   b) SMS messages can be intercepted or SIM cards can be swapped  
   c) SMS codes expire too quickly  
   d) SMS requires internet connectivity  
   **Answer**: b) SMS messages can be intercepted or SIM cards can be swapped

3. **MC**: In TOTP implementation, what happens if the server and client clocks are slightly out of sync?
   a) Authentication always fails  
   b) The system automatically syncs the clocks  
   c) The server typically accepts codes from adjacent time windows  
   d) Users must manually adjust their device time  
   **Answer**: c) The server typically accepts codes from adjacent time windows

4. **MC**: Which Python library is commonly used for implementing TOTP functionality?
   a) hashlib  
   b) pyotp  
   c) bcrypt  
   d) cryptography  
   **Answer**: b) pyotp

5. **MC**: What is the main advantage of TOTP over HOTP for authentication systems?
   a) TOTP codes are longer  
   b) TOTP doesn't require server-side counter synchronization  
   c) TOTP is more widely supported  
   d) TOTP uses stronger cryptography  
   **Answer**: b) TOTP doesn't require server-side counter synchronization

6. **MC**: How should backup codes be stored in a secure authentication system?
   a) In plaintext for quick verification  
   b) Encrypted with a user's password  
   c) Hashed using a secure hash function  
   d) Not stored, generated on demand  
   **Answer**: c) Hashed using a secure hash function

7. **MC**: What makes bcrypt suitable for password hashing in MFA systems?
   a) It's the fastest available hash function  
   b) It includes built-in salting and configurable work factor  
   c) It produces the shortest hash values  
   d) It's required by authentication standards  
   **Answer**: b) It includes built-in salting and configurable work factor

8. **MC**: Which factor is considered strongest against remote attacks?
   a) Passwords  
   b) Security questions  
   c) Hardware tokens  
   d) SMS codes  
   **Answer**: c) Hardware tokens

9. **MC**: What information is typically encoded in a TOTP setup QR code?
   a) The user's hashed password  
   b) The service name, user account, and shared secret  
   c) The user's biometric data  
   d) The server's public key  
   **Answer**: b) The service name, user account, and shared secret

10. **MC**: In a proper MFA implementation, what should happen if a user enters an incorrect TOTP code multiple times?
    a) The account should be permanently locked  
    b) The system should implement rate limiting or temporary lockouts  
    c) The shared secret should be regenerated  
    d) All active sessions should be terminated  
    **Answer**: b) The system should implement rate limiting or temporary lockouts

11. **MC**: Which attack vector does MFA primarily defend against?
    a) Physical device theft  
    b) Password-only compromises  
    c) Social engineering  
    d) Man-in-the-middle attacks  
    **Answer**: b) Password-only compromises

12. **MC**: What is the typical lifespan of a TOTP code?
    a) 10 seconds  
    b) 30 seconds  
    c) 60 seconds  
    d) 5 minutes  
    **Answer**: b) 30 seconds

13. **MC**: Which of the following represents the weakest form of two-factor authentication?
    a) Hardware security keys  
    b) Authenticator app codes  
    c) SMS text messages  
    d) Push notifications  
    **Answer**: c) SMS text messages

14. **MC**: In Python's pyotp library, which method would you use to verify a TOTP code?
    a) verify_token()  
    b) check_code()  
    c) validate_totp()  
    d) verify()  
    **Answer**: a) verify_token()

15. **MC**: What should be the minimum requirements for backup codes in a secure MFA system?
    a) At least 3 codes, 6 digits each  
    b) At least 10 codes, 8+ characters each with random generation  
    c) At least 5 codes, user-defined  
    d) At least 20 codes, 4 digits each  
    **Answer**: b) At least 10 codes, 8+ characters each with random generation

### Short Answer Questions (5 total - Canvas will select 1)

1. **SA**: Explain why TOTP-based authentication is more secure than SMS-based authentication, and describe one potential weakness of TOTP systems.  
   **Answer**: TOTP is more secure because codes are generated locally on the user's device using a shared secret, eliminating risks of SMS interception and SIM swapping attacks. One weakness is that TOTP codes can be stolen if malware compromises the device generating them, or if users are tricked into entering codes on phishing sites.

2. **SA**: Describe the role of backup codes in MFA systems and explain why they should be hashed rather than stored in plaintext.  
   **Answer**: Backup codes provide account recovery when primary MFA methods are unavailable (lost device, etc.). They should be hashed because plaintext storage would allow anyone with database access to bypass MFA entirely, while hashing ensures codes can be verified without exposing their values.

3. **SA**: What are the three classic authentication factors, and why does combining multiple factors improve security compared to using just one?  
   **Answer**: The three factors are something you know (passwords), something you have (tokens/devices), and something you are (biometrics). Combining factors improves security because an attacker must compromise multiple different types of credentials, making attacks significantly more difficult and less likely to succeed.

4. **SA**: Explain how clock synchronization affects TOTP authentication and describe how systems typically handle minor time differences.  
   **Answer**: TOTP codes are generated based on current time, so significant clock differences between client and server cause authentication failures. Systems handle this by accepting codes from adjacent time windows (typically ±1 window) and sometimes implementing clock skew detection to accommodate minor differences.

5. **SA**: Why is bcrypt preferred over simple hash functions like SHA-256 for password hashing in authentication systems?  
   **Answer**: bcrypt includes automatic salt generation and configurable computational cost (work factor), making it resistant to rainbow table attacks and allowing the difficulty to be increased over time as hardware improves. Simple hash functions are too fast, enabling efficient brute force attacks.

---

## Week 5: Access Control Systems (RBAC)

### True/False Questions (15 total - Canvas will select 5)

1. **T/F**: Role-Based Access Control (RBAC) assigns permissions directly to users rather than to roles.  
   **Answer**: FALSE (RBAC assigns permissions to roles, then assigns roles to users)

2. **T/F**: In RBAC, a user can have multiple roles simultaneously.  
   **Answer**: TRUE

3. **T/F**: The principle of least privilege means users should have the minimum permissions necessary to perform their job functions.  
   **Answer**: TRUE

4. **T/F**: Role hierarchies in RBAC allow senior roles to inherit permissions from junior roles.  
   **Answer**: TRUE

5. **T/F**: Discretionary Access Control (DAC) allows resource owners to set permissions for their own resources.  
   **Answer**: TRUE

6. **T/F**: Mandatory Access Control (MAC) is more flexible than RBAC for most business applications.  
   **Answer**: FALSE (MAC is more rigid; RBAC is more flexible for business needs)

7. **T/F**: In RBAC, permissions define what actions can be performed on specific resources.  
   **Answer**: TRUE

8. **T/F**: Role explosion occurs when an organization creates too many specific roles, making management difficult.  
   **Answer**: TRUE

9. **T/F**: Access control decisions should always be logged for audit purposes.  
   **Answer**: TRUE

10. **T/F**: RBAC completely eliminates the need for user-specific permissions in all scenarios.  
    **Answer**: FALSE (Some scenarios may require user-specific exceptions)

11. **T/F**: The principle of separation of duties can be enforced through mutually exclusive roles in RBAC.  
    **Answer**: TRUE

12. **T/F**: Dynamic access control can change permissions based on contextual factors like time or location.  
    **Answer**: TRUE

13. **T/F**: In RBAC, revoking a role from a user immediately removes all associated permissions.  
    **Answer**: TRUE

14. **T/F**: Access control matrices become unmanageable in large organizations without role-based abstractions.  
    **Answer**: TRUE

15. **T/F**: RBAC models require users to activate all their assigned roles simultaneously.  
    **Answer**: FALSE (Users can activate subsets of their roles as needed)

### Multiple Choice Questions (15 total - Canvas will select 7)

1. **MC**: What are the core components of RBAC?
   a) Users, passwords, and resources  
   b) Users, roles, permissions, and resources  
   c) Authentication, authorization, and accounting  
   d) Subjects, objects, and access rights  
   **Answer**: b) Users, roles, permissions, and resources

2. **MC**: Which access control model is most appropriate for organizations with well-defined job functions and hierarchies?
   a) Discretionary Access Control (DAC)  
   b) Mandatory Access Control (MAC)  
   c) Role-Based Access Control (RBAC)  
   d) Attribute-Based Access Control (ABAC)  
   **Answer**: c) Role-Based Access Control (RBAC)

3. **MC**: What is the primary advantage of RBAC over traditional user-permission assignments?
   a) Better performance  
   b) Simplified administration and reduced complexity  
   c) Stronger cryptographic protection  
   d) Automatic backup capabilities  
   **Answer**: b) Simplified administration and reduced complexity

4. **MC**: In RBAC role hierarchies, what does inheritance mean?
   a) Child roles automatically include permissions of parent roles  
   b) Parent roles inherit permissions from child roles  
   c) Roles are automatically assigned based on user attributes  
   d) Permissions are inherited from the system administrator  
   **Answer**: a) Child roles automatically include permissions of parent roles

5. **MC**: What is "role explosion" in RBAC systems?
   a) When too many users are assigned to a single role  
   b) When roles are created too specifically, leading to management overhead  
   c) When role hierarchies become circular  
   d) When roles are deleted accidentally  
   **Answer**: b) When roles are created too specifically, leading to management overhead

6. **MC**: Which principle helps prevent conflicts of interest in RBAC implementations?
   a) Principle of least privilege  
   b) Separation of duties  
   c) Role hierarchy  
   d) Dynamic role assignment  
   **Answer**: b) Separation of duties

7. **MC**: What should happen when an employee changes departments in a well-designed RBAC system?
   a) Create a new user account  
   b) Modify all individual permissions manually  
   c) Change role assignments to reflect new job functions  
   d) Reset all access permissions to default  
   **Answer**: c) Change role assignments to reflect new job functions

8. **MC**: In the context of RBAC implementation, what is a permission?
   a) A user's authentication credentials  
   b) A role assigned to a user  
   c) An action that can be performed on a specific resource  
   d) A security policy document  
   **Answer**: c) An action that can be performed on a specific resource

9. **MC**: What type of access control allows resource owners to set permissions?
   a) Role-Based Access Control (RBAC)  
   b) Mandatory Access Control (MAC)  
   c) Discretionary Access Control (DAC)  
   d) Attribute-Based Access Control (ABAC)  
   **Answer**: c) Discretionary Access Control (DAC)

10. **MC**: Which RBAC feature helps manage temporary access requirements?
    a) Static role assignment  
    b) Role activation/deactivation  
    c) Permission inheritance  
    d) Access control matrices  
    **Answer**: b) Role activation/deactivation

11. **MC**: What is the difference between permissions and privileges in access control?
    a) There is no difference; they are synonymous  
    b) Permissions are granted to users; privileges are granted to roles  
    c) Permissions define what can be done; privileges define the level of access  
    d) Permissions are technical; privileges are administrative  
    **Answer**: a) There is no difference; they are synonymous

12. **MC**: In RBAC audit logging, what information is most critical to record?
    a) User passwords and authentication tokens  
    b) User identity, requested action, resource, and decision (allow/deny)  
    c) System performance metrics  
    d) Network traffic patterns  
    **Answer**: b) User identity, requested action, resource, and decision (allow/deny)

13. **MC**: What is a key challenge when implementing RBAC in large organizations?
    a) Technical complexity of role assignment  
    b) Defining appropriate roles that match business functions  
    c) Performance impact of access control checks  
    d) Integration with existing authentication systems  
    **Answer**: b) Defining appropriate roles that match business functions

14. **MC**: Which access control approach provides the most granular control over permissions?
    a) RBAC with role hierarchies  
    b) Traditional user-permission assignments  
    c) Attribute-Based Access Control (ABAC)  
    d) Mandatory Access Control (MAC)  
    **Answer**: c) Attribute-Based Access Control (ABAC)

15. **MC**: What happens to access permissions when a role is deleted in a properly implemented RBAC system?
    a) Permissions are automatically reassigned to all users  
    b) All users lose access to all resources  
    c) Users with that role lose associated permissions until reassigned  
    d) The system continues working without any changes  
    **Answer**: c) Users with that role lose associated permissions until reassigned

### Short Answer Questions (5 total - Canvas will select 1)

1. **SA**: Explain how RBAC simplifies access control administration compared to directly assigning permissions to individual users, and describe one potential drawback of RBAC.  
   **Answer**: RBAC simplifies administration by grouping permissions into roles that match job functions, so administrators manage role-user assignments rather than individual user-permission mappings. This reduces complexity especially when employees change positions. One drawback is that RBAC may be too rigid for dynamic access needs or special cases requiring user-specific permissions.

2. **SA**: Describe the principle of least privilege and explain how it should be applied when designing roles in an RBAC system.  
   **Answer**: The principle of least privilege means giving users only the minimum access needed to perform their job duties. In RBAC design, this means creating roles with just the essential permissions for specific job functions, avoiding overprivileged "super-user" roles, and regularly reviewing role permissions to remove unnecessary access.

3. **SA**: What is separation of duties and how can it be enforced in RBAC through mutually exclusive roles?  
   **Answer**: Separation of duties prevents any single person from completing sensitive processes alone, reducing fraud and error risks. In RBAC, this is enforced by creating mutually exclusive roles where users cannot be assigned conflicting roles simultaneously, such as preventing the same person from having both "Purchase Approver" and "Purchase Requestor" roles.

4. **SA**: Explain the concept of role hierarchies in RBAC and provide an example of how inheritance works in practice.  
   **Answer**: Role hierarchies create parent-child relationships where child roles automatically inherit all permissions of their parent roles. For example, a "Manager" role might inherit all permissions of an "Employee" role plus additional management permissions, so users assigned the Manager role get both sets of permissions automatically.

5. **SA**: Why is audit logging essential in access control systems, and what key information should be logged for RBAC decisions?  
   **Answer**: Audit logging provides accountability, helps detect security breaches, and supports compliance requirements by creating a record of access attempts. Key information includes user identity, timestamp, requested resource/action, roles involved, and the access decision (allow/deny) with justification for forensic analysis.

---

## Week 6: Network Security Infrastructure Analysis

### True/False Questions (15 total - Canvas will select 5)

1. **T/F**: Firewalls operating at the network layer can inspect packet headers but not payload content.  
   **Answer**: TRUE

2. **T/F**: A DMZ (Demilitarized Zone) provides an isolated network segment for public-facing services.  
   **Answer**: TRUE

3. **T/F**: Network Address Translation (NAT) provides security benefits by hiding internal network structure.  
   **Answer**: TRUE

4. **T/F**: VPNs always provide both confidentiality and integrity protection for network traffic.  
   **Answer**: FALSE (Depends on the VPN protocol and configuration)

5. **T/F**: Intrusion Detection Systems (IDS) can automatically block malicious network traffic.  
   **Answer**: FALSE (IDS detects and alerts; IPS blocks traffic)

6. **T/F**: Network segmentation helps contain security breaches by limiting lateral movement.  
   **Answer**: TRUE

7. **T/F**: SSL/TLS VPNs operate at the application layer while IPSec VPNs operate at the network layer.  
   **Answer**: TRUE

8. **T/F**: Stateful firewalls maintain connection state information to make more intelligent filtering decisions.  
   **Answer**: TRUE

9. **T/F**: Network monitoring should focus only on traffic crossing network perimeter boundaries.  
   **Answer**: FALSE (Internal traffic monitoring is also important)

10. **T/F**: Zero Trust Network Access (ZTNA) assumes that network location indicates trustworthiness.  
    **Answer**: FALSE (Zero Trust assumes no inherent trust based on location)

11. **T/F**: pfSense is a commercial firewall solution that requires expensive licensing.  
    **Answer**: FALSE (pfSense Community Edition is free and open source)

12. **T/F**: Network access control can integrate with identity systems to make authorization decisions.  
    **Answer**: TRUE

13. **T/F**: Wireshark can decrypt encrypted network traffic without access to cryptographic keys.  
    **Answer**: FALSE (Wireshark requires keys to decrypt encrypted traffic)

14. **T/F**: VLAN segmentation provides both performance and security benefits in network design.  
    **Answer**: TRUE

15. **T/F**: Network behavioral analysis can detect threats that signature-based systems might miss.  
    **Answer**: TRUE

### Multiple Choice Questions (15 total - Canvas will select 7)

1. **MC**: What is the primary purpose of a DMZ in network security architecture?
   a) To increase network performance  
   b) To provide isolated hosting for public-facing services  
   c) To store backup data securely  
   d) To manage user authentication  
   **Answer**: b) To provide isolated hosting for public-facing services

2. **MC**: Which firewall type provides the highest level of security inspection?
   a) Packet filtering firewall  
   b) Stateful firewall  
   c) Application layer firewall  
   d) Network address translation firewall  
   **Answer**: c) Application layer firewall

3. **MC**: What is the main difference between an IDS and an IPS?
   a) IDS works faster than IPS  
   b) IDS monitors network traffic; IPS actively blocks threats  
   c) IDS is hardware-based; IPS is software-based  
   d) IDS is more expensive than IPS  
   **Answer**: b) IDS monitors network traffic; IPS actively blocks threats

4. **MC**: In network segmentation, what is the purpose of VLANs?
   a) To increase bandwidth capacity  
   b) To logically separate network traffic and improve security  
   c) To provide wireless connectivity  
   d) To manage IP address assignments  
   **Answer**: b) To logically separate network traffic and improve security

5. **MC**: Which VPN protocol provides the strongest security for remote access?
   a) PPTP  
   b) L2TP  
   c) IPSec with IKEv2  
   d) SSL/TLS  
   **Answer**: c) IPSec with IKEv2

6. **MC**: What is the primary advantage of certificate-based VPN authentication over password-based authentication?
   a) Faster connection establishment  
   b) Lower computational overhead  
   c) Resistance to brute force attacks and stronger identity verification  
   d) Better compatibility with mobile devices  
   **Answer**: c) Resistance to brute force attacks and stronger identity verification

7. **MC**: In Zero Trust Network Access, what principle guides access control decisions?
   a) Trust but verify  
   b) Never trust, always verify  
   c) Trust based on network location  
   d) Default allow with explicit deny  
   **Answer**: b) Never trust, always verify

8. **MC**: What type of network monitoring is most effective for detecting insider threats?
   a) Perimeter monitoring only  
   b) External traffic analysis  
   c) East-west (lateral) traffic monitoring  
   d) DNS query monitoring  
   **Answer**: c) East-west (lateral) traffic monitoring

9. **MC**: Which network security approach integrates identity management with network access control?
   a) Traditional firewall rules  
   b) Static network segmentation  
   c) Identity-aware networking  
   d) Perimeter-based security  
   **Answer**: c) Identity-aware networking

10. **MC**: What is the main security benefit of network address translation (NAT)?
    a) Improved network performance  
    b) Hiding internal network topology from external attackers  
    c) Automatic traffic encryption  
    d) Built-in intrusion detection  
    **Answer**: b) Hiding internal network topology from external attackers

11. **MC**: In network behavioral analysis, what indicates a potential security threat?
    a) High bandwidth utilization during business hours  
    b) Regular backup traffic patterns  
    c) Unusual communication patterns or traffic anomalies  
    d) Standard protocol usage  
    **Answer**: c) Unusual communication patterns or traffic anomalies

12. **MC**: What is the primary purpose of network access control (NAC) systems?
    a) To increase network speed  
    b) To verify device compliance and identity before granting network access  
    c) To manage IP address assignments  
    d) To provide wireless connectivity  
    **Answer**: b) To verify device compliance and identity before granting network access

13. **MC**: Which tool is most appropriate for detailed network packet analysis?
    a) pfSense  
    b) Wireshark  
    c) Nmap  
    d) Splunk  
    **Answer**: b) Wireshark

14. **MC**: What is the main advantage of role-based network segmentation?
    a) Reduced hardware costs  
    b) Network access permissions align with organizational roles and responsibilities  
    c) Faster network performance  
    d) Simplified cable management  
    **Answer**: b) Network access permissions align with organizational roles and responsibilities

15. **MC**: In enterprise network security, what is the most effective approach for monitoring network traffic?
    a) Monitoring only inbound traffic  
    b) Monitoring only outbound traffic  
    c) Comprehensive monitoring of both north-south and east-west traffic  
    d) Monitoring only wireless traffic  
    **Answer**: c) Comprehensive monitoring of both north-south and east-west traffic

### Short Answer Questions (5 total - Canvas will select 1)

1. **SA**: Explain the concept of Zero Trust Network Access (ZTNA) and describe how it differs from traditional perimeter-based security approaches.  
   **Answer**: ZTNA assumes no inherent trust based on network location and requires verification of every user and device before granting access to resources. Unlike traditional perimeter security that trusts internal traffic once inside the network, ZTNA continuously validates identity and device compliance, providing granular access control regardless of user location.

2. **SA**: Describe the security benefits of network segmentation and explain how VLANs can be used to implement role-based network access control.  
   **Answer**: Network segmentation limits attack spread by isolating different network zones, preventing lateral movement during breaches. VLANs can implement role-based access by assigning users to different virtual networks based on their organizational roles, ensuring employees only access resources necessary for their job functions while maintaining network isolation between departments.

3. **SA**: What is the difference between an Intrusion Detection System (IDS) and an Intrusion Prevention System (IPS), and why might an organization choose to deploy both?  
   **Answer**: IDS passively monitors and alerts on suspicious network activity, while IPS actively blocks detected threats in real-time. Organizations deploy both because IDS provides comprehensive logging and forensic analysis capabilities without impacting network performance, while IPS provides active protection, creating layered defense with both detection and prevention capabilities.

4. **SA**: Explain how certificate-based VPN authentication enhances security compared to password-based authentication, and describe one potential operational challenge.  
   **Answer**: Certificate-based authentication is immune to password attacks, provides strong identity verification through cryptographic proof, and enables non-repudiation. One operational challenge is certificate lifecycle management, including secure distribution, renewal before expiration, and revocation procedures when employees leave or certificates are compromised.

5. **SA**: Describe the concept of identity-aware networking and explain how it integrates network security with access control systems from previous weeks.  
   **Answer**: Identity-aware networking makes access control decisions based on verified user identity rather than just network location or device characteristics. It integrates with authentication systems (Week 4 MFA) and access control (Week 5 RBAC) by incorporating identity verification and role-based policies into network infrastructure, enabling dynamic firewall rules and network segmentation based on user authentication status and assigned roles.

---

## Week 7: Security Monitoring and SIEM Analysis

### True/False Questions (15 total - Canvas will select 5)

1. **T/F**: SIEM systems collect, correlate, and analyze security events from multiple sources across the enterprise.  
   **Answer**: TRUE

2. **T/F**: Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) serve identical functions.  
   **Answer**: FALSE (SIEM focuses on monitoring and analysis; SOAR focuses on automation and response)

3. **T/F**: Log normalization converts different log formats into a common schema for analysis.  
   **Answer**: TRUE

4. **T/F**: The ELK Stack consists of Elasticsearch, Logstash, and Kibana components.  
   **Answer**: TRUE

5. **T/F**: Security monitoring should only focus on external threats and perimeter security events.  
   **Answer**: FALSE (Internal threats and lateral movement are equally important)

6. **T/F**: Behavioral analytics can detect threats that signature-based detection systems might miss.  
   **Answer**: TRUE

7. **T/F**: Splunk is a proprietary SIEM solution while the ELK Stack is completely open source.  
   **Answer**: TRUE

8. **T/F**: Security dashboards should provide real-time visibility into critical security metrics and indicators.  
   **Answer**: TRUE

9. **T/F**: Threat intelligence feeds provide context about known malicious indicators and attack patterns.  
   **Answer**: TRUE

10. **T/F**: Security event correlation can reduce false positives by combining related events into meaningful incidents.  
    **Answer**: TRUE

11. **T/F**: The MITRE ATT&CK framework provides a comprehensive matrix of adversary tactics and techniques.  
    **Answer**: TRUE

12. **T/F**: Log retention policies are primarily driven by storage costs and have no security implications.  
    **Answer**: FALSE (Legal, compliance, and forensic requirements drive retention policies)

13. **T/F**: Security orchestration can automatically execute response actions based on predefined playbooks.  
    **Answer**: TRUE

14. **T/F**: Security monitoring systems should alert on every detected anomaly to ensure comprehensive coverage.  
    **Answer**: FALSE (This would create alert fatigue; systems should prioritize and filter alerts)

15. **T/F**: Threat hunting is a proactive security practice that looks for undetected threats using hypothesis-driven investigations.  
    **Answer**: TRUE

### Multiple Choice Questions (15 total - Canvas will select 7)

1. **MC**: What is the primary purpose of a SIEM system?
   a) To prevent all security attacks  
   b) To centralize security event collection, correlation, and analysis  
   c) To replace all other security tools  
   d) To provide network connectivity monitoring  
   **Answer**: b) To centralize security event collection, correlation, and analysis

2. **MC**: In the ELK Stack, which component is responsible for log parsing and transformation?
   a) Elasticsearch  
   b) Logstash  
   c) Kibana  
   d) Filebeat  
   **Answer**: b) Logstash

3. **MC**: What is the main difference between security monitoring and threat hunting?
   a) Monitoring uses automated tools; hunting uses manual processes  
   b) Monitoring is reactive to alerts; hunting is proactive searching for threats  
   c) Monitoring is cheaper; hunting is more expensive  
   d) Monitoring focuses on internal threats; hunting focuses on external threats  
   **Answer**: b) Monitoring is reactive to alerts; hunting is proactive searching for threats

4. **MC**: Which type of analysis helps identify unusual patterns in user behavior that might indicate compromised accounts?
   a) Signature-based detection  
   b) Statistical analysis  
   c) User and Entity Behavior Analytics (UEBA)  
   d) Network performance monitoring  
   **Answer**: c) User and Entity Behavior Analytics (UEBA)

5. **MC**: What is the primary advantage of using threat intelligence feeds in SIEM systems?
   a) Reduced log storage requirements  
   b) Context about known malicious indicators and attack attribution  
   c) Improved network performance  
   d) Automatic incident resolution  
   **Answer**: b) Context about known malicious indicators and attack attribution

6. **MC**: In security incident response, what is the correct order of the typical phases?
   a) Containment, Preparation, Detection, Recovery  
   b) Detection, Analysis, Containment, Recovery  
   c) Preparation, Detection, Analysis, Containment, Eradication, Recovery  
   d) Analysis, Detection, Preparation, Recovery  
   **Answer**: c) Preparation, Detection, Analysis, Containment, Eradication, Recovery

7. **MC**: What is the main benefit of security event correlation in SIEM systems?
   a) Faster log processing  
   b) Reduced storage requirements  
   c) Combining related events to identify complex attack patterns  
   d) Improved user interface design  
   **Answer**: c) Combining related events to identify complex attack patterns

8. **MC**: Which security monitoring approach is most effective for detecting advanced persistent threats (APTs)?
   a) Perimeter-based monitoring only  
   b) Signature-based detection systems  
   c) Comprehensive behavioral analysis and threat hunting  
   d) Antivirus software monitoring  
   **Answer**: c) Comprehensive behavioral analysis and threat hunting

9. **MC**: What is the primary purpose of security playbooks in SOAR systems?
   a) To document security policies  
   b) To provide automated response procedures for specific incident types  
   c) To store log data  
   d) To manage user access permissions  
   **Answer**: b) To provide automated response procedures for specific incident types

10. **MC**: In SIEM deployment, what is the most critical factor for ensuring effective threat detection?
    a) Having the fastest hardware  
    b) Using the most expensive software  
    c) Proper tuning and customization of detection rules  
    d) Maximizing the number of log sources  
    **Answer**: c) Proper tuning and customization of detection rules

11. **MC**: What type of security event requires immediate escalation and response?
    a) Failed login attempt  
    b) Scheduled system maintenance  
    c) Successful privilege escalation on a critical server  
    d) Regular backup completion  
    **Answer**: c) Successful privilege escalation on a critical server

12. **MC**: Which metric is most important for measuring SIEM effectiveness?
    a) Number of events processed per second  
    b) Mean time to detect (MTTD) and mean time to respond (MTTR)  
    c) Amount of disk storage used  
    d) Number of dashboards created  
    **Answer**: b) Mean time to detect (MTTD) and mean time to respond (MTTR)

13. **MC**: What is the main advantage of cloud-based SIEM solutions over on-premises deployments?
    a) Better security guarantees  
    b) Lower total cost of ownership  
    c) Scalability and reduced infrastructure management overhead  
    d) Faster alert processing  
    **Answer**: c) Scalability and reduced infrastructure management overhead

14. **MC**: In threat hunting, what is the starting point for most investigations?
    a) Random log sampling  
    b) Hypothesis based on threat intelligence or observed anomalies  
    c) Automated alert generation  
    d) Compliance requirements  
    **Answer**: b) Hypothesis based on threat intelligence or observed anomalies

15. **MC**: Which factor most commonly causes SIEM implementation failures in organizations?
    a) Insufficient hardware resources  
    b) Lack of skilled security analysts and poor process integration  
    c) Incompatible software versions  
    d) Network bandwidth limitations  
    **Answer**: b) Lack of skilled security analysts and poor process integration

### Short Answer Questions (5 total - Canvas will select 1)

1. **SA**: Explain the difference between SIEM and SOAR systems and describe how they complement each other in a comprehensive security operations center.  
   **Answer**: SIEM focuses on collecting, correlating, and analyzing security events to detect threats and provide visibility. SOAR focuses on automating response actions and orchestrating workflows once threats are identified. Together, SIEM provides the detection and analysis capabilities while SOAR provides automated response and case management, creating an efficient security operations workflow.

2. **SA**: Describe the concept of User and Entity Behavior Analytics (UEBA) and explain how it can detect threats that traditional signature-based systems might miss.  
   **Answer**: UEBA establishes baseline behaviors for users, devices, and applications, then identifies deviations that might indicate compromise. It can detect insider threats, compromised accounts acting normally but accessing unusual resources, and advanced attacks that don't trigger signature-based rules, providing detection based on behavioral patterns rather than known attack signatures.

3. **SA**: What is threat hunting and how does it differ from traditional security monitoring? Provide an example of a threat hunting hypothesis.  
   **Answer**: Threat hunting is proactive searching for undetected threats using hypothesis-driven investigations, while traditional monitoring reacts to automated alerts. Hunters analyze data looking for signs of compromise that automated systems missed. Example hypothesis: "Attackers using living-off-the-land techniques might abuse PowerShell for persistence," leading to investigation of unusual PowerShell activity patterns.

4. **SA**: Explain how security event correlation works in SIEM systems and why it's essential for reducing false positives and identifying complex attack patterns.  
   **Answer**: Event correlation combines related security events from multiple sources based on time, source, destination, or other attributes to create meaningful incidents. This reduces false positives by providing context (e.g., failed login followed by successful login from same IP) and identifies multi-stage attacks that span different systems and timeframes.

5. **SA**: Describe how SIEM systems integrate with the security technologies from Weeks 3-6 (PKI, MFA, RBAC, Network Security) to provide comprehensive visibility.  
   **Answer**: SIEM centralizes logs from all security domains: PKI certificate events for cryptographic monitoring, MFA authentication logs for access analysis, RBAC access control decisions for authorization tracking, and network security events for traffic analysis. This integration enables correlation across security layers, detecting complex attacks that span multiple domains like credential compromise leading to lateral movement.

---

## Week 8: Security Assessment and Penetration Testing

### True/False Questions (15 total - Canvas will select 5)

1. **T/F**: Vulnerability assessments identify security weaknesses while penetration testing attempts to exploit them.  
   **Answer**: TRUE

2. **T/F**: The OWASP Top 10 provides a standardized list of the most critical web application security risks.  
   **Answer**: TRUE

3. **T/F**: Penetration testing should always be conducted without authorization to simulate real-world attacks.  
   **Answer**: FALSE (Penetration testing requires explicit written authorization)

4. **T/F**: OpenVAS is an open-source vulnerability assessment scanner that can identify known security vulnerabilities.  
   **Answer**: TRUE

5. **T/F**: Social engineering attacks are outside the scope of technical security assessments.  
   **Answer**: FALSE (Social engineering is often included in comprehensive security assessments)

6. **T/F**: Risk assessment combines vulnerability severity with likelihood and business impact to prioritize remediation.  
   **Answer**: TRUE

7. **T/F**: Automated vulnerability scanners can identify all possible security vulnerabilities in a system.  
   **Answer**: FALSE (Manual testing and logic flaws often require human analysis)

8. **T/F**: The Common Vulnerability Scoring System (CVSS) provides a standardized method for rating vulnerability severity.  
   **Answer**: TRUE

9. **T/F**: Web application firewalls (WAFs) eliminate the need for secure coding practices and application security testing.  
   **Answer**: FALSE (WAFs provide protection but don't eliminate underlying vulnerabilities)

10. **T/F**: Security assessments should test both technical controls and security processes and procedures.  
    **Answer**: TRUE

11. **T/F**: Penetration testing reports should include detailed exploitation techniques to help with remediation.  
    **Answer**: FALSE (Reports should focus on vulnerabilities and remediation, not detailed attack methods)

12. **T/F**: The PTES (Penetration Testing Execution Standard) provides a comprehensive framework for conducting penetration tests.  
    **Answer**: TRUE

13. **T/F**: Security assessments should be conducted only by external third-party consultants for objectivity.  
    **Answer**: FALSE (Internal teams can conduct assessments, though external perspective adds value)

14. **T/F**: Compliance scanning and security assessments serve the same purpose and use identical methodologies.  
    **Answer**: FALSE (Compliance scanning checks specific standards; security assessments are more comprehensive)

15. **T/F**: Security assessment findings should be prioritized based solely on technical severity scores.  
    **Answer**: FALSE (Business impact and organizational risk should also be considered)

### Multiple Choice Questions (15 total - Canvas will select 7)

1. **MC**: What is the primary difference between vulnerability assessment and penetration testing?
   a) Vulnerability assessment is automated; penetration testing is manual  
   b) Vulnerability assessment identifies weaknesses; penetration testing exploits them  
   c) Vulnerability assessment is cheaper; penetration testing is more expensive  
   d) Vulnerability assessment focuses on networks; penetration testing focuses on applications  
   **Answer**: b) Vulnerability assessment identifies weaknesses; penetration testing exploits them

2. **MC**: Which phase of penetration testing involves gathering information about the target organization and systems?
   a) Vulnerability analysis  
   b) Exploitation  
   c) Reconnaissance  
   d) Post-exploitation  
   **Answer**: c) Reconnaissance

3. **MC**: What does a CVSS score of 9.0 or higher typically indicate?
   a) Low severity vulnerability  
   b) Medium severity vulnerability  
   c) High severity vulnerability  
   d) Critical severity vulnerability  
   **Answer**: d) Critical severity vulnerability

4. **MC**: Which OWASP Top 10 vulnerability involves attackers injecting malicious code into input fields?
   a) Broken Authentication  
   b) Cross-Site Scripting (XSS)  
   c) Insecure Direct Object References  
   d) Security Misconfiguration  
   **Answer**: b) Cross-Site Scripting (XSS)

5. **MC**: What is the most important prerequisite before conducting any penetration testing activities?
   a) Having the latest testing tools  
   b) Written authorization from system owners  
   c) Completing security training  
   d) Understanding the technical architecture  
   **Answer**: b) Written authorization from system owners

6. **MC**: In the context of security assessments, what is meant by "false positive"?
   a) A real vulnerability that was not detected  
   b) A vulnerability report that is incorrectly flagged as a security issue  
   c) A test that fails to run properly  
   d) A critical finding that requires immediate attention  
   **Answer**: b) A vulnerability report that is incorrectly flagged as a security issue

7. **MC**: Which tool is most appropriate for comprehensive network vulnerability scanning?
   a) Wireshark  
   b) OpenVAS/Greenbone  
   c) Metasploit  
   d) Burp Suite  
   **Answer**: b) OpenVAS/Greenbone

8. **MC**: What type of testing approach provides testers with full knowledge of the system architecture?
   a) Black box testing  
   b) White box testing  
   c) Gray box testing  
   d) Red team testing  
   **Answer**: b) White box testing

9. **MC**: In risk assessment, how is risk typically calculated?
   a) Risk = Threat × Vulnerability  
   b) Risk = Impact × Likelihood × Vulnerability  
   c) Risk = Likelihood × Impact  
   d) Risk = Vulnerability × Asset Value  
   **Answer**: c) Risk = Likelihood × Impact

10. **MC**: What is the primary purpose of a security assessment executive summary?
    a) To provide detailed technical exploitation steps  
    b) To list all vulnerabilities found during testing  
    c) To communicate high-level findings and business risk to management  
    d) To document all tools used during assessment  
    **Answer**: c) To communicate high-level findings and business risk to management

11. **MC**: Which of the following best describes responsible disclosure?
    a) Immediately publishing vulnerability details publicly  
    b) Reporting vulnerabilities to vendors with reasonable time for remediation before public disclosure  
    c) Never disclosing vulnerabilities to protect organizations  
    d) Selling vulnerability information to the highest bidder  
    **Answer**: b) Reporting vulnerabilities to vendors with reasonable time for remediation before public disclosure

12. **MC**: What should be the first priority when a critical vulnerability is discovered during a security assessment?
    a) Document it for the final report  
    b) Attempt to exploit it further  
    c) Immediately notify the client/system owner  
    d) Continue testing other systems  
    **Answer**: c) Immediately notify the client/system owner

13. **MC**: Which methodology provides a structured approach for web application security testing?
    a) NIST Cybersecurity Framework  
    b) ISO 27001  
    c) OWASP Testing Guide  
    d) COBIT  
    **Answer**: c) OWASP Testing Guide

14. **MC**: What is the main advantage of using multiple vulnerability scanners during an assessment?
    a) Faster scanning speeds  
    b) Reduced false negatives by combining different detection capabilities  
    c) Lower licensing costs  
    d) Simplified report generation  
    **Answer**: b) Reduced false negatives by combining different detection capabilities

15. **MC**: In penetration testing, what is the purpose of the "post-exploitation" phase?
    a) To fix discovered vulnerabilities  
    b) To determine the potential impact and scope of compromise  
    c) To gather initial information about targets  
    d) To clean up traces of testing activities  
    **Answer**: b) To determine the potential impact and scope of compromise

### Short Answer Questions (5 total - Canvas will select 1)

1. **SA**: Explain the difference between black box, white box, and gray box security testing approaches, and describe when each would be most appropriate.  
   **Answer**: Black box testing simulates external attackers with no internal knowledge, ideal for testing perimeter security. White box testing provides full system knowledge, best for comprehensive code review and architectural analysis. Gray box testing combines limited internal knowledge with external perspective, useful for simulating insider threats or testing after initial compromise.

2. **SA**: Describe the OWASP Top 10 and explain why it's important for web application security assessments. Provide one example vulnerability and its potential impact.  
   **Answer**: The OWASP Top 10 identifies the most critical web application security risks based on industry data and expert consensus. It provides standardized focus areas for security testing and developer training. Example: SQL Injection allows attackers to manipulate database queries through input fields, potentially leading to data breach, authentication bypass, or complete database compromise.

3. **SA**: What is responsible disclosure in vulnerability research, and why is it important for maintaining ethical security practices?  
   **Answer**: Responsible disclosure involves privately reporting vulnerabilities to affected organizations with reasonable time for remediation before public disclosure. This balances the need for security improvement with protecting users from active exploitation. It maintains trust between security researchers and organizations while ensuring vulnerabilities get fixed rather than ignored.

4. **SA**: Explain how risk assessment integrates with security testing results to help organizations prioritize remediation efforts.  
   **Answer**: Risk assessment evaluates vulnerabilities based on likelihood of exploitation and business impact, not just technical severity. It considers factors like asset value, threat landscape, and organizational context to prioritize which vulnerabilities need immediate attention versus those that can be addressed later. This helps organizations allocate limited resources effectively.

5. **SA**: Describe how security assessments should evaluate the integrated security architecture from Weeks 3-7, and explain why testing individual components in isolation is insufficient.  
   **Answer**: Comprehensive security assessments must test integration points between PKI, authentication, access control, network security, and monitoring systems to identify gaps that emerge from component interactions. Testing in isolation misses real-world attack paths that span multiple security layers, such as certificate compromise leading to authentication bypass and lateral network movement. Integration testing reveals whether the complete security architecture functions as intended.

---

## Week 9: Security Architecture Design and Integration

### True/False Questions (15 total - Canvas will select 5)

1. **T/F**: Security architecture design should integrate preventive, detective, and responsive security controls.  
   **Answer**: TRUE

2. **T/F**: The STRIDE threat modeling methodology categorizes threats into Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.  
   **Answer**: TRUE

3. **T/F**: Zero Trust architecture assumes that all network traffic is inherently trustworthy once inside the perimeter.  
   **Answer**: FALSE (Zero Trust assumes no inherent trust based on location)

4. **T/F**: Threat modeling should be performed only after a security architecture is completely implemented.  
   **Answer**: FALSE (Threat modeling should be performed during design phase)

5. **T/F**: Defense in depth involves implementing multiple layers of security controls to protect against various attack vectors.  
   **Answer**: TRUE

6. **T/F**: Security architecture documentation is primarily needed for compliance purposes and has limited operational value.  
   **Answer**: FALSE (Documentation is essential for operations, maintenance, and incident response)

7. **T/F**: Forensic readiness should be integrated into security architecture design from the beginning.  
   **Answer**: TRUE

8. **T/F**: Cloud security architectures require the same security controls as traditional on-premises infrastructures.  
   **Answer**: FALSE (Cloud architectures require adapted controls and shared responsibility models)

9. **T/F**: Security architects should focus only on technical controls and leave policy controls to other teams.  
   **Answer**: FALSE (Security architecture must integrate technical, administrative, and physical controls)

10. **T/F**: Microservices architectures typically require more granular security controls than monolithic applications.  
    **Answer**: TRUE

11. **T/F**: The TOGAF framework can be adapted to include security architecture domains and considerations.  
    **Answer**: TRUE

12. **T/F**: Security architecture should be designed to minimize single points of failure that could compromise the entire system.  
    **Answer**: TRUE

13. **T/F**: Incident response procedures should be integrated into security architecture design decisions.  
    **Answer**: TRUE

14. **T/F**: Security architecture reviews should only be conducted when security incidents occur.  
    **Answer**: FALSE (Regular reviews should be conducted proactively)

15. **T/F**: Privacy by design principles should be integrated into security architecture for data protection compliance.  
    **Answer**: TRUE

### Multiple Choice Questions (15 total - Canvas will select 7)

1. **MC**: What is the primary goal of security architecture design?
   a) To implement the most advanced security technologies  
   b) To create a comprehensive framework that addresses organizational risk while enabling business objectives  
   c) To achieve perfect security with zero vulnerabilities  
   d) To minimize security-related costs  
   **Answer**: b) To create a comprehensive framework that addresses organizational risk while enabling business objectives

2. **MC**: In the STRIDE threat modeling methodology, what does the "R" represent?
   a) Risk  
   b) Repudiation  
   c) Resilience  
   d) Recovery  
   **Answer**: b) Repudiation

3. **MC**: Which principle is fundamental to Zero Trust architecture?
   a) Trust but verify  
   b) Never trust, always verify  
   c) Trust based on network location  
   d) Trust based on user credentials  
   **Answer**: b) Never trust, always verify

4. **MC**: What is the main advantage of implementing defense in depth?
   a) Reduced cost of security controls  
   b) Simplified security management  
   c) Multiple layers of protection if one control fails  
   d) Faster system performance  
   **Answer**: c) Multiple layers of protection if one control fails

5. **MC**: In security architecture design, what should drive the selection of security controls?
   a) Latest technology trends  
   b) Vendor recommendations  
   c) Risk assessment and threat analysis  
   d) Compliance requirements only  
   **Answer**: c) Risk assessment and threat analysis

6. **MC**: Which component is essential for forensic readiness in security architecture?
   a) Advanced firewalls  
   b) Comprehensive logging and audit trails  
   c) Encrypted communications  
   d) Multi-factor authentication  
   **Answer**: b) Comprehensive logging and audit trails

7. **MC**: What is the primary challenge when designing security for microservices architectures?
   a) Higher licensing costs  
   b) Managing security across numerous distributed services and APIs  
   c) Slower development cycles  
   d) Limited scalability options  
   **Answer**: b) Managing security across numerous distributed services and APIs

8. **MC**: Which architectural pattern best supports the principle of least privilege?
   a) Centralized authentication with broad access rights  
   b) Role-based access control with granular permissions  
   c) Single sign-on with admin privileges  
   d) Network-based access control only  
   **Answer**: b) Role-based access control with granular permissions

9. **MC**: In cloud security architecture, what is the most critical consideration?
   a) Understanding and implementing the shared responsibility model  
   b) Using only cloud-native security services  
   c) Maintaining complete control over all security aspects  
   d) Avoiding hybrid cloud deployments  
   **Answer**: a) Understanding and implementing the shared responsibility model

10. **MC**: What should be the first step in designing a security architecture?
    a) Selecting security tools and technologies  
    b) Understanding business requirements and conducting risk assessment  
    c) Implementing compliance frameworks  
    d) Designing network topology  
    **Answer**: b) Understanding business requirements and conducting risk assessment

11. **MC**: Which factor is most important when integrating multiple security technologies into a cohesive architecture?
    a) All technologies must be from the same vendor  
    b) Ensuring interoperability and unified management  
    c) Using only open-source solutions  
    d) Implementing the newest available technologies  
    **Answer**: b) Ensuring interoperability and unified management

12. **MC**: How should security architecture address the integration of preventive and detective controls?
    a) Focus exclusively on prevention to stop all attacks  
    b) Implement detection only after prevention fails  
    c) Create complementary layers where detection capabilities support preventive controls  
    d) Choose either prevention or detection based on cost  
    **Answer**: c) Create complementary layers where detection capabilities support preventive controls

13. **MC**: What is the most important outcome of threat modeling in security architecture?
    a) A complete list of all possible vulnerabilities  
    b) Identification of high-priority threats that drive architectural decisions  
    c) Detailed exploitation techniques for penetration testing  
    d) Compliance with regulatory requirements  
    **Answer**: b) Identification of high-priority threats that drive architectural decisions

14. **MC**: Which approach best describes secure architecture design for enterprise environments?
    a) Implement maximum security regardless of business impact  
    b) Balance security requirements with business needs and usability  
    c) Focus only on perimeter security controls  
    d) Prioritize cost reduction over security effectiveness  
    **Answer**: b) Balance security requirements with business needs and usability

15. **MC**: What is the key benefit of integrating incident response considerations into security architecture design?
    a) Reduced need for security monitoring  
    b) Faster recovery and containment capabilities when incidents occur  
    c) Lower security implementation costs  
    d) Elimination of security vulnerabilities  
    **Answer**: b) Faster recovery and containment capabilities when incidents occur

### Short Answer Questions (5 total - Canvas will select 1)

1. **SA**: Explain the STRIDE threat modeling methodology and describe how it can be used to identify security requirements during architecture design.  
   **Answer**: STRIDE categorizes threats into six types: Spoofing (identity), Tampering (data), Repudiation (actions), Information Disclosure (confidentiality), Denial of Service (availability), and Elevation of Privilege (authorization). Architects analyze each system component against these threat categories to identify potential attack vectors and design appropriate countermeasures, ensuring comprehensive threat coverage during the design phase.

2. **SA**: Describe the concept of Zero Trust architecture and explain how it differs from traditional perimeter-based security approaches.  
   **Answer**: Zero Trust architecture operates on "never trust, always verify" principles, requiring authentication and authorization for every access request regardless of location. Unlike traditional perimeter security that trusts internal traffic, Zero Trust assumes potential compromise at any point and implements continuous verification, micro-segmentation, and least privilege access. This approach better addresses modern threats like insider attacks and lateral movement.

3. **SA**: What is defense in depth and how should it be implemented in modern security architectures? Provide examples of different security layers.  
   **Answer**: Defense in depth implements multiple independent security layers so that if one fails, others continue providing protection. Examples include: perimeter security (firewalls, IDS), network segmentation (VLANs, micro-segmentation), endpoint protection (antivirus, EDR), application security (WAF, secure coding), access controls (MFA, RBAC), and data protection (encryption, DLP). Each layer addresses different attack vectors and failure modes.

4. **SA**: Explain how forensic readiness should be integrated into security architecture design and why this is important for incident response.  
   **Answer**: Forensic readiness involves designing systems to preserve evidence from the start, including comprehensive logging, audit trails, timestamp synchronization, data integrity protection, and secure log storage. This enables effective incident investigation, legal proceedings, and lessons learned analysis. Without forensic readiness, crucial evidence may be lost or inadmissible, hampering response efforts and organizational learning.

5. **SA**: Describe how the security technologies from Weeks 3-8 should be integrated into a comprehensive enterprise security architecture, and explain the benefits of this integration.  
   **Answer**: A comprehensive architecture integrates PKI (trust foundation and digital signatures), MFA (strong authentication), RBAC (granular authorization), network security (traffic control and segmentation), SIEM (centralized monitoring and correlation), and security assessment (validation and improvement). Integration benefits include: unified policy enforcement, correlated threat detection across domains, streamlined management, reduced security gaps, and comprehensive visibility enabling faster incident response and better security outcomes.

---