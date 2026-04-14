# Security Policy

## Intended Use

SharkPy is a network security testing and research tool. It is designed for:

- Security professionals auditing networks and systems they own or administer
- Penetration testers with written authorization to test a target environment
- Researchers studying network protocols, TLS implementations, and traffic analysis
- Developers debugging their own applications' network behaviour

**SharkPy must only be used on networks, devices, and systems that you own or have explicit written permission to test.** Intercepting, capturing, or modifying network traffic without authorization is illegal in most jurisdictions and is a violation of this project's intended use. The authors and contributors accept no liability for misuse.

Capabilities such as TLS MITM interception, packet modification via NFQUEUE/WinDivert, and ARP-level traffic manipulation carry significant potential for harm if misused. Use them responsibly.

---

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x (current) | Yes |
| Pre-release / development | Best effort |

---

## Reporting a Vulnerability

If you discover a security vulnerability in SharkPy itself (e.g., a flaw in certificate generation, an injection vector in the iptables rule builder, or an unsafe deserialization path), please follow responsible disclosure:

1. **Do not open a public GitHub issue** for the vulnerability. Public disclosure before a fix is available puts users at risk.

2. **Email the maintainer** directly. Use the contact information in the repository's GitHub profile or send a message via GitHub's private vulnerability reporting feature:
   - Navigate to the repository → **Security** tab → **Report a vulnerability**

3. **Include in your report:**
   - A clear description of the vulnerability and its potential impact
   - Steps to reproduce or a minimal proof-of-concept
   - The SharkPy version and platform (Linux/Windows) where you observed the issue
   - Any suggested mitigations you've already identified

4. **Expected response time:** We aim to acknowledge reports within 72 hours and provide a timeline for a fix within 7 days. Complex issues may take longer; we will keep you informed.

5. **Coordinated disclosure:** Once a fix is released, we are happy to credit you in the CHANGELOG and release notes (or keep your report anonymous if you prefer).

---

## Notes on the CA Private Key

SharkPy generates a root CA private key stored at `~/.sharkpy/ca/ca.key`. This key is written with no passphrase. It should be treated as sensitive:

- Do not share it or commit it to version control.
- Regenerate the CA (TLS tab → **Generate CA**) if you suspect the key has been compromised.
- Remove the SharkPy CA from your browser's trust store when you are done testing.

The generated CA is valid for 10 years. Installing it as a system-trusted root makes your machine vulnerable to TLS impersonation by anyone who obtains the private key. Install it only in a dedicated test browser profile or a disposable VM.
