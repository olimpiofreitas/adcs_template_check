# ADCS Template Vulnerability Checker

This script is designed to analyze exported certificate templates from an Active Directory Certificate Services (ADCS) environment and identify insecure configurations that can be exploited by malicious users. It not only detects vulnerabilities but also provides exploitation guidance and recommended tools.

---


## ✅ Features

- Detects vulnerable configurations in certificate templates:
  - Enrollment permission granted to `Authenticated Users`
  - Full control granted to non-administrative SIDs
  - Certificate issuance without manager approval
  - Allows client authentication (EKU)
  - Allows arbitrary UPN in SubjectAltName

- Displays:
  - Template name
  - Reasons for the vulnerability
  - Relevant template attributes
  - Step-by-step exploitation guidance
  - Suggested tools

---

## 📦 Requirements

- Bash shell
- Input file containing raw template data exported from ADCS (e.g., output from `certipy find -v` or LDAP export)

---

## 🚀 How to Use

```bash
chmod +x adcs_template_check_enhanced.sh
./adcs_template_check_enhanced.sh templates.txt
