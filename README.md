# ADCS Template Vulnerability Checker

This script is designed to analyze exported certificate templates from an Active Directory Certificate Services (ADCS) environment and identify insecure configurations that can be exploited by malicious users. It not only detects vulnerabilities but also provides exploitation guidance and recommended tools.

---

```ruby
└─# ./vuln-check-adcs-sh cert-templates.txt

=== Análise de Templates ADCS para Vulnerabilidades ===
------------------------------------------------------

Template Vulnerável Encontrado:
Resumo das Falhas:
  - Inclui 'Client Authentication' como política de uso.
  - Permite definir SubjectAltName com UPN arbitrário.


Recomendações e Possível Exploração:
  ➤ Certificados podem ser usados para autenticar via Kerberos (Pass-the-Cert).
  ➤ Possível emitir certificado com UPN de outro usuário (ex: administrator@domínio).


Trecho Relevante do Template:
----------------------------------------
  CanonicalName                   : domain.local/Configuration/Services/Public Key Services/Certificate Templates/User
  DisplayName                     : User
  DistinguishedName               : CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=AD,DC=local
  msPKI-Certificate-Name-Flag     : -1509949440
  Name                            : User
  nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
  pKIExtendedKeyUsage             : {1.3.6.1.4.1.311.10.3.4, 1.3.6.1.5.5.7.3.4, 1.3.6.1.5.5.7.3.2}
  CanonicalName                   : ad.local/Configuration/Services/Public Key Services/Certificate Templates/UserSignature
  DisplayName                     : User Signature Only
  DistinguishedName               : CN=UserSignature,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=AD,DC=local
  msPKI-Certificate-Name-Flag     : -1509949440
  Name                            : UserSignature
  nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
  pKIExtendedKeyUsage             : {1.3.6.1.5.5.7.3.4, 1.3.6.1.5.5.7.3.2}
  CanonicalName                   : ad.local/Configuration/Services/Public Key Services/Certificate Templates/SmartcardUser
  DisplayName                     : Smartcard User
  DistinguishedName               : CN=SmartcardUser,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=AD,DC=local
  msPKI-Certificate-Name-Flag     : -1509949440
  Name                            : SmartcardUser
  nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
  pKIExtendedKeyUsage             : {1.3.6.1.5.5.7.3.4, 1.3.6.1.5.5.7.3.2, 1.3.6.1.4.1.311.20.2.2}
  CanonicalName                   : ad.local/Configuration/Services/Public Key Services/Certificate Templates/ClientAuth
  DisplayName                     : Authenticated Session

Passos para Exploração:
  1. Enumerar com: certipy find -u <usuario> -p <senha> -target <DC>
  2. Emitir certificado com: certipy req -u <usuario> -p <senha> -ca <CA> -template  -upn administrator@dominio
  3. Autenticar com certificado: certipy auth -pfx <arquivo.pfx> -target <DC>
  4. Usar acesso como Administrator com secretsdump ou psexec.

Ferramentas sugeridas:
  🔧 Certipy   → Enumeração e abuso de ADCS
  🔧 Rubeus    → Requisição e uso de TGT com certificados
  🔧 Mimikatz  → Autenticação Pass-the-Cert
  🔧 BloodHound → Mapeamento de relações ACL e trustes

=== Análise Concluída ===


```



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
