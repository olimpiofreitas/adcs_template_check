#!/bin/bash

# Cores ANSI
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

# Verifica se o arquivo de input foi fornecido
if [ $# -ne 1 ]; then
    echo -e "${RED}Erro: Uso: $0 <arquivo_input.txt>${NC}"
    exit 1
fi

INPUT_FILE="$1"

# Verifica se o arquivo existe
if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}Erro: Arquivo $INPUT_FILE não encontrado.${NC}"
    exit 1
fi

echo -e "${BLUE}=== Análise de Templates ADCS para Vulnerabilidades ===${NC}"
echo -e "${BLUE}------------------------------------------------------${NC}\n"

# Função para verificar vulnerabilidades em um template
check_vulnerabilities() {
    local template_data="$1"
    local template_name=$(echo "$template_data" | grep -i "Name:" | awk -F': ' '{print $2}' | tr -d '\r')
    local vulnerable=0
    local reasons=""
    local guidance=""

    # Vulnerabilidade 1: Permite inscrição para qualquer usuário autenticado
    if echo "$template_data" | grep -i "nTSecurityDescriptor" | grep -q "S:AI(A;;FA;;;AU)"; then
        reasons="$reasons- Permite inscrição para 'Authenticated Users'.\n"
        guidance="$guidance  ➤ Potencial exploração ESC1 ou ESC7. Usuários comuns podem solicitar certificados.\n"
        vulnerable=1
    fi

    # Vulnerabilidade 2: Permite controle total para usuários não privilegiados
    if echo "$template_data" | grep -i "nTSecurityDescriptor" | grep -q "S:AI(A;;GA;;;S-[0-9-]\+)"; then
        reasons="$reasons- Controle total concedido a SID potencialmente não administrativo.\n"
        guidance="$guidance  ➤ Pode indicar ESC2. Usuário pode modificar o template ou delegar acesso.\n"
        vulnerable=1
    fi

    # Vulnerabilidade 3: Emissão sem aprovação do gerente
    if echo "$template_data" | grep -i "pKIEnrollmentFlag" | grep -q "0x00000000"; then
        reasons="$reasons- Não exige aprovação manual para emissão do certificado.\n"
        guidance="$guidance  ➤ Usuários com permissão de 'Enroll' podem emitir certificados automaticamente.\n"
        vulnerable=1
    fi

    # Vulnerabilidade 4: Permite autenticação de cliente
    if echo "$template_data" | grep -i "msPKI-Certificate-Application-Policy" | grep -q "1.3.6.1.5.5.7.3.2"; then
        reasons="$reasons- Inclui 'Client Authentication' como política de uso.\n"
        guidance="$guidance  ➤ Certificados podem ser usados para autenticar via Kerberos (Pass-the-Cert).\n"
        vulnerable=1
    fi

    # Vulnerabilidade 5: Permite UPN arbitrário (ESC1/ESC7)
    if echo "$template_data" | grep -i "pKIExtendedKeyUsage" | grep -q "1.3.6.1.4.1.311.20.2.2"; then
        reasons="$reasons- Permite definir SubjectAltName com UPN arbitrário.\n"
        guidance="$guidance  ➤ Possível emitir certificado com UPN de outro usuário (ex: administrator@domínio).\n"
        vulnerable=1
    fi

    # Exibe resultado se o template for vulnerável
    if [ "$vulnerable" -eq 1 ]; then
        echo -e "${RED}Template Vulnerável Encontrado:${NC} ${YELLOW}$template_name${NC}"
        echo -e "${GREEN}Resumo das Falhas:${NC}"
        echo -e "${reasons}" | while IFS= read -r reason; do
            echo -e "${GREEN}  $reason${NC}"
        done

        echo -e "${CYAN}\nRecomendações e Possível Exploração:${NC}"
        echo -e "${guidance}"

        echo -e "${BLUE}\nTrecho Relevante do Template:${NC}"
        echo -e "${YELLOW}----------------------------------------${NC}"
        echo "$template_data" | grep -iE "Name|nTSecurityDescriptor|pKIEnrollmentFlag|msPKI-Certificate-Application-Policy|pKIExtendedKeyUsage" | while IFS= read -r line; do
            echo -e "${YELLOW}  $line${NC}"
        done
        echo -e "${YELLOW}----------------------------------------${NC}"

        echo -e "${CYAN}\nPassos para Exploração:${NC}"
        echo -e "  1. Enumerar com: certipy find -u <usuario> -p <senha> -target <DC>"
        echo -e "  2. Emitir certificado com: certipy req -u <usuario> -p <senha> -ca <CA> -template $template_name -upn administrator@dominio"
        echo -e "  3. Autenticar com certificado: certipy auth -pfx <arquivo.pfx> -target <DC>"
        echo -e "  4. Usar acesso como Administrator com secretsdump ou psexec.\n"

        echo -e "${CYAN}Ferramentas sugeridas:${NC}"
        echo -e "  🔧 Certipy   → Enumeração e abuso de ADCS"
        echo -e "  🔧 Rubeus    → Requisição e uso de TGT com certificados"
        echo -e "  🔧 Mimikatz  → Autenticação Pass-the-Cert"
        echo -e "  🔧 BloodHound → Mapeamento de relações ACL e trustes\n"
    fi
}

# Processa o arquivo de entrada
current_template=""
while IFS= read -r line || [[ -n "$line" ]]; do
    line=$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [[ $line == DistinguishedName:* ]]; then
        if [ -n "$current_template" ]; then
            check_vulnerabilities "$current_template"
        fi
        current_template="${line}"$'\n'
    elif [ -n "$line" ]; then
        current_template="${current_template}${line}"$'\n'
    fi
done < "$INPUT_FILE"

if [ -n "$current_template" ]; then
    check_vulnerabilities "$current_template"
fi

echo -e "${BLUE}=== Análise Concluída ===${NC}"