# Pacote de remediação de segurança: {{COMPANY}}

**Data do relatório:** {{DATE}}  
**Escopo:** {{SCOPE}}  
**Classificação:** CONFIDENCIAL. Compartilhar por departamento conforme necessidade de saber.

---

## 1. Resumo executivo

{{EXEC_SUMMARY}}

{{KPI_TABLE}}

### O que a diretoria precisa decidir esta semana

1. Aprovar responsáveis e prazos da seção 3 (ticket `MGMT-001`).
2. Liberar capacidade para cada item P1: a meta é conter em 72 horas.
3. Aceitar formalmente, com responsável nomeado e data de expiração, qualquer risco que não será corrigido dentro do SLA.

## 2. Achados priorizados

A prioridade é **P1 (ACT)**, **P2 (ATTEND)**, **P3 (TRACK\*)** ou **P4 (TRACK)**. Ela vem de uma decisão inspirada no SSVC que combina evidência de exploração (CISA KEV, FIRST EPSS, exploit público), exposição (internet / OT / interna), impacto técnico (CVSS v4.0) e criticidade de negócio do ativo.

{{PRIORITY_TABLE}}

## 3. Distribuição do trabalho por departamento

Cada achado tem exatamente um papel Accountable (A) e pelo menos um departamento Responsável (R). Enquanto uma correção P1/P2 está pendente, o SOC recebe em paralelo um ticket de detecção.

{{DEPARTMENT_TABLE}}

Arquivos de tickets: `tickets/<DEPT>.md` (legível), `tickets/<DEPT>.csv` e `.json`; consolidados `jira_import.csv`, `servicenow_import.json` e `defectdojo_generic.json`.

## 4. Indicador de segurança operacional

{{METRICS}}

## 5. Detalhes dos achados e passos de correção

{{FINDINGS_DETAIL}}

## 6. Plano de reteste

{{RETEST_PLAN}}

## 7. Delta do reteste

{{DELTA}}

## 8. Método e fontes

{{METHOD}}

{{SOURCES}}

Identificadores citados: MITRE ATT&CK® e MITRE D3FEND™ (© The MITRE Corporation), IDs de teste do OWASP WSTG, CWE, CVE, CISA KEV, FIRST EPSS e CVSS v4.0. Todo o texto explicativo é original. Veja NOTICE.md no repositório da skill.
