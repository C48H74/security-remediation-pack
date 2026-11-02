---
name: security-remediation-pack
description: Transforma a saída bruta de testes de segurança (nmap, Nessus, OWASP ZAP, Burp, um CSV de achados ou anotações de pentest) em um pacote de remediação pronto para aplicar e distribuído aos departamentos que precisam agir. Use quando houver resultados de varredura ou um relatório de pentest/red team e forem necessários achados priorizados (CVSS v4, CISA KEV, FIRST EPSS, impacto no negócio), mapeamento MITRE ATT&CK / D3FEND / OWASP WSTG, passos de correção e verificação, responsável RACI e SLA por achado, tickets por departamento para Jira, ServiceNow ou DefectDojo e um delta de reteste. Cobre achados de TI, web, identidade, pessoas e OT/ICS.
---

# Pacote de remediação de segurança

Idiomas: [English](../../SKILL.md) | [Español](../es/SKILL.md) | **Português (Brasil)**

Um teste só se paga quando a correção chega à produção. Esta skill pega o que os avaliadores encontraram e entrega o que cada equipe precisa para agir: um relatório para a diretoria e uma fila de tickets por departamento, com os passos, o prazo e a evidência necessária para fechar cada um.

## Quando usar

- Você tem saída de scanners (nmap, Nessus, ZAP, Burp) ou um CSV de achados de um pentest e precisa entregar isso para a empresa.
- Um cliente pergunta "quem corrige o quê e até quando?" depois de uma avaliação.
- Você precisa repetir o mesmo escopo depois e provar o que foi corrigido de fato.
- **Não serve para:** executar ataques ou varreduras. Os testes já devem ter sido feitos dentro de um escopo autorizado e com regras de engajamento (planejamento do NIST SP 800-115; pre-engagement do PTES).

## Entradas

| Entrada | Opção | Obrigatória | Observações |
|---|---|---|---|
| nmap XML (`-oX`) | `--nmap` | pelo menos uma fonte | Usa a saída NSE de `vulners` e `smb-vuln-*` para CVEs; regras de porta para serviços de risco (RDP, SMB, Telnet, Modbus, S7, OPC UA...) |
| Nessus `.nessus` | `--nessus` | | CVE, vetores CVSS v4/v3, saída do plugin |
| Relatório XML do OWASP ZAP | `--zap` | | Id do plugin e CWE → categoria; ataque confirmado conta como evidência de exploração |
| XML de issues do Burp Suite | `--burp` | | Tipo e nome do issue → categoria; informativos são ignorados |
| CSV de achados | `--findings` | | Achados manuais e de pentest. Colunas: `id,source,title,category,host,ip,port,url,cve,cwe,cvss4_vector,cvss4_score,severity,evidence,wstg,exploit_available,notes` |
| Inventário de ativos CSV | `--assets` | muito recomendado | `asset_id,ip,hostname,asset_name,business_service,criticality(1-5),environment,zone,internet_facing,data_classification,owner_dept`. Uma zona contendo `OT` marca ativos de planta |
| CSV de departamentos | `--org` | recomendado | `dept_code,name,lead,email,jira_component,servicenow_group` |
| Matriz RACI | `--raci` | padrão `routing/raci_matrix.yaml` | Categoria → R/A/C/I e responsável pela detecção, SLAs, exceções |
| KEV / EPSS | `--kev`, `--epss` ou `--online` | recomendado | Snapshots deixam as execuções reproduzíveis; `--online` baixa o feed KEV da CISA e a API EPSS da FIRST |
| Linha de base | `--baseline <findings.json anterior>` | para retestes | Gera `retest_delta.md/.json` |

Todas as opções podem ser repetidas (`--nmap a.xml --nmap b.xml`). Achados de ferramentas diferentes no mesmo serviço ou URL viram um único achado (CVEs e fontes combinados).

## Como executar

```bash
python3 scripts/remediation_pack.py \
  --nmap scans/nmap.xml --nessus scans/scan.nessus --zap scans/zap.xml --burp scans/burp.xml \
  --findings notes/findings.csv --assets cmdb/assets.csv --org cmdb/org_departments.csv \
  --kev data/kev.json --epss data/epss.json \
  --company "ACME" --scope "Perímetro externo e portal de fornecedores" --lang pt-BR --out out/
python3 scripts/selftest.py out/ --org cmdb/org_departments.csv   # controle de qualidade, sai com 1 se falhar
```

Somente biblioteca padrão do Python 3.9+. `--lang es` ou `--lang pt-BR` gera o relatório e os tickets com os templates traduzidos de `i18n/`. Os textos de correção do catálogo estão em inglês.

## Procedimento para o agente

1. **Confira o escopo.** Confirme que o usuário tem autorização sobre os alvos da entrada. Se faltar o inventário de ativos ou o CSV de departamentos, peça. Sem eles dá para executar, mas avise que o impacto no negócio e os responsáveis serão genéricos.
2. **Normalize as anotações.** Converta as anotações livres do pentest em linhas do CSV de achados. Escolha a `category` em `knowledge/catalog.json` (18 categorias), mantenha a evidência do avaliador sem alterações e adicione um vetor CVSS v4.0 só se o avaliador tiver informado.
3. **Execute o script** com todas as fontes disponíveis, mais KEV/EPSS (snapshot ou `--online`).
4. **Execute o `selftest.py`.** Corrija as entradas e repita até todas as verificações passarem. Não entregue um pacote com falhas. Um `WARN` (por exemplo, KEV não carregado) deve ser informado ao usuário.
5. **Revise o começo do relatório como um diretor faria.** Leia a seção 1 e as linhas P1/P2. Cada achado tem uma linha "Why" em linguagem simples. Se uma prioridade parecer errada, corrija a entrada (criticidade do ativo, zona, exposição à internet) em vez de editar a saída.
6. **Entregue**:
   - `report.md` para a diretoria (a seção 1 lista as decisões da semana),
   - `tickets/<DEPT>.md` para cada líder de departamento,
   - `jira_import.csv` / `servicenow_import.json` / `defectdojo_generic.json` para os administradores dessas ferramentas,
   - `navigator/*.json` para o SOC ou o time de inteligência de ameaças (carregue no ATT&CK Navigator).
7. **Reteste.** Depois das correções, execute de novo com `--baseline out/findings.json`. Só pode ser marcado como *corrigido* o achado cuja ferramenta e host entraram na nova execução. O restante aparece como *não retestado* e continua aberto.

## Como decide (resumo)

**Prioridade.** É uma decisão inspirada no SSVC, escrita para esta skill:

- *Exploração*:
  - `active`: o CVE está no CISA KEV,
  - `poc`: EPSS ≥ 0,1, ou o exploit foi confirmado no teste,
  - `none`: nos demais casos.
- *Exposição*: internet, OT ou interna.
- *Impacto técnico*: CVSS v4 ≥ 8,5 significa total.
- *Criticidade do ativo*: de 1 a 5.

O resultado é ACT → **P1**, ATTEND → **P2**, TRACK\* → **P3** ou TRACK → **P4**. Algumas categorias têm piso (credenciais padrão nunca ficam abaixo de P2; lacunas de detecção nunca abaixo de P3). Achados KEV são sempre P1 ou P2.

**SLA (dias corridos)**

| Prioridade | TI | OT |
|---|---|---|
| P1 | 3 | 3 (contenção); correção definitiva via MOC |
| P2 | 14 | 30 |
| P3 | 45 | 90 |
| P4 | 90 | 180 |

Todos os SLAs são editáveis em `routing/raci_matrix.yaml`. Use o menor entre estes e qualquer prazo regulatório aplicável, como as datas da CISA BOD 26-04 para agências federais dos EUA ou o art. 33 do GDPR (72 h) para incidentes com dados pessoais (no Brasil, verifique também os prazos da LGPD/ANPD).

**Roteamento**

- Cada categoria tem R (quem corrige), um único A (quem responde, MGMT por padrão), C, I e um responsável pela detecção.
- Exceções:
  - Ativos da zona OT passam o papel R para **OT-ENG** e exigem Gestão de Mudanças (MOC) e aprovação de segurança de processo.
  - Dados pessoais adicionam **GRC-DPO** como Consultado.
  - Ativos expostos à internet informam **NETWORK**.
  - Ativos desconhecidos recebem uma nota de CMDB e IT-INFRA é informado.

**Tickets** de quatro tipos:

- **fix**, um por departamento Responsável,
- **detection**, para o SOC em cada P1/P2 enquanto a correção está pendente,
- **compliance**, para GRC-DPO quando um P1/P2 envolve dados pessoais,
- **governance**, um ticket MGMT para aprovar o plano.

## Pacote de saída

| Arquivo | Para quem | O que contém |
|---|---|---|
| `report.md` | Diretoria, líderes | Resumo executivo, linha de KPIs, decisões necessárias, tabela priorizada, carga por departamento, indicador de exposição inspirado no OSSTMM, detalhes dos achados (por quê, impacto, ATT&CK/D3FEND/WSTG/CWE, passos de correção, verificação, detecção provisória, evidência), plano de reteste, método e fontes |
| `tickets/<DEPT>.md/.csv/.json` | Cada departamento | Somente a própria fila: passos, prazo, RACI, critério de pronto |
| `jira_import.csv` | Administrador do Jira | Summary, Issue Type, Priority (Highest/High/Medium/Low), Component/s, Due Date, Labels, Description |
| `servicenow_import.json` | Administrador do ServiceNow | `records[]` com urgência/impacto, grupo de atribuição, prazo |
| `defectdojo_generic.json` | AppSec / gestão de vulnerabilidades | Formato Generic Findings Import do DefectDojo |
| `navigator/layer_*-attack.json` | SOC / CTI | Camadas do ATT&CK Navigator (Enterprise e ICS) pontuadas por prioridade |
| `findings.json` / `findings.csv` | Automação, linha de base do reteste | Achados normalizados com impressões digitais e IDs estáveis |
| `retest_delta.md/.json` | Diretoria, auditores | Corrigido e verificado / ainda aberto / novo / não retestado |

## Arquivos da skill

- `scripts/remediation_pack.py`: parsers, enriquecimento, decisão, roteamento, tickets e exportações.
- `scripts/selftest.py`: controle de qualidade com 27 regras (responsável, SLA, mapeamentos, passos, regras OT e DPO, ordem, prazos, marcadores, exportações).
- `scripts/verify_ids.py`: valida cada identificador ATT&CK, D3FEND e WSTG do catálogo contra os dados oficiais.
- `knowledge/catalog.json`: 18 categorias de achado com CWE, técnicas e mitigações ATT&CK, D3FEND, IDs WSTG, vetor CVSS v4 padrão, passos de correção, verificação e detecção.
- `routing/raci_matrix.yaml`: departamentos, RACI por categoria, SLAs, exceções. Ajuste para a sua organização.
- `templates/` e as traduções em `i18n/es/templates/` e `i18n/pt-BR/templates/`.
- `examples/novarefino/`: uma operadora de refinaria fictícia com entradas em formatos reais e as saídas geradas (`run_example.sh` recria tudo).

## Regras para o agente

- Nunca invente CVEs, notas CVSS, status KEV ou valores EPSS. Use os dados de entrada, os snapshots ou os feeds ao vivo. Se um vetor CVSS v4 for o padrão da categoria, o relatório informa e o avaliador precisa confirmar.
- Mantenha a evidência do avaliador sem alterações. Oculte segredos (senhas, tokens, números completos de cartão ou conta) antes de compartilhar tickets fora do time de segurança.
- OT/ICS: não recomende varredura ativa nem patch em controladores em operação. Contenha primeiro na fronteira TI/OT e planeje a correção definitiva para uma janela aprovada.
- Cada departamento recebe somente o próprio arquivo de tickets. O relatório completo fica restrito à diretoria e ao time de segurança.
- Os identificadores dos frameworks (ATT&CK, D3FEND, WSTG, CWE) são referências. Os textos de correção do catálogo são orientação original, não cópia das normas.
