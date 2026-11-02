---
name: security-remediation-pack
description: Convierte la salida bruta de pruebas de seguridad (nmap, Nessus, OWASP ZAP, Burp, un CSV de hallazgos o notas de pentest) en un paquete de remediación listo para aplicar y repartido entre los departamentos que deben actuar. Úsala cuando haya resultados de escaneo o un informe de pentest/red team y se necesiten hallazgos priorizados (CVSS v4, CISA KEV, FIRST EPSS, impacto de negocio), mapeo MITRE ATT&CK / D3FEND / OWASP WSTG, pasos de corrección y verificación, responsable RACI y SLA por hallazgo, tickets por departamento para Jira, ServiceNow o DefectDojo y un delta de retest. Cubre hallazgos de IT, web, identidad, personas y OT/ICS.
---

# Paquete de remediación de seguridad

Idiomas: [English](../../SKILL.md) | **Español** | [Português (Brasil)](../pt-BR/SKILL.md)

Una prueba solo rinde cuando la corrección llega a producción. Esta skill toma lo que encontraron los auditores y entrega lo que cada equipo necesita para actuar: un informe para la dirección y una cola de tickets por departamento, con los pasos, la fecha límite y la evidencia necesaria para cerrarlos.

## Cuándo usarla

- Tienes salida de escáneres (nmap, Nessus, ZAP, Burp) o un CSV de hallazgos de un pentest y debes entregarlo a la empresa.
- Un cliente pregunta "¿quién arregla qué y para cuándo?" después de una evaluación.
- Necesitas repetir el mismo alcance más tarde y demostrar qué se corrigió de verdad.
- **No sirve para:** lanzar ataques o escaneos. Las pruebas ya deben haberse hecho dentro de un alcance autorizado y unas reglas de enfrentamiento (planificación de NIST SP 800-115; pre-engagement de PTES).

## Entradas

| Entrada | Opción | Obligatoria | Notas |
|---|---|---|---|
| nmap XML (`-oX`) | `--nmap` | al menos una fuente | Usa la salida NSE de `vulners` y `smb-vuln-*` para CVEs; reglas de puertos para servicios de riesgo (RDP, SMB, Telnet, Modbus, S7, OPC UA...) |
| Nessus `.nessus` | `--nessus` | | CVE, vectores CVSS v4/v3, salida del plugin |
| Informe XML de OWASP ZAP | `--zap` | | Id de plugin y CWE → categoría; un ataque confirmado cuenta como evidencia de explotación |
| XML de issues de Burp Suite | `--burp` | | Tipo y nombre del issue → categoría; se ignoran los informativos |
| CSV de hallazgos | `--findings` | | Hallazgos manuales y de pentest. Columnas: `id,source,title,category,host,ip,port,url,cve,cwe,cvss4_vector,cvss4_score,severity,evidence,wstg,exploit_available,notes` |
| Inventario de activos CSV | `--assets` | muy recomendable | `asset_id,ip,hostname,asset_name,business_service,criticality(1-5),environment,zone,internet_facing,data_classification,owner_dept`. Una zona que contenga `OT` marca activos de planta |
| CSV de departamentos | `--org` | recomendable | `dept_code,name,lead,email,jira_component,servicenow_group` |
| Matriz RACI | `--raci` | por defecto `routing/raci_matrix.yaml` | Categoría → R/A/C/I y responsable de detección, SLAs, excepciones |
| KEV / EPSS | `--kev`, `--epss` o `--online` | recomendable | Las instantáneas hacen las ejecuciones reproducibles; `--online` descarga el feed KEV de CISA y la API EPSS de FIRST |
| Línea base | `--baseline <findings.json anterior>` | para retests | Genera `retest_delta.md/.json` |

Todas las opciones se pueden repetir (`--nmap a.xml --nmap b.xml`). Los hallazgos de herramientas distintas sobre el mismo servicio o URL se fusionan en uno solo (se combinan CVEs y fuentes).

## Cómo ejecutarla

```bash
python3 scripts/remediation_pack.py \
  --nmap scans/nmap.xml --nessus scans/scan.nessus --zap scans/zap.xml --burp scans/burp.xml \
  --findings notes/findings.csv --assets cmdb/assets.csv --org cmdb/org_departments.csv \
  --kev data/kev.json --epss data/epss.json \
  --company "ACME" --scope "Perímetro externo y portal de proveedores" --lang es --out out/
python3 scripts/selftest.py out/ --org cmdb/org_departments.csv   # control de calidad, sale con 1 si falla
```

Solo biblioteca estándar de Python 3.9+. `--lang es` o `--lang pt-BR` genera el informe y los tickets con las plantillas traducidas de `i18n/`. Los textos de corrección del catálogo están en inglés.

## Procedimiento para el agente

1. **Comprueba el alcance.** Confirma que el usuario tiene autorización sobre los objetivos de la entrada. Si falta el inventario de activos o el CSV de departamentos, pídelos. Sin ellos puedes ejecutar igualmente, pero debes avisar de que el impacto de negocio y los responsables serán genéricos.
2. **Normaliza las notas.** Pasa las notas libres del pentest a filas del CSV de hallazgos. Elige la `category` de `knowledge/catalog.json` (18 categorías), copia la evidencia del auditor tal cual y añade un vector CVSS v4.0 solo si el auditor lo dio.
3. **Ejecuta el script** con todas las fuentes disponibles, más KEV/EPSS (instantánea o `--online`).
4. **Ejecuta `selftest.py`.** Corrige las entradas y repite hasta que todas las comprobaciones pasen. No entregues un paquete con fallos. Un `WARN` (por ejemplo, KEV no cargado) debe comunicarse al usuario.
5. **Revisa el inicio del informe como lo haría un directivo.** Lee la sección 1 y las filas P1/P2. Cada hallazgo tiene una línea "Why" en lenguaje llano. Si una prioridad parece incorrecta, corrige la entrada (criticidad del activo, zona, exposición a internet) en lugar de editar la salida.
6. **Entrega**:
   - `report.md` a la dirección (la sección 1 enumera las decisiones de esta semana),
   - `tickets/<DEPT>.md` a cada responsable de departamento,
   - `jira_import.csv` / `servicenow_import.json` / `defectdojo_generic.json` a los administradores de esas herramientas,
   - `navigator/*.json` al SOC o al equipo de inteligencia de amenazas (se cargan en ATT&CK Navigator).
7. **Retest.** Tras las correcciones, vuelve a ejecutar con `--baseline out/findings.json`. Solo puede marcarse como *corregido* un hallazgo cuya herramienta y host se incluyeron en la nueva ejecución. El resto aparece como *no retestado* y sigue abierto.

## Cómo decide (resumen)

**Prioridad.** Es una decisión inspirada en SSVC, escrita para esta skill:

- *Explotación*:
  - `active`: el CVE está en CISA KEV,
  - `poc`: EPSS ≥ 0,1, o el exploit se confirmó en la prueba,
  - `none`: en otro caso.
- *Exposición*: internet, OT o interna.
- *Impacto técnico*: CVSS v4 ≥ 8,5 significa total.
- *Criticidad del activo*: de 1 a 5.

El resultado es ACT → **P1**, ATTEND → **P2**, TRACK\* → **P3** o TRACK → **P4**. Algunas categorías tienen un mínimo (las credenciales por defecto nunca bajan de P2; las brechas de detección nunca de P3). Los hallazgos KEV siempre son P1 o P2.

**SLA (días naturales)**

| Prioridad | IT | OT |
|---|---|---|
| P1 | 3 | 3 (contención); corrección definitiva mediante MOC |
| P2 | 14 | 30 |
| P3 | 45 | 90 |
| P4 | 90 | 180 |

Todos los SLA se editan en `routing/raci_matrix.yaml`. Aplica el más corto entre estos y cualquier plazo regulatorio que te afecte, como las fechas de la CISA BOD 26-04 para agencias federales de EE. UU. o el art. 33 del RGPD (72 h) para brechas de datos personales.

**Enrutado**

- Cada categoría tiene R (quién corrige), un único A (quien responde, MGMT por defecto), C, I y un responsable de detección.
- Excepciones:
  - Los activos de zona OT pasan el rol R a **OT-ENG** y exigen Gestión del Cambio (MOC) y aprobación de seguridad de procesos.
  - Los datos personales añaden **GRC-DPO** como Consultado.
  - Los activos expuestos a internet informan a **NETWORK**.
  - Los activos desconocidos reciben una nota de CMDB y se informa a IT-INFRA.

**Tickets** de cuatro tipos:

- **fix**, uno por cada departamento Responsable,
- **detection**, para el SOC en cada P1/P2 mientras la corrección está pendiente,
- **compliance**, para GRC-DPO cuando un P1/P2 afecta a datos personales,
- **governance**, un ticket MGMT para aprobar el plan.

## Paquete de salida

| Fichero | Para quién | Qué contiene |
|---|---|---|
| `report.md` | Dirección, responsables | Resumen ejecutivo, fila de KPIs, decisiones necesarias, tabla priorizada, carga por departamento, indicador de exposición inspirado en OSSTMM, detalle de hallazgos (por qué, impacto, ATT&CK/D3FEND/WSTG/CWE, pasos de corrección, verificación, detección provisional, evidencia), plan de retest, método y fuentes |
| `tickets/<DEPT>.md/.csv/.json` | Cada departamento | Solo su cola: pasos, fecha límite, RACI, criterio de cierre |
| `jira_import.csv` | Administrador de Jira | Summary, Issue Type, Priority (Highest/High/Medium/Low), Component/s, Due Date, Labels, Description |
| `servicenow_import.json` | Administrador de ServiceNow | `records[]` con urgencia/impacto, grupo de asignación, fecha límite |
| `defectdojo_generic.json` | AppSec / gestión de vulnerabilidades | Formato Generic Findings Import de DefectDojo |
| `navigator/layer_*-attack.json` | SOC / CTI | Capas de ATT&CK Navigator (Enterprise e ICS) puntuadas por prioridad |
| `findings.json` / `findings.csv` | Automatización, línea base de retest | Hallazgos normalizados con huellas e IDs estables |
| `retest_delta.md/.json` | Dirección, auditores | Corregido y verificado / sigue abierto / nuevo / no retestado |

## Ficheros de la skill

- `scripts/remediation_pack.py`: parsers, enriquecimiento, decisión, enrutado, tickets y exportaciones.
- `scripts/selftest.py`: control de calidad con 27 reglas (responsable, SLA, mapeos, pasos, reglas OT y DPO, orden, fechas, marcadores, exportaciones).
- `scripts/verify_ids.py`: valida cada identificador ATT&CK, D3FEND y WSTG del catálogo contra los datos oficiales.
- `knowledge/catalog.json`: 18 categorías de hallazgo con CWE, técnicas y mitigaciones ATT&CK, D3FEND, IDs WSTG, vector CVSS v4 por defecto, pasos de corrección, verificación y detección.
- `routing/raci_matrix.yaml`: departamentos, RACI por categoría, SLAs, excepciones. Adáptalo a tu organización.
- `templates/` y sus traducciones en `i18n/es/templates/` e `i18n/pt-BR/templates/`.
- `examples/novarefino/`: un operador de refinería ficticio con entradas en formatos reales y las salidas generadas (`run_example.sh` las reconstruye).

## Reglas para el agente

- Nunca inventes CVEs, puntuaciones CVSS, estado KEV ni valores EPSS. Usa los datos de entrada, las instantáneas o los feeds en vivo. Si un vector CVSS v4 es el valor por defecto de la categoría, el informe lo indica y el auditor debe confirmarlo.
- Mantén la evidencia del auditor sin cambios. Oculta secretos (contraseñas, tokens, números completos de tarjeta o cuenta) antes de compartir tickets fuera del equipo de seguridad.
- OT/ICS: no recomiendes escaneo activo ni parches sobre controladores en marcha. Primero contén en la frontera IT/OT y planifica la corrección definitiva para una ventana aprobada.
- Cada departamento recibe solo su fichero de tickets. El informe completo se limita a la dirección y al equipo de seguridad.
- Los identificadores de los marcos (ATT&CK, D3FEND, WSTG, CWE) son referencias. Los textos de corrección del catálogo son guía original, no copia de las normas.
