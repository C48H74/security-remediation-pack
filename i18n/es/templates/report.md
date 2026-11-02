# Paquete de remediación de seguridad: {{COMPANY}}

**Fecha del informe:** {{DATE}}  
**Alcance:** {{SCOPE}}  
**Clasificación:** CONFIDENCIAL. Compartir por departamento según necesidad de conocer.

---

## 1. Resumen ejecutivo

{{EXEC_SUMMARY}}

{{KPI_TABLE}}

### Lo que la dirección debe decidir esta semana

1. Aprobar responsables y fechas de la sección 3 (ticket `MGMT-001`).
2. Liberar capacidad para cada elemento P1: el objetivo es contenerlo en 72 horas.
3. Aceptar formalmente, con responsable nominal y fecha de caducidad, cualquier riesgo que no se corrija dentro de su SLA.

## 2. Hallazgos priorizados

La prioridad es **P1 (ACT)**, **P2 (ATTEND)**, **P3 (TRACK\*)** o **P4 (TRACK)**. Sale de una decisión inspirada en SSVC que combina evidencia de explotación (CISA KEV, FIRST EPSS, exploit público), exposición (internet / OT / interna), impacto técnico (CVSS v4.0) y criticidad de negocio del activo.

{{PRIORITY_TABLE}}

## 3. Reparto del trabajo por departamento

Cada hallazgo tiene exactamente un rol Accountable (A) y al menos un departamento Responsable (R). Mientras una corrección P1/P2 está pendiente, el SOC recibe en paralelo un ticket de detección.

{{DEPARTMENT_TABLE}}

Ficheros de tickets: `tickets/<DEPT>.md` (legible), `tickets/<DEPT>.csv` y `.json`; consolidados `jira_import.csv`, `servicenow_import.json` y `defectdojo_generic.json`.

## 4. Indicador de seguridad operativa

{{METRICS}}

## 5. Detalle de hallazgos y pasos de corrección

{{FINDINGS_DETAIL}}

## 6. Plan de retest

{{RETEST_PLAN}}

## 7. Delta del retest

{{DELTA}}

## 8. Método y fuentes

{{METHOD}}

{{SOURCES}}

Identificadores citados: MITRE ATT&CK® y MITRE D3FEND™ (© The MITRE Corporation), IDs de prueba de OWASP WSTG, CWE, CVE, CISA KEV, FIRST EPSS y CVSS v4.0. Todo el texto explicativo es original. Ver NOTICE.md en el repositorio de la skill.
