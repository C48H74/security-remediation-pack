#!/usr/bin/env bash
# Regenerates the example package for the fictitious NovaRefino Demo Corp.
# Run from anywhere: bash examples/novarefino/run_example.sh
set -euo pipefail
cd "$(dirname "$0")"
PACK=../../scripts/remediation_pack.py
COMMON=(--assets input/assets.csv --org input/org_departments.csv --kev input/kev_snapshot.json --epss input/epss_snapshot.json
        --company "NovaRefino Demo Corp (fictitious)")
rm -rf output output_retest output_es output_pt-BR
# 1) first assessment: all sources
python3 "$PACK" --nmap input/nmap.xml --nessus input/scan.nessus --zap input/zap.xml --burp input/burp.xml --findings input/findings.csv "${COMMON[@]}" \
  --scope "External perimeter 203.0.113.0/24, corporate 10.10.0.0/16, OT 10.20.0.0/24 (read-only), supplier portal" \
  --date 2026-11-02 --out output
# 2) one week later: network rescan only, compared with the first run
python3 "$PACK" --nmap input/nmap_retest.xml "${COMMON[@]}" --scope "Network rescan after first P1 fixes (nmap only)" \
  --date 2026-11-09 --baseline output/findings.json --out output_retest
# 3) same assessment rendered with Spanish and Brazilian Portuguese templates
for L in es pt-BR; do
  python3 "$PACK" --nmap input/nmap.xml --nessus input/scan.nessus --zap input/zap.xml --burp input/burp.xml --findings input/findings.csv "${COMMON[@]}" \
    --scope "$( [ "$L" = es ] && echo "Perímetro externo, red corporativa, OT (solo lectura), portal de proveedores" || echo "Perímetro externo, rede corporativa, OT (somente leitura), portal de fornecedores")" --date 2026-11-02 --lang "$L" --out "output_$L"
done
# 4) quality gate
for D in output output_retest output_es output_pt-BR; do python3 ../../scripts/selftest.py "$D" --org input/org_departments.csv | head -1; done
