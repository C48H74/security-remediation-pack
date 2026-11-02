"""Generates the fictitious nmap XML samples (nmap.xml and nmap_retest.xml).
All addresses are RFC 5737 documentation ranges or RFC 1918 private ranges; names use .example."""
import sys
H = []
def host(ip, name, ports):
    H.append((ip, name, ports))
def port(num, svc, product="", version="", scripts=None, proto="tcp"):
    return (num, proto, svc, product, version, scripts or {})

def build(retest=False):
    H.clear()
    vpn_scripts = {} if retest else {"vulners": "cpe:/o:paloaltonetworks:pan-os:10.2.9:\n    \tCVE-2024-3400\t10.0\thttps://vulners.com/cve/CVE-2024-3400\t*EXPLOIT*"}
    host("203.0.113.10", "vpn.novarefino.example", [port(443, "https", "Palo Alto GlobalProtect", "PAN-OS 10.2.9" if not retest else "PAN-OS 10.2.9-h1", vpn_scripts)])
    host("203.0.113.11", "portal.novarefino.example", [port(443, "https", "Citrix NetScaler Gateway", "13.1-48.47",
        {"vulners": "cpe:/a:citrix:netscaler_gateway:13.1:\n    \tCVE-2023-4966\t9.4\thttps://vulners.com/cve/CVE-2023-4966\t*EXPLOIT*"})])
    host("203.0.113.20", "suppliers.novarefino.example", [port(443, "https", "nginx", "1.24.0")])
    # jump01: RDP closed to the internet after the first report (host still answers, no open ports)
    host("203.0.113.25", "jump01.novarefino.example", [] if retest else [port(3389, "ms-wbt-server", "Microsoft Terminal Services")])
    host("10.10.1.10", "dc01.corp.novarefino.example", [
        port(88, "kerberos-sec", "Microsoft Windows Kerberos"),
        port(445, "microsoft-ds", "Microsoft Windows Server 2016", "", {"vulners": "cpe:/o:microsoft:windows_server_2016:\n    \tCVE-2020-1472\t10.0\thttps://vulners.com/cve/CVE-2020-1472\t*EXPLOIT*"})])
    fs_scripts = {"smb-protocols": "dialects:\n  NT LM 0.12 (SMBv1) [dangerous, but default]\n  2.0.2\n  2.1",
                  "smb-vuln-ms17-010": "VULNERABLE:\n  Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)\n    State: VULNERABLE\n    IDs:  CVE:CVE-2017-0143"}
    host("10.10.1.20", "fs01.corp.novarefino.example", [port(445, "microsoft-ds", "Microsoft Windows Server 2008 R2", "", {} if retest else fs_scripts)])
    host("10.10.2.30", "mq01.corp.novarefino.example", [port(61616, "apachemq", "ActiveMQ OpenWire transport", "5.17.5",
        {"vulners": "cpe:/a:apache:activemq:5.17.5:\n    \tCVE-2023-46604\t10.0\thttps://vulners.com/cve/CVE-2023-46604\t*EXPLOIT*"})])
    host("10.10.2.40", "erp-db01.corp.novarefino.example", [port(1433, "ms-sql-s", "Microsoft SQL Server 2016", "13.00.5026"), port(5432, "postgresql", "PostgreSQL DB", "12.3")])
    host("10.10.2.50", "intranet.corp.novarefino.example", [port(80, "http", "Apache httpd", "2.4.49",
        {"vulners": "cpe:/a:apache:http_server:2.4.49:\n    \tCVE-2021-41773\t7.5\thttps://vulners.com/cve/CVE-2021-41773\t*EXPLOIT*\n    \tCVE-2021-42013\t9.8\thttps://vulners.com/cve/CVE-2021-42013\t*EXPLOIT*\n    \tCVE-2022-22720\t9.8\thttps://vulners.com/cve/CVE-2022-22720\n    \tCVE-2023-25690\t9.8\thttps://vulners.com/cve/CVE-2023-25690"})])
    host("10.10.2.60", "maint-app.corp.novarefino.example", [port(8080, "http", "Apache Tomcat", "9.0.31",
        {"vulners": "cpe:/a:apache:log4j:2.14.1:\n    \tCVE-2021-44228\t10.0\thttps://vulners.com/cve/CVE-2021-44228\t*EXPLOIT*"}),
        port(22, "ssh", "OpenSSH", "8.9p1", {"vulners": "cpe:/a:openbsd:openssh:8.9p1:\n    \tCVE-2024-6387\t8.1\thttps://vulners.com/cve/CVE-2024-6387\n    \tCVE-2023-48795\t5.9\thttps://vulners.com/cve/CVE-2023-48795"})])
    host("10.10.3.5", "core-sw01.corp.novarefino.example", [port(161, "snmp", "SNMPv1 server; public", "", {"snmp-info": "enterprise: ciscoSystems\n  engineIDFormat: unknown\n  community: public (read)"}, proto="udp")])
    host("10.10.3.8", "prn-ctrlroom.corp.novarefino.example", [port(21, "ftp", "vsftpd", "3.0.3"), port(23, "telnet", "Busybox telnetd")])
    host("10.10.9.99", "", [port(5900, "vnc", "VNC", "protocol 3.8")])
    host("10.20.0.10", "ews01.ot.novarefino.example", [port(3389, "ms-wbt-server", "Microsoft Terminal Services", "",
        {"vulners": "cpe:/o:microsoft:windows_7:\n    \tCVE-2019-0708\t9.8\thttps://vulners.com/cve/CVE-2019-0708\t*EXPLOIT*"})])
    host("10.20.0.21", "plc-cdu-01.ot.novarefino.example", [port(502, "modbus", "Modbus TCP")])
    host("10.20.0.22", "plc-utl-02.ot.novarefino.example", [port(102, "iso-tsap", "Siemens S7 PLC")])
    host("10.20.0.30", "opc-hist01.ot.novarefino.example", [port(4840, "opcua-tcp", "OPC UA Server")])

def xml():
    out = ['<?xml version="1.0" encoding="UTF-8"?>', '<!-- Fictitious sample. NovaRefino Demo Corp does not exist. -->',
           '<nmaprun scanner="nmap" args="nmap -sS -sU -sV --script vulners,smb-protocols,smb-vuln-ms17-010,snmp-info -p- -iL scope.txt" version="7.95">']
    for ip, name, ports in H:
        out.append('<host><status state="up" reason="syn-ack"/>')
        out.append(f'<address addr="{ip}" addrtype="ipv4"/>')
        out.append('<hostnames>' + (f'<hostname name="{name}" type="PTR"/>' if name else '') + '</hostnames><ports>')
        for num, proto, svc, prod, ver, scripts in ports:
            out.append(f'<port protocol="{proto}" portid="{num}"><state state="open" reason="syn-ack"/>'
                       f'<service name="{svc}" product="{prod}" version="{ver}" method="probed" conf="10"/>')
            for sid, o in scripts.items():
                o = o.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("\n", "&#xa;").replace("\t", "&#x9;")
                out.append(f'<script id="{sid}" output="{o}"/>')
            out.append('</port>')
        out.append('</ports></host>')
    out.append('<runstats><finished timestr="2026-10-28 10:42:00"/></runstats></nmaprun>')
    return "\n".join(out) + "\n"

build(False); open("nmap.xml", "w").write(xml())
build(True); open("nmap_retest.xml", "w").write(xml())
print("written")
