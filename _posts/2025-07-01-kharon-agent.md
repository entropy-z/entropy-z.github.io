---
title: "Kharon Agent: Demonstration of Advanced Post-Exploitation"
description: "Presentation of my new project of an agent for C2 (Mythic) that has advanced post-exploit capabilities and evasion features."
author: Oblivion
date: 2025-07-01 11:33:00 +0800
categories: [Malware Development]
tags: []
pin: true
math: true
mermaid: true
image:
  path: /commons/kharon-1/kharon.png
---

# Overview
Kharon has several post-exploitation capabilities that enable the operator to perform operations in an evasive manner. The agent code has some key and important things for its operation, the rest of the codes and functions are executed via stager in memory using BOF and later I will migrate to shellcode when Fork&Run is used. The agent is very flexible and much of its behavior can be controlled during execution using the 'Config' command. 

# Key Features
- Unmanaged Powershell execution without use Invoke-Expression using my own custom dotnet.


- .NET in memory execution tested against defense solutions like Crowdstrike, SentinelOne, Elastic and Microsoft Defender for Endpoint.

![dotnet_bypass_crowdstrike](../commons/kharon-1/crowdstrike_output_from_seatbelt.jpg)

![dotnet_bypass_elastic](../commons/kharon-1/elastic_dotnet_bypass.png)

- Shellcode in memory execution, its can be customized behavior in config options.
- Process creation with PPID spoof capability and output recovery. 
- Screenshot.
- Communication encrypted with loky encrypt and protect the key encoding pointer with process cookie.
- Token Manipulation.
- Kerberos interaction by [Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) from [Ralf](https://github.com/RalfHacker).
- SCM interaction.
- Registry interaction.

## Evasion
- Usa Hardware Breakpoint para bypass de AMSI/ETW para execucao de .NET e Powershell execute in memory. 
- Call Stack Spoofing for bypassing stack tracing detections.
- Sleep Obfuscation to hide beacon in memory.
- Heap Obfuscation during sleep, all heal allocation will be obfuscated during beacon sleep using XOR.
- Stack duplication during sleep.
- Indirect Syscalls.
- BOF API calls hooking applying the config choicce like stack spoof and indirect syscall (with options you dont need spoof the call in your BOF).