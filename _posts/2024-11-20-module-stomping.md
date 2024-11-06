---
title: "Evading detection in memory - Pt 2: Improving Module Stomping + Sleep Obfuscation"
description: In this chapter we will cover another approach that helps against memory detection called module stomping, we will talk about IOCs, and how to improve the technique.
author: Oblivion
date: 2024-11-20 11:33:00 +0800
categories: [Malware Development]
tags: []
pin: true
math: true
mermaid: true
---
As mentioned in the previous blog post [Evading detection in memory - Pt 1: Sleep Obfuscation - Foliage](https://oblivion-malware.xyz/posts/sleep-obf-foliage/), memory detections focus on private memory regions, RX memory regions, and the thread's call stack.

The **Module Stomping** technique involves overwriting the RX (read-execute) memory region of a DLL loaded in memory with shellcode, with the goal of evading detection based on private memory analysis. This method also avoids concerns about the *call stack*, as the shellcode is executed from a memory region that is supported. However, a challenge with this process is that, when using sRDI (Self-Reflective Data Injection) C2 beacons, the memory content will be reflected into a new region, causing an overwrite of a legitimate DLL area. This results in visible modifications, which can be easily detected, generating IOCs (Indicators of Compromise).

The solution to this problem involves using a **reflective loader** in conjunction with the main loader, in my case, I'll use a shellcode that doesn't reflect. However, even with this approach, the overwritten memory area can still be perceptible. To enhance this technique and reduce the likelihood of detection, we propose the following process:

1. **Allocate Mapped RW Memory**: First, we allocate two *Mapped RW* memory regions, called **Memory Mapped A** and **Memory Mapped B**.
   
2. **Backup the DLL**: We back up the DLL that will be overwritten by storing it in **Memory Mapped A**, preserving the integrity of the original DLL.

3. **Write the Encrypted Beacon**: The encrypted beacon (shellcode) is then written into **Memory Mapped B**, a secure memory area for the payload.

4. **Restore During "Sleep"**: During the process's "sleep" time (inactivity), the overwritten DLL is restored to its original position in memory from the backup in **Memory Mapped A**. This step ensures that while the beacon is inactive, the memory will appear legitimate, containing the original DLL data.

5. **Prepare for Execution**: When it's time to execute the beacon, the memory is overwritten again, and the beacon is loaded back into **Memory Mapped B**, replacing the restored DLL.

In this way, the DLL's memory will appear legitimate during the beacon's inactivity period, with a very brief window of visibility only during the beacon's execution. This minimizes the chances of detection, as the memory changes occur only during the active execution phase and are quickly reverted once the beacon has finished executing.

# Reference and credits
- [https://bruteratel.com/release/2023/03/19/Release-Nightmare/](https://bruteratel.com/release/2023/03/19/Release-Nightmare/)
