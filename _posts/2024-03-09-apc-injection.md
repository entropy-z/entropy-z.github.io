---
title: APC Queue Injection
description: >-
  In this article, I will address process injection, focusing on Asynchronous Procedure Calls (APC) with evasion techniques and some important OPSEC warnings for your upcoming engagements in Red Team.
author: Oblivion
date: 2024-03-09 20:55:00 +0800
categories: [Malware Development]
tags: []
pin: true
media_subpath: '/posts/20180809'
---
# About APC
Firstly, ``Asynchronous Procedure Calls`` ([APC](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)) are a mechanism in the Windows operating system that allows programs to perform tasks asynchronously while continuing to execute other tasks. APCs are implemented as kernel-mode routines executed in the context of a specific thread.

# Process Injection - Shellcode Injection x Mapping Injection
One of the major advantages of using APCs is that we do not need to rely on highly suspicious WINAPIs like [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread). Two uses of it and their differences in process injection:
Shellcode Injection = [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) + [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) —  This way, it will allocate private memory in a remote process. A key observation regarding this process injection is that a ``Cleanup RWX`` can be performed to clear the memory protection and avoid leaving it as ``RWX``. Simply allocate memory with ``PAGE_READWRITE``, copy the payload into the memory, change it to ``PAGE_EXECUTE_READ``, and create the thread. The biggest issue is here, with the [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) for create thread. 
Mapping Injection = [CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga) + [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile) — It has an advantage over Shellcode Injection because it uses mapped memory with [CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga), which in itself is less targeted by malware. [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) uses private memory, which is already highly targeted by defense solutions. However, its memory protection poses an issue as it cannot be changed, so we are forced to use ``RWX``.

# Disadvantage of [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)
Both require the use of [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread), and therein lies the problem. Even if you employ techniques for evading EDR hooking such as ``NTLL Unhooking`` or ``Indirect Syscalls``, it will not be sufficient for you to stay undetected. The issue is that these functions can still be detected through process and thread monitoring, event logs, and a myriad of other methods.

# Payload Execution - APC Injection
The APC (Asynchronous Procedure Call) injection method for payload execution utilizes [QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc), differing from previous techniques. Its evasive nature stems from not being detected by methods capable of identifying the [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread). This is because there is no way to query APC Queue or have any way of visualizing them.
However, despite its advantages, there is a drawback to APC Injection. In order for [QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) to work and queue the payload into the thread, it requires a thread that is alertable or suspended. This can be a bit of a challenge, due to the fact that there is no way to check which threads are in an alert state and which are not, but I'll now demonstrate some ways to put this technique into practice.

# Two Ways to use APC Queue
The ``FIRST WAY`` is by using Early Bird APC Injection, the implementation will be as follows: 
1. We create a process with the flags ``EXTENDED_STARTUPINFO_PRESENT`` and ``DEBUG_PROCESS`` with [CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa). 
2. We will use ``Spoofing PPID`` to start the process in a specific parent process. 
3. Memory allocation in a remote process with [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) and writing to this memory with [WriteProcessMemory](). 
4. We will enqueue the payload with [QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) and stop the debugging of the remote process using DebugActiveProcessStop, resuming its 
threads and executing the payload.

Now let's move on to the explanation. The ``EXTENDED_STARTUPINFO_PRESENT`` flag is used to give us more privileges over the created process, which is useful for the ``Spoofing PPID`` we will be performing. DEBUG_PROCESS is an alternative to ``CREATE_SUSPENDED``, and it will make the remote process be debugged by our process, placing a breakpoint at its entrypoint.

About ``Spoofing PPID``, with the ``EXTENDED_STARTUPINFO_PRESENT`` flag set during the process creation, we will access the ``lpAttributeList`` member within the [STARTUPINFOEXA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa) structure, updating it with UpdateProcThreadAttribute to set the attributes defining the ``PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`` flag, thus allowing us to specify the parent process of the thread. It can also be used Process Argument Spoofing depending on how you are going to do it.
This part is quite simple: we will allocate memory in the remote process created with ``PAGE_READWRITE`` permission and write the payload with [WriteProcessMemory](). Then, we will change the protection again, but this time to ``PAGE_EXECUTE_READ``. Remember the "Cleanup RWX" I mentioned earlier; memories with RWX permissions can attract attention.
Finally, we will enqueue the payload with [QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc), passing to it the thread identifier and the address of the payload previously allocated with [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex). Then, we stop the debug with [DebugActiveProcessStop](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop), and voilà, the payload is executed. 😁

----------

The ``SECOND WAY`` is to pay to see and try to use the APC in all threads of a process. Something interesting is that browsers in general will almost certainly work, the problem is, we may end up receiving several connections in our C2 because it may happen that several threads are in an alert state. One solution for this is Execution Control, basically it's about using ``Mutexes``, ``Semaphores``, ``Events`` and others. Another solution is configuring the infrastructure of your C2, something we will not discuss at this moment. The implementation will be as follows:

1. Use [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) in target process, [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) to allocate memory in the remote process with RW permissions, write to the allocated memory with [WriteProcessMemory]() with your payload, and change the permissions to ``RX`` with [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex).

2. Perform a thread enumeration using CreateToolhelp32Snapshotor NtQuerySystemInformation, whichever you prefer, and then capture the identifier for the desired process and then retrieve the identifiers of the threads.

3. Utilize [QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) to enqueue your payload.

# Conclusion
The advantages, disadvantages, and methods of executing an evasive APC injection were explained. A reader with a certain level of programming and Windows knowledge will be able to apply the techniques properly explained without much difficulty, even though it is a theoretical article. However, I leave here an example of a repository on my GitHub called [Early_Bird_Injection](https://github.com/Entropy-z/Early_Bird_Injection) with first implementation.

Certainly, this raw technique as it stands may still be detected by some solutions through API Hooking. There are other functionalities to add, such as anti-analysis mechanisms and bypassing ``API Hooking``, for example, ``NTDLL Unhooking`` and ``Syscalls``. These will be two topics for future articles in this journal. Any questions or suggestions, feel free to contact me. Until the next article! 🙃