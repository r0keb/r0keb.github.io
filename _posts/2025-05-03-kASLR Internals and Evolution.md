---
title: "kASLR Internals and Evolution"
date: 2025-05-03 11:39:03 +/-0200
categories: [Research, Windows]
tags: [kaslr]     # TAG names should always be lowercase
---

Good morning! Today’s blog won’t be too long, but that doesn’t mean it’s not important.

Perhaps one of the oldest mitigations implemented in all software is ASLR (Address Space Layout Randomization). This mitigation randomizes the address range within a given piece of software, aiming to eliminate static addresses that attackers could exploit to perform certain functionality.

As expected, the Windows kernel also implements this mitigation, `kASLR`, which has been continuously improved with each new version.

This blog combines a bit of research differentiating the code of `Nt` functions available to a _medium integrity process_, which used to help bypass kASLR. We’ll also take a look at the subsequent patch and how it was implemented.

## kASLR (Pre `24H2`)

Prior to version `24H2`, it was possible to call `Nt` functions from User mode in a very straightforward manner. Perhaps the most commonly used was [NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation), which is represented as follows:
```cpp
__kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);
```

According to Microsoft: 
```
"[**NtQuerySystemInformation** may be altered or unavailable in future versions of Windows. Applications should use the alternate functions listed in this topic.]

Retrieves the specified system information."
```

And indeed, that turned out to be the case — but let’s not get ahead of ourselves.

**`NtQuerySystemInformation`** literally returned KM addresses or data just like that — all you had to do was pass one of the following [flags](https://github.com/waleedassar/RestrictedKernelLeaks):
```cpp
List of KASLR bypass techniques in Windows 10 kernel.
1. ZwQuerySystemInformation/SystemModuleInformation
2. ZwQuerySystemInformation/SystemModuleInformationEx
3. ZwQuerySystemInformation/SystemProcessInformation
4. ZwQuerySystemInformation/SystemExtendedProcessInformation
5. ZwQuerySystemInformation/SystemSessionProcessInformation
6. ZwQuerySystemInformation/SystemLocksInformation
7. ZwQuerySystemInformation/SystemHandleInformation
8. ZwQuerySystemInformation/SystemExtendedHandleInformation
9. ZwQuerySystemInformation/SystemObjectInformation
10. ZwQuerySystemInformation/SystemBigPoolInformation
11. ZwQuerySystemInformation/SystemSessionBigPoolInformation
12. ZwQueryInformationProcess/ProcessHandleTracing
13. ZwQueryInformationProcess/ProcessWorkingSetWatch
14. ZwQueryInformationProcess/ProcessWorkingSetWatchEx
```

The flag values are the following:
```cpp
//0x4 bytes (sizeof)
enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
...
    SystemModuleInformation = 11,
...
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
...
	SystemExtendedProcessInformation = 57,
...
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
...
    SystemModuleInformationEx = 77,
...
    MaxSystemInfoClass = 248
};
```
These are some of the most important flags. You can find all available flags at [flags](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_SYSTEM_INFORMATION_CLASS).

To execute this wonderful function, it's as simple as creating a function pointer, getting the address of **`NtQuerySystemInformation`** from `ntdll.dll`, and casting it for later execution.

Since this is a semi-documented function, some structures might not be available on MSDN, so we’ll have to look for them on GitHub or the internet.

Let’s look at the most basic — and most common — example. On an older version of Windows 10 (`Windows 10 1507`), we’ll retrieve the base address of `ntoskrnl.exe` using this function. For this, we need the `SystemModuleInformation` flag, which is decimal value 11, and the structure **PSYSTEM_MODULE_INFORMATION**, which we can get thanks to this great [GitHub repository](https://github.com/sam-b/windows_kernel_address_leaks/blob/master/NtQuerySysInfo_SystemModuleInformation/NtQuerySysInfo_SystemModuleInformation/NtQuerySysInfo_SystemModuleInformation.cpp).

![](imgs/blog/3kASLRInternalsandEvolution/20250503221159.png)

We’ll verify the address of `ntoskrnl.exe` using WinDbg:
```WinDbg
1: kd> lm m nt
Browse full module list
start             end                 module name
fffff800`b6a7d000 fffff800`b72cf000   nt         (pdb symbols)          c:\symbols\ntkrnlmp.pdb\C68EE22FDCF6477895C54A862BE165671\ntkrnlmp.pdb
```
Indeed, in this case the address would be `0xfffff800b6a7d000`.

Here’s what the code looks like:
```cpp
#include <stdio.h>
#include <windows.h>


//
// MODULE INFOMATION
//
#define MAXIMUM_FILENAME_LENGTH 255 

//0x4 bytes (sizeof)
enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11
};


//
// MODULE INFORMATION STRUCTURES
//
typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
#ifdef _WIN64
    ULONG				Reserved3;
#endif
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 w018;
    WORD                 NameOffset;
    CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;




//
// FUNCTION POINTER
//
typedef NTSTATUS(*_NtQuerySystemInformation)(
    _SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                     SystemInformation,
    ULONG                     SystemInformationLength,
    PULONG                    ReturnLength
    );


int main() {

    // cast the pointer to NtQuerySystemInformation inside ntdll.dll to NtQuerySystemInformation function pointer
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (NtQuerySystemInformation == nullptr) {
        printf("\n[ERROR] Error getting the \"NtQuerySystemInformation\" function pointer: %d\n", GetLastError());
        return -1;
    }

    NTSTATUS Status = 1;
    ULONG ReturnLength = 0;
    NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &ReturnLength);
    if (ReturnLength == 0) {
        printf("\n[ERROR] Error getting the length to \"SystemModuleInformation\"\n");
        return -1;
    }

    PSYSTEM_MODULE_INFORMATION SystemModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(nullptr, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    Status = NtQuerySystemInformation(SystemModuleInformation, SystemModuleInfo, ReturnLength, &ReturnLength);
    if (Status != 0) {
        printf("\n[ERROR] Error calling \"NtQuerySystemInformation\" for module info: 0x%0.16X\n", Status);
        return -1;
    }

    printf("\n[kASLR Lab]:");
    printf("\n\t\"SystemModuleInformation\" flag\n\t\t");
    printf("[Name] \"%s\"\n\t\t[Address] 0x%p\n\n\t\t", SystemModuleInfo[0].Modules->Name, SystemModuleInfo[0].Modules->ImageBaseAddress);
    printf("[Name] \"%s\"\n\t\t[Address] 0x%p\n\n\t\t", SystemModuleInfo[1].Modules->Name, SystemModuleInfo[1].Modules->ImageBaseAddress);
    printf("[Name] \"%s\"\n\t\t[Address] 0x%p\n\n\t\t", SystemModuleInfo[2].Modules->Name, SystemModuleInfo[2].Modules->ImageBaseAddress);

    // SystemModuleInfo cleanup
    VirtualFree(SystemModuleInfo, ReturnLength, MEM_RELEASE);
    SystemModuleInfo = nullptr;
    ReturnLength = 0;


    return 0;
}
```
As we can see, we first make a call to get the size of the structure we’re going to allocate. For that, we pass a pointer to `ReturnLength`, which will store the appropriate size so we can allocate memory on the heap for the **SYSTEM_MODULE_INFORMATION** structure. This two-call pattern, first for the size and the second call to fill the data structure.

Now let’s look at a variation of the code. We’ll request more Kernel Mode data using the same function. This time, we’ll use two more flags.

![](imgs/blog/3kASLRInternalsandEvolution/20250503222612.png)

As shown, we request `SystemModuleInformation`, `SystemExtendedProcessInformation`, and `SystemExtendedHandleInformation`.

The code would be:
```cpp
#include <stdio.h>
#include <windows.h>


//
// MODULE INFOMATION
//
#define MAXIMUM_FILENAME_LENGTH 255 

//0x4 bytes (sizeof)
enum _SYSTEM_INFORMATION_CLASS
{
    SystemModuleInformation = 11,
    SystemExtendedProcessInformation = 57,
    SystemExtendedHandleInformation = 64
};



//
// MODULE INFORMATION STRUCTURES
//
typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
#ifdef _WIN64
    ULONG				Reserved3;
#endif
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 w018;
    WORD                 NameOffset;
    CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;



//
// EXTENDED PROCESS INFOMATION STRUCTURES
//
typedef LONG       KPRIORITY;
typedef struct _CLIENT_ID {
    DWORD          UniqueProcess;
    DWORD          UniqueThread;
} CLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT         Length;
    USHORT         MaximumLength;
    PWSTR          Buffer;
} UNICODE_STRING;

//from http://boinc.berkeley.edu/android-boinc/boinc/lib/diagnostics_win.h
typedef struct _VM_COUNTERS {
    // the following was inferred by painful reverse engineering
    SIZE_T		   PeakVirtualSize;	// not actually
    SIZE_T         PageFaultCount;
    SIZE_T         PeakWorkingSetSize;
    SIZE_T         WorkingSetSize;
    SIZE_T         QuotaPeakPagedPoolUsage;
    SIZE_T         QuotaPagedPoolUsage;
    SIZE_T         QuotaPeakNonPagedPoolUsage;
    SIZE_T         QuotaNonPagedPoolUsage;
    SIZE_T         PagefileUsage;
    SIZE_T         PeakPagefileUsage;
    SIZE_T         VirtualSize;		// not actually
} VM_COUNTERS;

typedef enum _KWAIT_REASON
{
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrEventPair = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    Spare2 = 21,
    Spare3 = 22,
    Spare4 = 23,
    Spare5 = 24,
    WrCalloutStack = 25,
    WrKernel = 26,
    WrResource = 27,
    WrPushLock = 28,
    WrMutex = 29,
    WrQuantumEnd = 30,
    WrDispatchInt = 31,
    WrPreempted = 32,
    WrYieldExecution = 33,
    WrFastMutex = 34,
    WrGuardedMutex = 35,
    WrRundown = 36,
    MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitchCount;
    ULONG ThreadState;
    KWAIT_REASON WaitReason;
#ifdef _WIN64
    ULONG Reserved[4];
#endif
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
    SYSTEM_THREAD_INFORMATION ThreadInfo;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32StartAddress;
    PVOID TebAddress; /* This is only filled in on Vista and above */
    ULONG Reserved1;
    ULONG Reserved2;
    ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;
typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    ULONG ProcessId;
    ULONG InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID PageDirectoryBase;
    VM_COUNTERS VirtualMemoryCounters;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
    SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_EXTENDED_PROCESS_INFORMATION, * PSYSTEM_EXTENDED_PROCESS_INFORMATION;





//
// EXTENDED HANDLE INFOMATION STRUCTURES
//
typedef struct _SYSTEM_HANDLE
{
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;




//
// FUNCTION POINTER STRUCTURES
//
typedef NTSTATUS (*_NtQuerySystemInformation)(
	_SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                     SystemInformation,
	ULONG                     SystemInformationLength,
	PULONG                    ReturnLength
);

int main() {

    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (NtQuerySystemInformation == nullptr) {
        printf("\n[ERROR] Error getting the \"NtQuerySystemInformation\" function pointer: %d\n", GetLastError());
        return -1;
    }

    NTSTATUS Status = 1;
    ULONG ReturnLength = 0;
    NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &ReturnLength);
    if (ReturnLength == 0) {
        printf("\n[ERROR] Error getting the length to \"SystemModuleInformation\"\n");
        return -1;
    }

    PSYSTEM_MODULE_INFORMATION SystemModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(nullptr, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    Status = NtQuerySystemInformation(SystemModuleInformation, SystemModuleInfo, ReturnLength, &ReturnLength);
    if (Status != 0) {
        printf("\n[ERROR] Error calling \"NtQuerySystemInformation\" for module info: 0x%0.16X\n", Status);
        return -1;
    }

	printf("\n[kASLR Lab]:");
    printf("\n\t\"SystemModuleInformation\" flag\n\t\t");
    printf("[Name] \"%s\"\n\t\t[Address] 0x%p\n\n\t\t", SystemModuleInfo[0].Modules->Name, SystemModuleInfo[0].Modules->ImageBaseAddress);
    printf("[Name] \"%s\"\n\t\t[Address] 0x%p\n\n\t\t", SystemModuleInfo[1].Modules->Name, SystemModuleInfo[1].Modules->ImageBaseAddress);
    printf("[Name] \"%s\"\n\t\t[Address] 0x%p\n\n\t\t", SystemModuleInfo[2].Modules->Name, SystemModuleInfo[2].Modules->ImageBaseAddress);

    // SystemModuleInfo cleanup
    VirtualFree(SystemModuleInfo, ReturnLength, MEM_RELEASE);
    SystemModuleInfo = nullptr;
    ReturnLength = 0;





    NtQuerySystemInformation(SystemExtendedProcessInformation, nullptr, 0, &ReturnLength);
    if (ReturnLength == 0) {
        printf("\n[ERROR] Error getting the length to \"SystemExtendedProcessInformation\"\n");
        return -1;
    }
    PSYSTEM_EXTENDED_PROCESS_INFORMATION SysProcessInfoEx = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)VirtualAlloc(nullptr, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    Status = NtQuerySystemInformation(SystemExtendedProcessInformation, SysProcessInfoEx, ReturnLength, &ReturnLength);
    if (Status != 0) {
        printf("\n[ERROR] Error calling \"NtQuerySystemInformation\" for process info Ex: 0x%0.16X\n", Status);
        return -1;
    }

    printf("\n\t\"SystemExtendedProcessInformation\" flag\n\t\t");
    printf("[Main Thread StackBase] 0x%p\n\t\t", SysProcessInfoEx->Threads[0].StackBase);
    printf("[Main Thread StackLimit] 0x%p\n\n\t\t", SysProcessInfoEx->Threads[0].StackLimit);
    // SysProcessInfoEx cleanup
    VirtualFree(SysProcessInfoEx, ReturnLength, MEM_RELEASE);
    SysProcessInfoEx = nullptr;
    ReturnLength = 0;




    PSYSTEM_HANDLE_INFORMATION_EX SysHandleInfoEx = nullptr;
    Status = 1;
    ReturnLength = 1;
    while (Status != 0) {

        if (SysHandleInfoEx != nullptr) {
            VirtualFree(SysHandleInfoEx, ReturnLength, MEM_RELEASE);
            SysHandleInfoEx = nullptr;
        }

        ReturnLength *= 2;

        SysHandleInfoEx = (PSYSTEM_HANDLE_INFORMATION_EX)VirtualAlloc(nullptr, ReturnLength, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        ULONG length = 0;
        Status = NtQuerySystemInformation(SystemExtendedHandleInformation, SysHandleInfoEx, ReturnLength, &length);


    }


    printf("\n\t\"SystemHandleInformation\" flag\n\t\t");
    printf("[Handle Count] %d\n\t\t", SysHandleInfoEx->HandleCount);

    for (unsigned int i = 0; i < SysHandleInfoEx->HandleCount; i++) {

        if ((DWORD)SysHandleInfoEx->Handles[i].UniqueProcessId == GetProcessId(((HANDLE)-1))) {
            printf("[PROC ID] %d\n\t\t", SysHandleInfoEx->Handles[i].UniqueProcessId);
            printf("[Handle Value] 0x%p\n\t\t", SysHandleInfoEx->Handles[i].HandleValue);
            printf("[ObjectValue] 0x%p\n\t\t", SysHandleInfoEx->Handles[i].ObjectTypeIndex);
            printf("[Kernel Object (_KTHREAD...)] 0x%p\n\t\t", SysHandleInfoEx->Handles[i].Object);
            break;
        }

    }

    // SysHandleInfoEx cleanup
    VirtualFree(SysHandleInfoEx, ReturnLength, MEM_RELEASE);
    SysHandleInfoEx = nullptr;
    ReturnLength = 0;



    return 0;
}
```
The main thing to highlight in this code is how we obtain `ReturnLength` when requesting `SystemExtendedHandleInformation`. That’s because the previously mentioned method fails here, so we keep allocating more and more space, depending on whether the **`NtQuerySystemInformation`** call returns **STATUS_SUCCESS**. If not, the loop repeats.

Ultimately, these two examples demonstrate that it's indeed possible to obtain very valuable information from User Mode, useful for later exploitation.

Now let’s see how this function actually works.

### NtQuerySystemInformation Internals

Here’s the pseudo-code of the function in IDA:
```cpp
NTSTATUS __stdcall NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength)
{
  __int16 *p_Group; // rdx
  __int64 v7; // r8
  NTSTATUS result; // eax
  __int16 Group; // [rsp+40h] [rbp+8h] BYREF

  if ( SystemInformationClass >= SystemWow64SharedInformationObsolete
    && SystemInformationClass < SystemProcessorIdleCycleTimeInformation
    || SystemInformationClass < SystemProcessorPerformanceInformation )
  {
LABEL_3:
    p_Group = 0;
    v7 = 0;
    return ExpQuerySystemInformation(
             SystemInformationClass,
             p_Group,
             v7,
             SystemInformation,
             SystemInformationLength,
             ReturnLength);
  }
  else
  {
    switch ( SystemInformationClass )
    {
      case SystemProcessorPerformanceInformation:
      case SystemInterruptInformation:
      case SystemPowerInformationNative:
      case SystemProcessorPowerInformation:
      case SystemProcessorIdleCycleTimeInformation:
      case SystemPrefetchPathInformation|SystemPathInformation:
      case SystemPrefetchPathInformation|SystemLocksInformation:
      case SystemStackTraceInformation|0x80:
        v7 = 2;
        Group = KeGetCurrentPrcb()->Group;
        p_Group = &Group;
        return ExpQuerySystemInformation(
                 SystemInformationClass,
                 p_Group,
                 v7,
                 SystemInformation,
                 SystemInformationLength,
                 ReturnLength);
      case SystemLogicalProcessorInformation:
        v7 = 2;
        Group = 0;
        p_Group = &Group;
        return ExpQuerySystemInformation(
                 SystemInformationClass,
                 p_Group,
                 v7,
                 SystemInformation,
                 SystemInformationLength,
                 ReturnLength);
      case MaxSystemInfoClass|SystemFlagsInformation:
      case SystemVerifierFaultsInformation|SystemDpcBehaviorInformation:
        result = -1073741821;
        break;
      default:
        goto LABEL_3;
    }
  }
  return result;
}
```
As we can see, it’s just a wrapper for **`ExpQuerySystemInformation`**, which is a massive function...

![](imgs/blog/3kASLRInternalsandEvolution/20250503224606.png)

Due to the size of the function, let’s focus on example **11**, which corresponds to `SystemModuleInformation`.

![](imgs/blog/3kASLRInternalsandEvolution/20250504175119.png)

As shown, there's a call to **`ExIsRestrictedCaller()`**, which looks like this:
```cpp
_BOOL8 __fastcall ExIsRestrictedCaller(char a1)
{
  BOOLEAN v1; // bl
  _BOOL8 result; // rax
  struct _SECURITY_SUBJECT_CONTEXT SubjectContext; // [rsp+50h] [rbp-28h] BYREF
  NTSTATUS AccessStatus; // [rsp+80h] [rbp+8h] BYREF
  ACCESS_MASK GrantedAccess; // [rsp+88h] [rbp+10h] BYREF

  result = 0;
  if ( a1 )
  {
    SeCaptureSubjectContextEx(KeGetCurrentThread(), KeGetCurrentThread()->ApcState.Process, &SubjectContext);
    v1 = SeAccessCheck(
           SeMediumDaclSd,
           &SubjectContext,
           0,
           0x20000u,
           0,
           0,
           (PGENERIC_MAPPING)&ExpRestrictedGenericMapping,
           1,
           &GrantedAccess,
           &AccessStatus);
    SeReleaseSubjectContext(&SubjectContext);
    if ( v1 != 1 || AccessStatus < 0 )
      return 1;
  }
  return result;
}
```
This function checks and returns info to **`ExpQuerySystemInformation`**, but in `24H2` there was a major change.

## kASLR (Post `24H2`)
Now let’s take a look at **`NtQuerySystemInformation`** after `24H2`.

To test this, we’ll run both programs again. But spoiler alert: neither of them is going to work.

![](imgs/blog/3kASLRInternalsandEvolution/20250503225300.png)

![](imgs/blog/3kASLRInternalsandEvolution/20250503225418.png)

And sure enough, no addresses are returned. Why is that?

### NtQuerySystemInformation Internals
To start, we have **`NtQuerySystemInformation()`** just like in version `1507`:
```cpp
NTSTATUS __fastcall NtQuerySystemInformation(int a1, _QWORD *a2, ULONG a3, ULONG *a4)
{
  __int16 *p_PrimaryGroupThread; // rdx
  ULONG *v6; // r11
  int v8; // r10d
  int v9; // r8d
  __int16 PrimaryGroupThread; // [rsp+40h] [rbp+8h] BYREF

  p_PrimaryGroupThread = 0;
  v6 = a4;
  PrimaryGroupThread = 0;
  v8 = a1;
  switch ( a1 )
  {
    case 8:
    case 23:
    case 42:
    case 61:
    case 83:
    case 100:
    case 108:
    case 141:
      PrimaryGroupThread = KeQueryPrimaryGroupThread(KeGetCurrentThread());
      goto LABEL_5;
    case 73:
LABEL_5:
      p_PrimaryGroupThread = &PrimaryGroupThread;
      v9 = 2;
      return ExpQuerySystemInformation(v8, (__int64)p_PrimaryGroupThread, v9, a2, a3, v6);
    case 107:
    case 121:
    case 180:
    case 210:
    case 211:
    case 222:
    case 231:
    case 238:
    case 239:
    case 240:
      return 0xC0000003;
    default:
      v9 = 0;
      return ExpQuerySystemInformation(v8, (__int64)p_PrimaryGroupThread, v9, a2, a3, v6);
  }
}
```

So far, nothing new, the same call to **`ExpQuerySystemInformation`**. But if we dig into that function:

![](imgs/blog/3kASLRInternalsandEvolution/20250504175622.png)

And then check what’s inside...
```cpp
__int64 __fastcall ExIsRestrictedCaller(KPROCESSOR_MODE a1, _DWORD *a2)
{
  unsigned int v2; // edi
  BOOLEAN v5; // bl
  struct _SECURITY_SUBJECT_CONTEXT SubjectContext; // [rsp+50h] [rbp-28h] BYREF
  NTSTATUS AccessStatus; // [rsp+80h] [rbp+8h] BYREF
  ACCESS_MASK GrantedAccess; // [rsp+88h] [rbp+10h] BYREF

  v2 = 0;
  AccessStatus = 0;
  GrantedAccess = 0;
  memset(&SubjectContext, 0, sizeof(SubjectContext));
  if ( a2 )
    *a2 = 0;
  if ( !a1 )
    return 0;
  if ( a2 && (unsigned int)Feature_RestrictKernelAddressLeaks__private_IsEnabledDeviceUsageNoInline() )
    *a2 = SeSinglePrivilegeCheck(SeDebugPrivilege, a1) == 0;
  SeCaptureSubjectContext(&SubjectContext);
  v5 = SeAccessCheck(
         SeMediumDaclSd,
         &SubjectContext,
         0,
         0x20000u,
         0,
         0,
         (PGENERIC_MAPPING)&ExpRestrictedGenericMapping,
         1,
         &GrantedAccess,
         &AccessStatus);
  SeReleaseSubjectContext(&SubjectContext);
  if ( !v5 )
    return 1;
  LOBYTE(v2) = AccessStatus < 0;
  return v2;
}
```
We see that **a2** is checked using **`SeSinglePrivilegeCheck`** to verify the `SeDebugPrivilege`. We can also confirm this by setting a breakpoint at `nt!ExpQuerySystemInformation+0x770`, which is the memory address where we call **`ExIsRestrictedCaller`**, just before **`ExpQueryModuleInformation`** is executed:

![](imgs/blog/3kASLRInternalsandEvolution/20250504182836.png)

```WinDbg
0: kd> bl
     0 e Disable Clear  fffff807`d9fb2ed0     0001 (0001) nt!ExpQuerySystemInformation+0x770
```
Basically, it performs checks, and if `SeDebugPrivilege` is enabled, **`NtQuerySystemInformation()`** runs without restrictions. Otherwise, the execution is limited, as shown in this line:
```cpp
...
  if ( a2 && (unsigned int)Feature_RestrictKernelAddressLeaks__private_IsEnabledDeviceUsageNoInline() )
    *a2 = SeSinglePrivilegeCheck(SeDebugPrivilege, a1) == 0;
...
```
Ultimately, the option of calling this API to resolve Kernel Mode addresses is no longer viable, unless the goal is an Admin-to-Kernel escalation, in which case it still applies. However, since we can no longer rely on this advantage, the question remains: how can we bypass the increasingly stubborn kASLR?

That question will be addressed in future editions of this blog.
Thank you for reading.

## Closing
As previously mentioned, this blog post is relatively brief. It presents a concise piece of research on how recent changes have impacted the once-common use of **`NtQuerySystemInformation()`** for retrieving privileged Kernel Mode addresses.

Good morning, and in case I don’t see ya: Good afternoon, good evening, and good night!
