---
title: "Tp-Link Router Deep Research"
date: 2025-11-15 11:39:03 +/-0200
categories: [Hardware, Research]
tags: [router]     # TAG names should always be lowercase
---

Good morning! In this blog I would like to delve into hardware hacking and start expanding my learning.

To begin, in today's blog we go from 0 (sealed router) to reversing the u-boot by physically extracting the firmware as well as analyzing internal binaries and potential vulnerabilities.

The target is an old router which is one of the most purchased on Amazon (my version is older than the current one, I bought it second-hand):

# Target - **TL-WR841N**
This is the router itself, as I mentioned it is not the latest range but an earlier version:

![](imgs/blog/10TpLinkRouterResearch/20251110184021.png)

This is the back:

![](imgs/blog/10TpLinkRouterResearch/20251110184127.png)

If we look closely we can see both the model and the serial number:

![](imgs/blog/10TpLinkRouterResearch/20251110184337.png)

## Footprinting
Now we can open it and start looking at the internal components and the SoC:

![](imgs/blog/10TpLinkRouterResearch/20251110184712.png)

If we zoom in more...

![](imgs/blog/10TpLinkRouterResearch/20251110190053.png)

For now there are two visible components, the RAM (rectangular) and the CPU (square).

Here we have the RAM which is not very important for our objective but it is always important to record the serial number. The more information the better tho.

![](imgs/blog/10TpLinkRouterResearch/20251110185839.png)

The other visible component is the CPU, in this case Mediatek:

![](imgs/blog/10TpLinkRouterResearch/20251110190217.png)

We have a Mediatek **`MT7628NN`**, which if we check the datasheet:

![](imgs/blog/10TpLinkRouterResearch/20251111220955.png)

We obtain useful information but nothing groundbreaking.

If we look at the back of the chip, we will see that it has a flash memory, responsible for loading the operating system:

![](imgs/blog/10TpLinkRouterResearch/20251111221227.png)

if we zoom in we will see that it is the model **`25Q64CS1G`**:

![](imgs/blog/10TpLinkRouterResearch/20251111221321.png)

We will leave this chip for later.

Looking at the router's physical interfaces we find what could be a ``UART``:

![](imgs/blog/10TpLinkRouterResearch/20251111223617.png)

The first thing is to make sure which one is the **GND** with the multimeter. In this case it is marked on the board but I don't like to trust that completely.

![](imgs/blog/10TpLinkRouterResearch/20251111223747.png)

The other probe of the multimeter we would place on something we know is a **GND**, such as a conductor of one of the router's connectors, in my case I put it here:

![](imgs/blog/10TpLinkRouterResearch/20251111224326.png)

By testing with the multimeter we can observe how it indeed matches the chip's `rx` and `tx` of the UART protocol. On the `rx` we see information activity when we power on the router, however on the `tx` we don't see anything.

### Uart Protocol
UART or *Universal Asynchronous Receiver (Rx) Transmitter (Tx)* is a serial communication protocol between devices. It uses asynchronous communication which means there is no dedicated clock signal on the data line; instead the transmitter and receiver agree on a baud rate (9600 bps, 19200 bps, 38400 bps, 57600 bps, 115200 bps, 230400 bps, 460800 bps, 921600 bps, 1000000 bps, 1500000 bps) and synchronize from the start bit. Being serial, the bits are sent one after another over a single data line. Data can also be sent and received simultaneously.

![](imgs/blog/10TpLinkRouterResearch/20251112121924.png)

here we can see a diagram ([resource](https://en.wikipedia.org/wiki/File:UART_block_diagram.svg)) of UART to make it clearer:

![](imgs/blog/10TpLinkRouterResearch/20251112122018.png)

When establishing device-to-device communication over UART it is important to connect Ground to Ground, `tx` to `rx` and vice versa. The following [image](https://www.secureideas.com/blog/hardware-hacking-interfacing-to-uart-with-your-computer) explains it:

![](imgs/blog/10TpLinkRouterResearch/20251112122210.png)

## Communication
Now that we understand the UART protocol, we will proceed to connect. for that we can use a static mechanical arm which I don't have, or solder.

![](imgs/blog/10TpLinkRouterResearch/20251112123500.png)

### Uart: ``tx``
now we can connect to the `tx` with our logic analyzer to see the output:

![](imgs/blog/10TpLinkRouterResearch/20251112123625.png)

in **Logic 2** we can see the output:

![](imgs/blog/10TpLinkRouterResearch/20251015000003.png)

Which would be the following (removing the dirty bytes at the beginning):
```
DDR Calibration DQS reg = 00008A89


U-Boot 1.1.3 (Oct 12 2016 - 08:49:46)

Board: Ralink APSoC DRAM:  64 MB
relocate_code Pointer at: 83fb8000
gpiomode1 55054404.
gpiomode2 05540554.
gpiomode2 00000000.
gpiomode2 05550555.
flash manufacture id: c8, device id 40 17
find flash: GD25Q64B
============================================ 
Ralink UBoot Version: 4.3.0.0
-------------------------------------------- 
ASIC 7628_MP (Port5<->None)
DRAM component: 512 Mbits DDR, width 16
DRAM bus: 16 bit
Total memory: 64 MBytes
Flash component: SPI Flash
Date:Oct 12 2016  Time:08:49:46
============================================ 
icache: sets:512, ways:4, linesz:32 ,total:65536
dcache: sets:256, ways:4, linesz:32 ,total:32768 

 ##### The CPU freq = 575 MHZ #### 
 estimate memory size =64 Mbytes
RESET MT7628 PHY!!!!!!
continue to starting system.
\x08\x08\x08 0 
disable switch phyport...
   
3: System Boot system code via Flash.(0xbc020000)
do_bootm:argc=2, addr=0xbc020000
## Booting image at bc020000 ...
   Uncompressing Kernel Image ... OK
No initrd
## Transferring control to Linux (at address 8000c150) ...
## Giving linux memsize in MB, 64

Starting kernel ...

\xE6\x80\x98\x80\xE0\x98\x86\x98\xF8\x98fff\x98\xF8\x06~\x06\x86\xF8\x06~f\x06x\xF8\x86\xF8\x86\xF8\x86\xE6\x80\x98\x80\xE6\x80\x98\x80\0\x18f\x80\x98\x86\x98\x1Ef\x98\x18\xE6\x98\x06\x98\0\xE6\x98f\x98\x1Ef\x80\x98\x80Linux version 2.6.36 (root@tplink) (gcc version 4.6.3 (Buildroot 2012.11.1) ) #83 Wed Oct 12 08:54:10 HKT 2016

 The CPU feqenuce set to 580 MHz

 MIPS CPU sleep mode enabled.
CPU revision is: 00019655 (MIPS 24Kc)
Software DMA cache coherency
Determined physical RAM map:
 memory: 04000000 @ 00000000 (usable)
Initrd not found or empty - disabling initrd
Zone PFN ranges:
  Normal   0x00000000 -> 0x00004000
Movable zone start PFN for each node
early_node_map[1] active PFN ranges
    0: 0x00000000 -> 0x00004000
Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 16256
Kernel command line: console=ttyS1,115200 root=/dev/mtdblock2 rootfstype=squashfs init=/sbin/init
PID hash table entries: 256 (order: -2, 1024 bytes)
Dentry cache hash table entries: 8192 (order: 3, 32768 bytes)
Inode-cache hash table entries: 4096 (order: 2, 16384 bytes)
Primary instruction cache 64kB, VIPT, , 4-waylinesize 32 bytes.
Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
Writing ErrCtl register=00059793
Readback ErrCtl register=00059793
Memory: 61268k/65536k available (2628k kernel code, 4236k reserved, 638k data, 164k init, 0k highmem)
NR_IRQS:128
console [ttyS1] enabled
Calibrating delay loop... 386.04 BogoMIPS (lpj=772096)
pid_max: default: 4096 minimum: 301
Mount-cache hash table entries: 512
NET: Registered protocol family 16
bio: create slab <bio-0> at 0
Switching to clocksource Ralink Systick timer
NET: Registered protocol family 2
IP route cache hash table entries: 1024 (order: 0, 4096 bytes)
TCP established hash table entries: 2048 (order: 2, 16384 bytes)
TCP bind hash table entries: 2048 (order: 1, 8192 bytes)
TCP: Hash tables configured (established 2048 bind 2048)
TCP reno registered
NET: Registered protocol family 1
squashfs: version 4.0 (2009/01/31) Phillip Lougher
fuse init (API version 7.15)
msgmni has been set to 119
io scheduler noop registered
io scheduler deadline registered (default)
Ralink gpio driver initialized
i2cdrv_major = 218
Serial: 8250/16550 driver, 2 ports, IRQ sharing enabled
serial8250: ttyS0 at MMIO 0x10000d00 (irq = 21) is a 16550A
serial8250: ttyS1 at MMIO 0x10000c00 (irq = 20) is a 16550A
brd: module loaded
flash manufacture id: c8, device id 40 17
GD25Q64B(c8 40170000) (8192 Kbytes)
mtd .name = raspi, .size = 0x00800000 (8M) .erasesize = 0x00010000 (64K) .numeraseregions = 0
Creating 7 MTD partitions on "raspi":
0x000000000000-0x000000020000 : "boot"
0x000000020000-0x000000160000 : "kernel"
0x000000160000-0x0000007c0000 : "rootfs"
mtd: partition "rootfs" set to be root filesystem
0x0000007c0000-0x0000007d0000 : "config"
0x0000007d0000-0x0000007e0000 : "romfile"
0x0000007e0000-0x0000007f0000 : "rom"
0x0000007f0000-0x000000800000 : "radio"
Register flash device:flash0
PPP generic driver version 2.4.2
PPP MPPE Compression module registered
NET: Registered protocol family 24
Mirror/redirect action on
u32 classifier
    Actions configured
Netfilter messages via NETLINK v0.30.
nf_conntrack version 0.5.0 (957 buckets, 3828 max)
ip_tables: (C) 2000-2006 Netfilter Core Team, Type=Restricted Cone
TCP cubic registered
NET: Registered protocol family 10
ip6_tables: (C) 2000-2006 Netfilter Core Team
IPv6 over IPv4 tunneling driver
NET: Registered protocol family 17
Ebtables v2.0 registered
802.1Q VLAN Support v1.8 Ben Greear <greearb@candelatech.com>
All bugs added by David S. Miller <davem@redhat.com>
VFS: Mounted root (squashfs filesystem) readonly on device 31:2.
Freeing unused kernel memory: 164k freed
starting pid 679, tty '': '/etc/init.d/rcS'
rdm_major = 253
spiflash_ioctl_read, Read from 0x007df100 length 0x6, ret 0, retlen 0x6
Read MAC from flash(0x7DF100) ffffffd4-6e-0e-57-1e-ffffffe0
GMAC1_MAC_ADRH -- : 0x0000d46e
GMAC1_MAC_ADRL -- : 0x0e571ee0
Ralink APSoC Ethernet Driver Initilization. v3.1  256 rx/tx descriptors allocated, mtu = 1500!
spiflash_ioctl_read, Read from 0x007df100 length 0x6, ret 0, retlen 0x6
Read MAC from flash(0x7DF100) ffffffd4-6e-0e-57-1e-ffffffe0
GMAC1_MAC_ADRH -- : 0x0000d46e
GMAC1_MAC_ADRL -- : 0x0e571ee0
PROC INIT OK!
switch reg write offset=14, value=5555
switch reg write offset=40, value=1001
switch reg write offset=44, value=1001
switch reg write offset=48, value=1001
switch reg write offset=4c, value=1
switch reg write offset=50, value=2001
switch reg write offset=70, value=ffffffff
switch reg write offset=98, value=7f7f
switch reg write offset=e4, value=7f
done.
switch reg write offset=14, value=405555
switch reg write offset=50, value=2003
switch reg write offset=98, value=7f3f
switch reg write offset=e4, value=3f
switch reg write offset=40, value=3002
switch reg write offset=44, value=3003
switch reg write offset=48, value=3003
switch reg write offset=70, value=417e
switch reg write offset=74, value=0
done.
tp_domain init ok
L2TP core driver, V2.0
PPPoL2TP kernel driver, V2.0
Set: phy[0].reg[0] = 3900
Set: phy[1].reg[0] = 3900
Set: phy[2].reg[0] = 3900
Set: phy[3].reg[0] = 3900
Set: phy[4].reg[0] = 3900
Set: phy[0].reg[0] = 3300
Set: phy[1].reg[0] = 3300
Set: phy[2].reg[0] = 3300
Set: phy[3].reg[0] = 3300
Set: phy[4].reg[0] = 3300
resetMiiPortV over.
starting pid 746, tty '/dev/ttyS1': '/bin/sh'
~ # [ util_execSystem ] 135:  ipt_init cmd is "/var/tmp/dconf/rc.router"

[ dm_readFile ] 2061:  can not open xml file /var/tmp/pc/reduced_data_model.xml!, about to open file /etc/reduced_data_model.xml
spiflash_ioctl_read, Read from 0x007c0000 length 0x10000, ret 0, retlen 0x10000
spiflash_ioctl_read, Read from 0x007c0000 length 0x3010, ret 0, retlen 0x3010
[ dm_loadCfg ] 2278:  software version is not match, in config, version = 271585328
[ dm_readFile ] 2061:  can not open xml file /var/tmp/pc/default_config.xml!, about to open file /etc/default_config.xml
[ parseConfigNode ] 525:  Meet unrecognized object node "PhDDNSCfg", skip the node
[ parseConfigNode ] 530:  Meet unrecognized parameter node "PhDDNSCfg", skip the node
[ parseConfigNode ] 525:  Meet unrecognized object node "SnmpCfg", skspiflash_ioctl_read, Read from 0x007df100 length 0x6, ret 0, retlen 0x6
ip the node
[ pspiflash_ioctl_read, Read from 0x007df200 length 0x4, ret 0, retlen 0x4
arseConfigNode ]spiflash_ioctl_read, Read from 0x007df300 length 0x4, ret 0, retlen 0x4
 525:  Meet unrecognized object node "ACL", skip the node
[ parseConfigNode ] 530:  Meet unrecognized parameter node "ACL", skip the node
[ parseConfigNode ] 525:  Meet unrecognized object node "X_TP_WANUSB3gLinkConfig", skip the node
[ parseConfigNode ] 525:  Meet unrecognized object node "QueueManagement", skip the node
[ parseConfigNode ] 525:  Meet unrecognized object node "X_TP_IPTV", skip the node
[ parseConfigNode ] 525:  Meet unrecognized object node "VoiceService", skip the node
[ parseConfigNode ] 530:  Meet unrecognized parameter node "VoiceService", skip the node
[ parseConfigNode ] 525:  Meet unrecognized object node "StorageService", skip the node
[ parseConfigNode ] 525:  spiflash_ioctl_read, Read from 0x00020000 length 0x1d0, ret 0, retlen 0x1d0
Meet unrecognizespiflash_ioctl_read, Read from 0x007df100 length 0x6, ret 0, retlen 0x6
d object node "X_TP_SpeedDialCfg", skip the node
[ parseConfigNode ] 525:  Meet unrecognized object node "X_TP_MultiIspDialPlan", skip the node
[ parseConfigNode ] 525:  Meet unrecognized object node "X_TP_CallLogCfg", skip the node
sendto: No such file or directory
pid 745 send 2001 error
[ util_execSystem ] 135:  oal_startDynDns cmd is "dyndns /var/tmp/dconf/dyndns.conf"

[ oal_sys_getOldTZInfo ] 389:  Open TZ file error!
[ util_execSystem ] 135:  oal_sys_unsetTZ cmd is "echo "" > /etc/TZ"

[ util_execSystem ] 135:  oal_sys_unsetTZ cmd is "echo "" > /etc/TZ"

[ util_execSystem ] 135:  oal_startNoipDns cmd is "noipdns /var/tmp/dconf/noipdns.conf"

[ util_execSystem ] 135:  oal_startCmxDns cmd is "cmxdns /var/tmp/dconf/cmxdns.conf"

ioctl: No such device
[ util_execSystem ] 135:  oal_br_addBridge cmd is "brctl addbr br0;brctl setfd br0 0;brctl stp br0 off"

[ util_execSystem ] 135:  oal_ipt_addLanRules cmd is "iptables -t filter -A INPUT -i br+ -j ACCEPT
"

[ util_execSystem ] 135:  oal_intf_setIntf cmd is "ifconfig br0 192.168.0.1 netmask 255.255.255.0 up"

[ util_execSystem ] 135:  oal_util_setProcLanAddr cmd is "echo "br0 16820416,"Raeth v3.1 ( > /proc/net/conTaskletntract_LocalAddr,SkbRecycle"

[ util_exec)
System ] 135:  o
phy_tx_ring = 0x030ad000, tx_ring = 0xa30ad000
al_intf_enableIn
phy_rx_ring0 = 0x030ae000, rx_ring0 = 0xa30ae000
tf cmd is "ifcon[fe_sw_init:4776]rt305x_esw_init.
fig eth0 up"

disable switch phyport...
GMAC1_MAC_ADRH -- : 0x0000d46e
GMAC1_MAC_ADRL -- : 0x0e571ee0
RT305x_ESW: Link Status Changed
[ rsl_getUnusedVlan ] 1002:  GET UNUSED VLAN TAG 1 : [3]
[ rsl_getUnusedVlan ] 1002:  GET UNUSED VLAN TAG 2 : [4]
[ rsl_getUnusedVlan ] 1002:  GET UNUSED VLAN TAG 3 : [5]
[ rsl_getUnusedVlan ] 1002:  GET UNUSED VLAN TAG 4 : [6]
[ util_execSystem ] 135:  oal_addVlanTagIntf cmd is "vconfig add eth0 3"

[ util_execSystem ] 135:  oal_intf_enableIntf cmd is "ifconfig eth0.3 up"

set if eth0.3 to *not wan dev
[ util_execSystem ] 135:  oal_addVlanTagIntf cmd is "vconfig add eth0 4"

[ util_execSystem ] 135:  oal_intf_enableIntf cmd is "ifconfig eth0.4 up"

set if eth0.4 to *not wan dev
[ util_execSystem ] 135:  oal_addVlanTagIntf cmd is "vconfig add eth0 5"

[ util_execSystem ] 135:  oal_intf_enableIntf cmd is "ifconfig eth0.5 up"

set if eth0.5 to *not wan dev
[ util_execSystem ] 135:  oal_addVlanTagIntf cmd is "vconfig add eth0 6"

[ util_execSystem ] 135:  oal_intf_enableIntf cmd isdevice eth0.3 entered promiscuous mode
 "ifconfig eth0.device eth0 entered promiscuous mode
6 up"

set if br0: port 1(eth0.3) entering forwarding state
eth0.6 to *not wbr0: port 1(eth0.3) entering forwarding state
an dev
[ util_execSystem ] 135:  oal_addVlanTagIntf cmd is "vconfig add eth0 2"device eth0.4 entered promiscuous mode


[ util_execSbr0: port 2(eth0.4) entering forwarding state
ystem ] 135:  oabr0: port 2(eth0.4) entering forwarding state
l_intf_enableIntf cmd is "ifconfig eth0.2 up"

set if eth0.2 to wan dev
[ vladevice eth0.5 entered promiscuous mode
n_addLanPortsIntbr0: port 3(eth0.5) entering forwarding state
oBridge ] 500:  br0: port 3(eth0.5) entering forwarding state
add lan Port 255 from br0
[ util_execSystem ] 135:  oal_br_addIntfIntoBridge cmdevice eth0.6 entered promiscuous mode
d is "brctl addibr0: port 4(eth0.6) entering forwarding state
f br0 eth0.3"
br0: port 4(eth0.6) entering forwarding state

[ util_execSystem ] 135:  oal_br_addIntfIntoBridge cmd is "brctl addif br0 eth0.4"

[ util_execSystem ] 135:  oal_br_addIntfIntoBridge cmd is "brctl addif br0 eth0.5"

[ util_execSystem ] 135:  oal_br_addIntfIntoBridge cmd is "brctl addif br0 eth0.6"

switch reg write offset=14, value=5555
switch reg write offset=40, value=1001
switch reg write offset=44, value=1001
switch reg write offset=48, value=1001
switch reg write offset=4c, value=1
switch reg write offset=50, value=2001
switch reg write offset=70, value=ffffffff
switch reg write offset=98, value=7f7f
switch reg write offset=e4, value=7f
done.
switch reg write offset=14, value=c05555
switch reg write offset=50, value=3002
switch reg write offset=54, value=5004
switch reg write offset=58, value=6
switch reg write offset=98, value=7f3f
switch reg write offset=e4, value=3f
switch reg write offset=40, value=3002
switch reg write offset=44, value=5004
switch reg write offset=48, value=6
switch reg write offset=70, value=48444241
switch reg write offset=74, value=50
done.
[ util_execSystem ] 135:  rsl_initIPv6CfgObj cmd is "echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6"

[ util_execSystem ] 135:  oal_eth_setIGMPSnoopParam cmd is "echo 1 > /sys/devices/virtual/net/br0/bridge/multicast_snooping"

[ util_execSystem ] 135:  oal_eth_setIGMPSnoopParam cmd is "/sbin/config-vlan-router.sh br0"

switch reg write offset=14, value=5555
switch reg write offset=40, value=1001
switch reg write offset=44, value=1001
switch reg write offset=48, value=1001
switch reg write offset=4c, value=1
switch reg write offset=50, value=2001
switch reg write offset=70, value=ffffffff
switch reg write offset=98, value=7f7f
switch reg write offset=e4, value=7f
done.
switch reg write offset=14, value=c05555
switch reg write offset=50, value=3002
switch reg write offset=54, value=5004
switch reg write offset=58, value=6
switch reg write offset=98, value=7f3f
switch reg write offset=e4, value=3f
switch reg write offset=40, value=3002
switch reg write offset=44, value=5004
switch reg write offset=48, value=6
switch reg write offset=70, value=48444241
switch reg write offset=74, value=50
done.
[ util_execSystem ] 135:  oal_wlan_ra_setCountryRegion cmd is "cp /etc/SingleSKU_CE.dat /var/Wireless/RT2860AP/SingleSKU.dat"

[ util_execSystem ] 135:  oal_wlan_ra_setCountryRegion cmd is "iwpriv ra0 set CountryRegion=1"

ra0       no private ioctls.

[ util_execSystem ] 135:  oal_wlan_ra_loadDriver cmd is "insmod /lib/modules/kmdir/kernel/drivers/net/wireless/mt_wifi_ap/mt_wifi.ko"

ADDRCONF(NETDEV_CHANGE): eth0.4: link becomes ready
ADDRCONF(NETDEV_CHANGE): eth0.5: link becomes ready
ADDRCONF(NETDEV_CHANGE): eth0.6: link becomes ready
ADDRCONF(NETDEV_CHANGE): eth0.2: link becomes ready


=== pAd = c082b000, size = 1459424 ===

<-- RTMPAllocTxRxRingMemory, Status=0, ErrorValue=0x
<-- RTMPAllocAdapterBlock, Status=0
RtmpChipOpsHook(492): Not support for HIF_MT yet!
mt7628_init()-->
mt7628_init(FW(8a00), HW(8a01), CHIPID(7628))
e2.bin mt7628_init(1135)::(2), pChipCap->fw_len(63888)
mt_bcn_buf_init(218): Not support for HIF_MT yet!
<--mt7628_init()
[ util_execSystem ] 135:  oal_wlan_ra_initWlan cmd is "ifconfig ra0 up"

TX_BCN DESC a327e000 size = 320
RX[0] DESC a3281000 size = 1024
RX[1] DESC a3282000 size = 1024
cfg_mode=9
cfg_mode=9
wmode_band_equal(): Band Equal!
AndesSendCmdMsg: Could not send in band command due to diable fRTMP_ADAPTER_MCU_SEND_IN_BAND_CMD
APSDCapable[0]=0
APSDCapable[1]=0
APSDCapable[2]=0
APSDCapable[3]=0
APSDCapable[4]=0
APSDCapable[5]=0
APSDCapable[6]=0
APSDCapable[7]=0
APSDCapable[8]=0
APSDCapable[9]=0
APSDCapable[10]=0
APSDCapable[11]=0
APSDCapable[12]=0
APSDCapable[13]=0
APSDCapable[14]=0
APSDCapable[15]=0
default ApCliAPSDCapable[0]=0
Key1Str is Invalid key length(0) or Type(0)
Key1Str is Invalid key length(0) or Type(0)
Key2Str is Invalid key length(0) or Type(0)
Key2Str is Invalid key length(0) or Type(0)
Key3Str is Invalid key length(0) or Type(0)
Key3Str is Invalid key length(0) or Type(0)
Key4Str is Invalid key length(0) or Type(0)
Key4Str is Invalid key length(0) or Type(0)
WscKeyASCII=8
WscKeyASCII=8
[RTMPReadParametersHook:254]wifi read profile faild.
load fw image from fw_header_image
AndesMTLoadFwMethod1(2182)::pChipCap->fw_len(63888)
FW Version:20151201
FW Build Date:20151201183641
CmdAddressLenReq:(ret = 0)
CmdFwStartReq: override = 1, address = 1048576
CmdStartDLRsp: WiFI FW Download Success
MtAsicDMASchedulerInit(): DMA Scheduler Mode=0(LMAC)
efuse_probe: efuse = 10000012
RtmpChipOpsEepromHook::e2p_type=2, inf_Type=4
RtmpEepromGetDefault::e2p_dafault=2
RtmpChipOpsEepromHook: E2P type(2), E2pAccessMode = 2, E2P default = 2
NVM is FLASH mode
1. Phy Mode = 14
exec!
spiflash_ioctl_read, Read from 0x007f0000 length 0x400, ret 0, retlen 0x400
eeFlashId = 0x7628!
Country Region from e2p = ffff
tssi_1_target_pwr_g_band = 30
2. Phy Mode = 14
3. Phy Mode = 14
NICInitPwrPinCfg(11): Not support for HIF_MT yet!
NICInitializeAsic(651): Not support rtmp_mac_sys_reset () for HIF_MT yet!
mt_mac_init()-->
MtAsicInitMac()-->
mt7628_init_mac_cr()-->
MtAsicSetMacMaxLen(1277): Set the Max RxPktLen=450!
<--mt_mac_init()
        WTBL Segment 1 info:
                MemBaseAddr/FID:0x28000/0
                EntrySize/Cnt:32/128
        WTBL Segment 2 info:
                MemBaseAddr/FID:0x40000/0
                EntrySize/Cnt:64/128
        WTBL Segment 3 info:
                MemBaseAddr/FID:0x42000/64
                EntrySize/Cnt:64/128
        WTBL Segment 4 info:
                MemBaseAddr/FID:0x44000/128
                EntrySize/Cnt:32/128
AntCfgInit(2940): Not support for HIF_MT yet!
MCS Set = ff ff 00 00 01
MtAsicSetChBusyStat(861): Not support for HIF_MT yet!
CmdSlotTimeSet:(ret = 0)
[PMF]ap_pmf_init:: apidx=0, MFPC=0, MFPR=0, SHA256=0
[PMF]RTMPMakeRsnIeCap: RSNIE Capability MFPC=0, MFPR=0
[PMF]ap_pmf_init:: apidx=1, MFPC=0, MFPR=0, SHA256=0
MtAsicSetRalinkBurstMode(3048): Not support for HIF_MT yet!
MtAsicSetPiggyBack(796): Not support for HIF_MT yet!
reload DPD from flash , 0x9F = [c000] doReload bit7[0]
CmdLoadDPDDataFromFlash: Channel = 2, DoReload = 0
MtAsicSetTxPreamble(3027): Not support for HIF_MT yet!
MtAsicAddSharedKeyEntry(1344): Not support for HIF_MT yet!
MtAsicSetPreTbtt(): bss_idx=0, PreTBTT timeout = 0xf0
ap_ftkd> Initialize FT KDP Module...
Main bssid = d4:6e:0e:57:1e:e0
<==== rt28xx_init, Status=0
@@@ ed_monitor_init : ===>
@@@ ed_monitor_init : <===
mt7628_set_ed_cca: TURN ON EDCCA mac 0x10618 = 0xd7c87d0f, EDCCA_Status=1
WiFi Startup Cost (ra0): 3.428s
[ util_execSystem ] 135:  oal_wlan_ra_initWlan cmd is "echo 1 > /proc/tplink/led_wlan_24G"

[ util_execSystem device ra0 entered promiscuous mode
] 135:  oal_br_abr0: port 5(ra0) entering forwarding state
ddIntfIntoBridgebr0: port 5(ra0) entering forwarding state
 cmd is "brctl addif br0 ra0"

[ util_execSystem ] 135:  oal_br_addIntfIntoBridevice apcli0 entered promiscuous mode
dge cmd is "brctl addif br0 apcli0"

[ util_execSystem ] 135:  oal_br_addIntfIntoBridge cmd is "brctl addif br0 apcli0"

brctl: bridge br0: Device or resourdevice ra1 entered promiscuous mode
ce busy
[ util_execSystem ] 135:  oal_br_addIntfIntoBridge cmd is "brctl addif br0 ra1"

[ utspiflash_ioctl_read, Read from 0x007f0000 length 0x2, ret 0, retlen 0x2
il_execSystem ] 135:  oal_wlan_ra_initEnd cmd is "wlNetlinkTool &"


====
@@@ ed_status_read: EDCCA TH - H
pAd->ed_trigger_cnt : 1 > 20 ||  pAd->ed_big_rssi_stat : 0 < 50
====
[ util_execSystem ] 135:  oal_wlan_ra_initEnd cmd is "killall -q wscd"

WLAN-Start wlNetlinkTool
Waiting for Wireless Events from interfaces...
swWlanChkAhbErr: netlink to do
[ util_execSystem ] 135:  oal_wlan_ra_initEnd cmd is "wscd -i ra0 -m 1 -w /var/tmp/wsc_upnp/ &"

[ oal_wlan_ra_loadDriver ] 1786:  no 5G chip.


wscd: SSDP UDP PORT = 1900
sendto: No such file or directory
pid 745 send 2030 error
sendto: No such file or directory
pid 745 send 2004 error
[ util_execSystem ] 135:  oal_startDhcps cmd is "dhcpd /var/tmp/dconf/udhcpd.conf"

[ util_execSystem ] 135:  oal_lan6_startDhcp6s cmd is "dhcp6s -c /var/tmp/dconf/dhcp6s_br0.conf -P /var/run/dhcp6s_br0.pid br0 &"

[ util_execSystem ] 135:  oal_lan6_startRadvd cmd is "radvd -C /var/tmp/dconf/radvd_br0.conf -p /var/run/radvd_br0.pid &"

mldProxy# file: src/mld_ifinfo.c;line: 102; error = No such file or directory
mldProxy# Err: get LLA failed
[ util_execSystem ] 135:  oal_br_delIntfFromBridge cmd is "brctl delif br0 eth0.2"

iptables: Bad rule (does a matching rule exist in that chain?).
brctl: bridge br0: Invalid argument
[ util_execSystem ] 135:  oal_intf_setIfMac cmd is "ifconfig eth0.2 down"

[ util_execSystem ] 135:  oal_intf_setIfMac cmd is "ifconfig eth0.2 hw ether D4:6E:0E:57:1E:E1 up"

[ util_execSystem ] 135:  oal_intf_enableIntf cmd is "ifconfig eth0.2 up"

radvd starting
[Jan 01 00:00:07] radvd: no linklocal address configured for br0
[Jan 01 00:00:07] radvd: error parsing or activating the config file: /var/tmp/dconf/radvd_br0.conf
[ util_execSystem ] 135:  prepareDropbear cmd is "dropbearkey -t rsa -f /var/tmp/dropbear/dropbear_rsa_host_key"

Will output 1024 bit rsa secret key to '/var/tmp/dropbear/dropbear_rsa_host_key'
Generating key, this may take a while...
[ util_execSystem ] 135:  prepareDropbear cmd is "dropbearkey -t dss -f /var/tmp/dropbear/dropbear_dss_host_key"

Will output 1024 bit dss secret key to '/var/tmp/dropbear/dropbear_dss_host_key'
Generating key, this may take a while...
[ util_execSystem ] 135:  oal_rip_updateConfig cmd is "rm -f /var/tmp/dconf/zebra.conf"

[ util_execSystem ] 135:  oal_rip_updateConfig cmd is "rm -f /var/tmp/dconf/ripd.conf"

[ util_execSystem ] 135:  removeAllRIPIpTableRule cmd is "iptables -L INPUT -v --line-numbers > /var/iptable"

[ getPidFromPidFile ] 112:  Cann't open file: /var/run/zebra.pid.
[ util_execSystem ] 135:  controlRipProcess cmd is "zebra -d -f /var/tmp/dconf/zebra.conf"

[ getPidFromPidFile ] 112:  Cann't open file: /var/run/ripd.pid.
[ util_execSystem ] 135:  oal_ipt_fwDdos cmd is "iptables -D FORWARD -j FIREWALL_DDOS
"

iptables: No chain/target/match by that name.
[ util_execSystem ] 135:  oal_ipt_forbidLanPing cmd is "iptables -t filter -D INPUT -i br+ -p icmp --icmp-type echo-request -j DROP
iptables -t filter -D FORWARD -i br+ -p icmp --icmp-type echo-request -j DROP
"

iptables: Bad rule (does a matching rule exist in that chain?).
iptables: Bad rule (does a matching rule exist in that chain?).
[ util_execSystem ] 135:  oal_ddos_delPingRule cmd is "iptables -t filter -D INPUT ! -i br+ -p icmp --icmp-type echo-request -j ACCEPT
"

iptables: Bad rule (does a matching rule exist in that chain?).
[ util_execSystem ] 135:  oal_ipt_setDDoSRules cmd is "iptables -F FIREWALL_DDOS"

[ util_execSystem ] 135:  ddos_clearAll cmd is "rm -f /var/tmp/dosHost"

[ util_execSystem ] 135:  prepareDropbear cmd is "dropbear -p 22 -r /var/tmp/dropbear/dropbear_rsa_host_key -d /var/tmp/dropbear/dropbear_dss_host_key -A /var/tmp/dropbear/dropbearpwd"

[ util_execSystem ] 135:  oal_initFirewallObj cmd is "ebtables -N FIREWALL"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -F"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -X"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -P INPUT ACCEPT"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -P FORWARD DROP"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -P OUTPUT ACCEPT"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -N FIREWALL"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -N FWRULE"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -N SETMSS"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A INPUT -i lo -p ALL -j ACCEPT -m comment                                      --comment "loop back""

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A INPUT  -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A INPUT -i br+ -p tcp --dport 23 -j ACCEPT"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A INPUT -p tcp --dport 23 -j DROP"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A INPUT -i br+ -p icmpv6 --icmpv6-type echo-request -j ACCEPT"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A INPUT -p icmpv6 --icmpv6-type echo-request -j DROP"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A FORWARD -i br+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A FORWARD -o br+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -A FORWARD -j FIREWALL"

[ util_execSystem ] 135:  oal_initIp6FirewallObj cmd is "ip6tables -I FORWARD 1 -j SETMSS"

[ util_execSystem ] 135:  oal_fw6_setFwEnabeld cmd is "ip6tables -D FIREWALL -j ACCEPT"

ip6tables: Bad rule (does a matching rule exist in that chain?).
[ util_execSystem ] 135:  oal_fw6_setFwEnabeld cmd is "ip6tables -F FIREWALL"

[ util_execSystem ] 135:  oal_fw6_setFwEnabeld cmd is "ip6tables -A FIREWALL -j ACCEPT"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/netfilter/nf_conntrack_ftp.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/ipv4/netfilter/nf_nat_ftp.ko"

[ util_execSystem ] 135:  oal_openAlg cmd is "iptables -D FORWARD_VPN_PASSTHROUGH  -p udp --dport 500 -j DROP"

iptables: Bad rule (does a matching rule exist in that chain?).
[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/ipv4/netfilter/nf_nat_proto_gre.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/ipv4/netfilter/nf_nat_pptp.ko"

[ util_execSystem ] 135:  oal_openAlg cmd is "iptables -D FORWARD_VPN_PASSTHROUGH  -p tcp --dport 1723 -j DROP"

iptables: Bad rule (does a matching rule exist in that chain?).
[ util_execSystem ] 135:  oal_openAlg cmd is "iptables -D FORWARD_VPN_PASSTHROUGH  -p udp --dport 1701 -j DROP"

iptables: Bad rule (does a matching rule exist in that chain?).
[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/netfilter/nf_conntrack_tftp.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/ipv4/netfilter/nf_nat_tftp.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/netfilter/nf_conntrack_h323.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/ipv4/netfilter/nf_nat_h323.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/netfilter/nf_conntrack_sip.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/ipv4/netfilter/nf_nat_sip.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/netfilter/nf_conntrack_rtsp.ko"

[ util_execSystem ] 135:  setupModules cmd is "insmod /lib/modules/kmdir/kernel/net/ipv4/netfilter/nf_nat_rtsp.ko"

nf_nat_rtsp v0.6.21 loading
enable switch phyport...
Set: phy[0].reg[0] = 3900
Set: phy[1].reg[0] = 3900
Set: phy[2].reg[0] = 3900
Set: phy[3].reg[0] = 3900
Set: phy[4].reg[0] = 3900
Set: phy[0].reg[0] = 3300
Set: phy[1].reg[0] = 3300
Set: phy[2].reg[0] = 3300
Set: phy[3].reg[0] = 3300
Set: phy[4].reg[0] = 3300
resetMiiPortV over.
[ util_execSystem ] 135:  oal_sys_unsetTZ cmd is "echo "" > /etc/TZ"

[ util_execSystem ] 135:  oal_sys_unsetTZ cmd is "echo "" > /etc/TZ"


```

Here we can clearly see the **UART** packets that were sent:

![](imgs/blog/10TpLinkRouterResearch/20251015000545.png)

![](imgs/blog/10TpLinkRouterResearch/20251015000556.png)

### Uart: ``rx``
Now we can try to connect to the `rx` to see if we get command execution via the serial console that easily or if we need to make further modifications.

For that we will use a **UART-TTL USB**

![](imgs/blog/10TpLinkRouterResearch/20251112124650.png)

I personally used this one which supports both 5V and 3.3V, nevertheless since communication is at 3.3V we will use that.

Now we can use the cables to connect the different pins and use (in my case) **Tera Term** for communication with the device:

![](imgs/blog/10TpLinkRouterResearch/20251112124923.png)

After launching and configuring Tera Term we see the following:

![](imgs/blog/10TpLinkRouterResearch/20251015004017.png)

We have command execution

![](imgs/blog/10TpLinkRouterResearch/20251112134405.png)

This is the boot sequence when you reset the router:
```
 The CPU feqenuce set to 580 MHz

 MIPS CPU sleep mode enabled.
CPU revision is: 00019655 (MIPS 24Kc)
Software DMA cache coherency
Determined physical RAM map:
 memory: 04000000 @ 00000000 (usable)
Initrd not found or empty - disabling initrd
Zone PFN ranges:
  Normal   0x00000000 -> 0x00004000
Movable zone start PFN for each node
early_node_map[1] active PFN ranges
    0: 0x00000000 -> 0x00004000
Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 16256
Kernel command line: console=ttyS1,115200 root=/dev/mtdblock2 rootfstype=squashfs init=/sbin/init
PID hash table entries: 256 (order: -2, 1024 bytes)
Dentry cache hash table entries: 8192 (order: 3, 32768 bytes)
Inode-cache hash table entries: 4096 (order: 2, 16384 bytes)
Primary instruction cache 64kB, VIPT, , 4-waylinesize 32 bytes.
Primary data cache 32kB, 4-way, PIPT, no aliases, linesize 32 bytes
Writing ErrCtl register=00059380
Readback ErrCtl register=00059380
Memory: 61268k/65536k available (2628k kernel code, 4236k reserved, 638k data, 164k init, 0k highmem)
NR_IRQS:128
console [ttyS1] enabled
Calibrating delay loop... 386.04 BogoMIPS (lpj=772096)
pid_max: default: 4096 minimum: 301
Mount-cache hash table entries: 512
NET: Registered protocol family 16
bio: create slab <bio-0> at 0
Switching to clocksource Ralink Systick timer
NET: Registered protocol family 2
IP route cache hash table entries: 1024 (order: 0, 4096 bytes)
TCP established hash table entries: 2048 (order: 2, 16384 bytes)
TCP bind hash table entries: 2048 (order: 1, 8192 bytes)
TCP: Hash tables configured (established 2048 bind 2048)
TCP reno registered
NET: Registered protocol family 1
squashfs: version 4.0 (2009/01/31) Phillip Lougher
fuse init (API version 7.15)
msgmni has been set to 119
io scheduler noop registered
io scheduler deadline registered (default)
Ralink gpio driver initialized
i2cdrv_major = 218
Serial: 8250/16550 driver, 2 ports, IRQ sharing enabled
serial8250: ttyS0 at MMIO 0x10000d00 (irq = 21) is a 16550A
serial8250: ttyS1 at MMIO 0x10000c00 (irq = 20) is a 16550A
brd: module loaded
flash manufacture id: c8, device id 40 17
GD25Q64B(c8 40170000) (8192 Kbytes)
mtd .name = raspi, .size = 0x00800000 (8M) .erasesize = 0x00010000 (64K) .numeraseregions = 0
Creating 7 MTD partitions on "raspi":
0x000000000000-0x000000020000 : "boot"
0x000000020000-0x000000160000 : "kernel"
0x000000160000-0x0000007c0000 : "rootfs"
mtd: partition "rootfs" set to be root filesystem
0x0000007c0000-0x0000007d0000 : "config"
0x0000007d0000-0x0000007e0000 : "romfile"
0x0000007e0000-0x0000007f0000 : "rom"
0x0000007f0000-0x000000800000 : "radio"
Register flash device:flash0
PPP generic driver version 2.4.2
PPP MPPE Compression module registered
NET: Registered protocol family 24
Mirror/redirect action on
u32 classifier
    Actions configured
Netfilter messages via NETLINK v0.30.
nf_conntrack version 0.5.0 (957 buckets, 3828 max)
ip_tables: (C) 2000-2006 Netfilter Core Team, Type=Restricted Cone
TCP cubic registered
NET: Registered protocol family 10
ip6_tables: (C) 2000-2006 Netfilter Core Team
IPv6 over IPv4 tunneling driver
NET: Registered protocol family 17
Ebtables v2.0 registered
802.1Q VLAN Support v1.8 Ben Greear <greearb@candelatech.com>
All bugs added by David S. Miller <davem@redhat.com>
VFS: Mounted root (squashfs filesystem) readonly on device 31:2.
Freeing unused kernel memory: 164k freed
starting pid 679, tty '': '/etc/init.d/rcS'
rdm_major = 253
spiflash_ioctl_read, Read from 0x007df100 length 0x6, ret 0, retlen 0x6
Read MAC from flash(0x7DF100) ffffffd4-6e-0e-57-1e-ffffffe0
GMAC1_MAC_ADRH -- : 0x0000d46e
GMAC1_MAC_ADRL -- : 0x0e571ee0
Ralink APSoC Ethernet Driver Initilization. v3.1  256 rx/tx descriptors allocated, mtu = 1500!
spiflash_ioctl_read, Read from 0x007df100 length 0x6, ret 0, retlen 0x6
Read MAC from flash(0x7DF100) ffffffd4-6e-0e-57-1e-ffffffe0
GMAC1_MAC_ADRH -- : 0x0000d46e
GMAC1_MAC_ADRL -- : 0x0e571ee0
PROC INIT OK!
```

### The Guts of the Router
As we can see we do not have full commands, rather a very limited console. It uses `busybox` (**BusyBox v1.19.2**) for commands:
```bash
~ # whoami
/bin/sh: whoami: not found
~ # ls
web      usr      sbin     mnt      lib      dev
var      sys      proc     linuxrc  etc      bin
~ # b
bpalogin  brctl     busybox
~ # busybox
BusyBox v1.19.2 (2016-10-06 19:50:18 HKT) multi-call binary.
Copyright (C) 1998-2011 Erik Andersen, Rob Landley, Denys Vlasenko
and others. Licensed under GPLv2.
See source distribution for full notice.

Usage: busybox [function] [arguments]...
   or: busybox --list[-full]
   or: function [arguments]...

        BusyBox is a multi-call binary that combines many common Unix
        utilities into a single executable.  Most people will create a
        link to busybox for each function they wish to use and BusyBox
        will act like whatever it was invoked as.

Currently defined functions:
        arping, ash, brctl, cat, chmod, cp, date, df, echo, free, getty, halt,
        ifconfig, init, insmod, ipcrm, ipcs, kill, killall, linuxrc, login, ls,
        lsmod, mkdir, mount, netstat, pidof, ping, ping6, poweroff, ps, reboot,
        rm, rmmod, route, sh, sleep, taskset, telnetd, tftp, top, umount,
        vconfig

~ #
```

We can investigate a bit by listing the network interfaces but we don't obtain anything interesting
```bash
~ # ifconfig
br0       Link encap:Ethernet  HWaddr D4:6E:0E:57:1E:E0
          inet addr:192.168.0.1  Bcast:192.168.0.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:97 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:40970 (40.0 KiB)

eth0      Link encap:Ethernet  HWaddr D4:6E:0E:57:1E:E0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:63 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:20150 (19.6 KiB)
          Interrupt:3

eth0.2    Link encap:Ethernet  HWaddr D4:6E:0E:57:1E:E1
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:31 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:17914 (17.4 KiB)

eth0.3    Link encap:Ethernet  HWaddr D4:6E:0E:57:1E:E0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:7 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:446 (446.0 B)

eth0.4    Link encap:Ethernet  HWaddr D4:6E:0E:57:1E:E0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:528 (528.0 B)

eth0.5    Link encap:Ethernet  HWaddr D4:6E:0E:57:1E:E0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:528 (528.0 B)

eth0.6    Link encap:Ethernet  HWaddr D4:6E:0E:57:1E:E0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:7 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:0 (0.0 B)  TX bytes:446 (446.0 B)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:12 errors:0 dropped:0 overruns:0 frame:0
          TX packets:12 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:4467 (4.3 KiB)  TX bytes:4467 (4.3 KiB)

ra0       Link encap:Ethernet  HWaddr D4:6E:0E:57:1E:E0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
          Interrupt:4

~ #
```

During enumeration we obtain a file of great importance because it contains the router's configuration:
```bash
/var # cat Wireless/RT2860AP/RT2860AP.dat
Default
TP-LINK=
CountryNum=276
AutoChannelSelect=2
Channel=6
MaxStaNum=32
BssidNum=2
WirelessMode=9
NoForwardingBTNBSSID=0
BasicRate=15
BeaconPeriod=100
DtimPeriod=1
TxPower=100
RTSThreshold=2346
FragThreshold=2346
APSDCapable=0
DLSCapable=0
PMKCachePeriod=10
AccessPolicy0=0
AccessPolicy1=0
AccessPolicy2=0
AccessPolicy3=0
HT_BW=1
HT_EXTCHA=0
HT_BSSCoexistence=0
HT_GI=1
HT_HTC=0
HT_LinkAdapt=0
HT_OpMode=0
HT_MpduDensity=5
HT_AutoBA=1
HT_AMSDU=0
HT_BAWinSize=64
HT_MCS=33;33;33;33
CountryRegion=1
CountryRegionABand=1
EDCCA_AP_STA_TH=1
EDCCA_AP_AP_TH=1
EDCCA_AP_RSSI_TH=-80
EDCCA_ED_TH=90
EDCCA_FALSE_CCA_TH=250
EDCCA_BLOCK_CHECK_TH=2
HT_DisallowTKIP=1
HT_STBC=0
DisableOLBC=0
HT_RDG=0
HT_BADecline=0
BGProtection=0
EfuseBufferMode=1
TxPreamble=0
TxBurst=0
PktAggregate=0
IEEE80211H=0
ShortSlot=1
IgmpSnEnable=1
FixedTxMode=0
TxRate=0
PreAuth=0
WirelessEvent=0
ApCliEnable=0
ApCliDefaultKeyID=0
ApCliKey1Type=0
ApCliKey2Type=0
ApCliKey3Type=0
ApCliKey4Type=0
IEEE8021X=0
session_timeout_interval=0
WscSetupLock=0
VHT_BW=0
VHT_SGI=1
VHT_STBC=0
VHT_BW_SIGNAL=0
VHT_DisallowNonVHT=0
CountryCode=NOCOUNTRY
MacAddress=D4:6E:0E:57:1E:E0
ApCliBssid=
SSID1=TP-LINK_1EE0
SSID2=TP-LINK_Guest_1EE0
SSID3=
SSID4=
ApCliSsid=
WmmCapable=1;1;1;1
APAifsn=3;7;1;1
APCwmin=4;4;3;2
APCwmax=6;10;4;3
APTxop=0;0;94;47
APACM=0;0;0;0
BSSAifsn=3;7;2;2
BSSCwmin=4;4;3;2
BSSCwmax=10;10;4;3
BSSTxop=0;0;94;47
BSSACM=0;0;0;0
AckPolicy=0;0;0;0
AuthMode=WPA2PSK;OPEN
ApCliAuthMode=OPEN
EncrypType=AES;NONE
ApCliEncrypType=NONE
WPAPSK1=78231573
WPAPSK2=
WPAPSK3=
WPAPSK4=
ApCliWPAPSK=
RekeyMethod=TIME;TIME;TIME;TIME
DefaultKeyID=2;2;2;2
HideSSID=0;0;1;1
NoForwarding=0;0;1;1
WscConfMode=7;0;0;0
WscConfStatus=2;2;2;2
WscKeyASCII=8;8;8;8
WscSecurityMode=0;0;0;0
Key1Type=0;0;0;0
Key2Type=0;0;0;0
Key3Type=0;0;0;0
Key4Type=0;0;0;0
Key1Str1=
Key1Str2=
Key1Str3=
Key1Str4=
Key2Str1=
Key2Str2=
Key2Str3=
Key2Str4=
Key3Str1=
Key3Str2=
Key3Str3=
Key3Str4=
Key4Str1=
Key4Str2=
Key4Str3=
Key4Str4=
ApCliKey1Str=
ApCliKey2Str=
ApCliKey3Str=
ApCliKey4Str=
WscVendorPinCode=78231573;0;0;0
AccessControlList0=
AccessControlList1=
AccessControlList2=
AccessControlList3=
RekeyInterval=0;0;0;0
WscDeviceName=Wireless N Router TL-WR841N
WscManufacturer=TP-LINK
WscModelName=TL-WR841N
WscModelNumber=13.0
WscSerialNumber=1.0
RADIUS_Server=;;;
own_ip_addr=192.168.0.1
RADIUS_Key=;;;
Ethifname=br0
RADIUS_Port=1812;1812;0;0
WSC_UUID_Str1=38833092-3092-1883-9c77-D46E0E571Ec4
WSC_UUID_E1=38833092309218839c77D46E0E571Ec4
AutoChannelSkipList=12;13;52;56;60;64;100;104;108;112;116;120;124;128;132;136;140
/var # 
```

Including its password so we could already connect if we had not been able to obtain the password by other means. (in this case the password is on the back of the router in the photos already shown)
```bash
...
WscVendorPinCode=78231573;0;0;0
...
```

When we connect a device to the router this message appears making it clear that the connection was successful and that it uses AES encryption. although being WPA2 this is always the case
```bash
/bin # PeerAssocReqSanity - IE_HT_CAP
PeerAssocReqSanity - IE_EXT_CAPABILITY!
AP SETKEYS DONE - WPA2, AuthMode(7)=WPA2PSK, WepStatus(6)=AES, GroupWepStatus(6)=AES

Rcv Wcid(1) AddBAReq
Start Seq = 00000014
Rcv Wcid(1) AddBAReq
Start Seq = 00000004
```

From our computer we can see which IP the router assigned us:
```bash
root@ack:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: wlo1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 64:d6:9a:e1:20:76 brd ff:ff:ff:ff:ff:ff
    altname wlp0s20f3
    inet 192.168.0.100/24 brd 192.168.0.255 scope global dynamic noprefixroute wlo1
       valid_lft 7056sec preferred_lft 7056sec
    inet6 fe80::249:8abd:ef5c:1b8f/64 scope link noprefixroute
       valid_lft forever preferred_lft forever
root@ack:~#
```

From the router we have connectivity to the computer so everything is working fine
```bash
/var # ping 192.168.0.100
PING 192.168.0.100 (192.168.0.100): 56 data bytes
64 bytes from 192.168.0.100: seq=0 ttl=64 time=97.880 ms
64 bytes from 192.168.0.100: seq=1 ttl=64 time=118.660 ms
64 bytes from 192.168.0.100: seq=2 ttl=64 time=138.080 ms
64 bytes from 192.168.0.100: seq=3 ttl=64 time=57.540 ms
64 bytes from 192.168.0.100: seq=4 ttl=64 time=77.980 ms
64 bytes from 192.168.0.100: seq=5 ttl=64 time=76.040 ms
64 bytes from 192.168.0.100: seq=6 ttl=64 time=124.600 ms
64 bytes from 192.168.0.100: seq=7 ttl=64 time=136.880 ms
^C
--- 192.168.0.100 ping statistics ---
8 packets transmitted, 8 packets received, 0% packet loss
round-trip min/avg/max = 57.540/103.457/138.080 ms
/var #
```

We have an interesting program called `login`
```bash
~ # cd bin/
/bin # ls
umount   rm       ping     mount    login    df       chmod    ash
sleep    ps       pidof    mkdir    kill     date     cat
sh       ping6    netstat  ls       echo     cp       busybox
/bin # ./login
TL-WR841N login: user
Password:
Login incorrect
TL-WR841N login:

```

We find the shadow file so we can try to crack the password using `john` for example
```bash
/var # cat passwd
admin:$1$$iC.dUsGpxNNJGeOm1dFio/:0:0:root:/:/bin/sh
dropbear:x:500:500:dropbear:/var/dropbear:/bin/sh
nobody:*:0:0:nobody:/:/bin/sh
/var #
```

we run `john` with the dictionary and...
```bash
root@ack:~# john --wordlist=modified.txt passwd
Loaded 1 password hash (md5crypt [MD5 32/64 X2])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1234             (admin)
1g 0:00:00:00 100% 50.00g/s 102400p/s 102400c/s 102400C/s 123456..lovers1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
root@ack:~#
```
The password is `1234`, sounds like a joke but it's not xd

The application simply outputs a log and gives us a privileged shell, which is useless since we already have one:
```bash
/bin # ./login
TL-WR841N login: admin
Password:
Jan  1 03:17:52 login[879]: root login on 'ttyS1'
~ #
```

we can also analyze the router from the TCP-accessible ports (for now we are not scanning UDP)
```bash
root@ack:~# sudo nmap -p- -sV -sS 192.168.0.1
Nmap scan report for 192.168.0.1
Host is up (0.0063s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     Dropbear sshd 2012.55 (protocol 2.0)
23/tcp   open  telnet  BusyBox telnetd 1.14.0 or later (TP-LINK ADSL2+ router telnetd)
80/tcp   open  http    TP-LINK TD-W8968 http admin
1900/tcp open  upnp    Portable SDK for UPnP devices 1.6.19 (Linux 2.6.36; UPnP 1.0)
MAC Address: D4:6E:0E:57:1E:E0 (Tp-link Technologies)
Service Info: OS: Linux; Device: WAP; CPE: cpe:/o:linux:linux_kernel, cpe:/h:tp-link:td-w8968, cpe:/o:linux:linux_kernel:2.6.36

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.25 seconds
root@ack:~#
```
We see open and vulnerable services.  

**NOTE: there are many vulnerabilities in the router, both in `busybox` and in the http daemon and I'm almost certain in `Dropbear` as well**

The system script `info.sh` gives us a lot of system information, it is useful and also shows running processes as well as their privileges:
```bash
/sbin # sh info.sh
  PID USER       VSZ STAT COMMAND
    1 admin     1076 S    init
    2 admin        0 SW   [kthreadd]
    3 admin        0 SW   [ksoftirqd/0]
    4 admin        0 SW   [kworker/0:0]
    5 admin        0 SW   [kworker/u:0]
    6 admin        0 SW<  [khelper]
    7 admin        0 SW   [kworker/u:1]
   42 admin        0 SW   [sync_supers]
   44 admin        0 SW   [bdi-default]
   46 admin        0 SW<  [kblockd]
   69 admin        0 SW   [kswapd0]
   71 admin        0 SW<  [crypto]
  630 admin        0 SW   [mtdblock0]
  635 admin        0 SW   [mtdblock1]
  640 admin        0 SW   [mtdblock2]
  645 admin        0 SW   [mtdblock3]
  650 admin        0 SW   [mtdblock4]
  655 admin        0 SW   [mtdblock5]
  660 admin        0 SW   [mtdblock6]
  678 admin        0 SW   [kworker/0:1]
  728 admin     1068 S    telnetd
  745 admin     2848 S    cos
  746 admin     1080 S    /bin/sh
  749 admin     2052 S    igmpd
  752 admin     2076 S    mldProxy
  839 admin     2848 S    cos
  840 admin     2848 S    cos
  841 admin     2848 S    cos
  860 admin     2020 S    ntpc
  865 admin     2028 S    dyndns /var/tmp/dconf/dyndns.conf
  868 admin     2028 S    noipdns /var/tmp/dconf/noipdns.conf
  871 admin     2028 S    cmxdns /var/tmp/dconf/cmxdns.conf
  879 admin     1080 S    -sh
 1017 admin        0 SW   [RtmpCmdQTask]
 1018 admin        0 SW   [RtmpWscTask]
 1019 admin        0 SW   [RtmpMlmeTask]
 1032 admin     1244 S    wlNetlinkTool
 1036 admin     1080 S    wscd -i ra0 -m 1 -w /var/tmp/wsc_upnp/
 1040 admin     1244 S    wlNetlinkTool
 1042 admin     1244 S    wlNetlinkTool
 1055 admin     2600 S    httpd
 1067 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1070 admin     2016 S    dnsProxy
 1073 admin     1068 S    dhcpd /var/tmp/dconf/udhcpd.conf
 1092 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1093 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1094 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1096 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1097 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1098 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1099 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1100 admin     1152 S    dhcp6s -c /var/tmp/dconf/dhcp6s_br0.conf -P /var/run
 1101 admin     2600 S    tmpd
 1104 admin     2488 S    tdpd
 1112 admin      988 S    dhcpc
 1113 admin     1076 S    sh
 1123 admin     1136 S    dropbear -p 22 -r /var/tmp/dropbear/dropbear_rsa_hos
 1124 admin     1036 S    zebra -d -f /var/tmp/dconf/zebra.conf
 1138 admin     2020 S    diagTool
 1253 admin     1076 S    busybox sh
 1773 admin     1064 S    sh info.sh
 1774 admin     1068 R    ps
MemTotal:          61432 kB
MemFree:           35184 kB
Buffers:            2488 kB
Cached:             9824 kB
SwapCached:            0 kB
Active:             6380 kB
Inactive:           8752 kB
Active(anon):       2820 kB
Inactive(anon):        0 kB
Active(file):       3560 kB
Inactive(file):     8752 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                 0 kB
Writeback:             0 kB
AnonPages:          2828 kB
Mapped:             2460 kB
Shmem:                 0 kB
Slab:               6936 kB
SReclaimable:        720 kB
SUnreclaim:         6216 kB
KernelStack:         496 kB
PageTables:          428 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:       61432 kB
Committed_AS:       8792 kB
VmallocTotal:    1048372 kB
VmallocUsed:        3600 kB
VmallocChunk:    1036896 kB
Node 0, zone   Normal      3      4     24     15      9      3      2      2      3      2      6
RTMPAPPrivIoctlShow(): Before check, this_char=psinfo
RTMPAPPrivIoctlShow(): after check, this_char=psinfo, value=
Show_PSTable_Proc(): arg=
Dump MacTable entries info, EntType=0x20001

HT Operating Mode : 0

pAd->MacTab.fAnyStationInPsm : 0
pAd->dequeu_fail_cnt : 0

MAC                     EntryType       AID     BSS     PSM     psm     ipsm    iips    sktx    redt    port    queu    pktnum        psnum   hinum#  hidrp#  TXOK/PER        APSD    rcount
  PID USER       VSZ STAT COMMAND
    1 admin     1076 S    init
    2 admin        0 SW   [kthreadd]
    3 admin        0 SW   [ksoftirqd/0]
    4 admin        0 SW   [kworker/0:0]
    5 admin        0 SW   [kworker/u:0]
    6 admin        0 SW<  [khelper]
    7 admin        0 SW   [kworker/u:1]
   42 admin        0 SW   [sync_supers]
   44 admin        0 SW   [bdi-default]
   46 admin        0 SW<  [kblockd]
   69 admin        0 SW   [kswapd0]
   71 admin        0 SW<  [crypto]
  630 admin        0 SW   [mtdblock0]
  635 admin        0 SW   [mtdblock1]
  640 admin        0 SW   [mtdblock2]
  645 admin        0 SW   [mtdblock3]
  650 admin        0 SW   [mtdblock4]
  655 admin        0 SW   [mtdblock5]
  660 admin        0 SW   [mtdblock6]
  678 admin        0 SW   [kworker/0:1]
  728 admin     1068 S    telnetd
  745 admin     2848 S    cos
  746 admin     1080 S    /bin/sh
  749 admin     2052 S    igmpd
  752 admin     2076 S    mldProxy
  839 admin     2848 S    cos
  840 admin     2848 S    cos
  841 admin     2848 S    cos
  860 admin     2020 S    ntpc
  865 admin     2028 S    dyndns /var/tmp/dconf/dyndns.conf
  868 admin     2028 S    noipdns /var/tmp/dconf/noipdns.conf
  871 admin     2028 S    cmxdns /var/tmp/dconf/cmxdns.conf
  879 admin     1080 S    -sh
 1017 admin        0 SW   [RtmpCmdQTask]
 1018 admin        0 SW   [RtmpWscTask]
 1019 admin        0 SW   [RtmpMlmeTask]
 1032 admin     1244 S    wlNetlinkTool
 1036 admin     1080 S    wscd -i ra0 -m 1 -w /var/tmp/wsc_upnp/
 1040 admin     1244 S    wlNetlinkTool
 1042 admin     1244 S    wlNetlinkTool
 1055 admin     2600 S    httpd
 1067 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1070 admin     2016 S    dnsProxy
 1073 admin     1068 S    dhcpd /var/tmp/dconf/udhcpd.conf
 1092 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1093 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1094 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1096 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1097 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1098 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1099 admin     1764 S    upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port
 1100 admin     1152 S    dhcp6s -c /var/tmp/dconf/dhcp6s_br0.conf -P /var/run
 1101 admin     2600 S    tmpd
 1104 admin     2488 S    tdpd
 1112 admin      988 S    dhcpc
 1113 admin     1076 S    sh
 1123 admin     1136 S    dropbear -p 22 -r /var/tmp/dropbear/dropbear_rsa_hos
 1124 admin     1036 S    zebra -d -f /var/tmp/dconf/zebra.conf
 1138 admin     2020 S    diagTool
 1253 admin     1076 S    busybox sh
 1773 admin     1064 S    sh info.sh
 1902 admin     1068 R    ps
MemTotal:          61432 kB
MemFree:           35140 kB
Buffers:            2488 kB
Cached:             9824 kB
SwapCached:            0 kB
Active:             6404 kB
Inactive:           8728 kB
Active(anon):       2820 kB
Inactive(anon):        0 kB
Active(file):       3584 kB
Inactive(file):     8728 kB
Unevictable:           0 kB
Mlocked:               0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Dirty:                 0 kB
Writeback:             0 kB
AnonPages:          2828 kB
Mapped:             2460 kB
Shmem:                 0 kB
Slab:               6980 kB
SReclaimable:        724 kB
SUnreclaim:         6256 kB
KernelStack:         496 kB
PageTables:          428 kB
NFS_Unstable:          0 kB
Bounce:                0 kB
WritebackTmp:          0 kB
CommitLimit:       61432 kB
Committed_AS:       8792 kB
VmallocTotal:    1048372 kB
VmallocUsed:        3600 kB
VmallocChunk:    1036896 kB
Node 0, zone   Normal      4      1     24     15      9      3      2      2      3      2      6
RTMPAPPrivIoctlShow(): Before check, this_char=psinfo
RTMPAPPrivIoctlShow(): after check, this_char=psinfo, value=
Show_PSTable_Proc(): arg=
Dump MacTable entries info, EntType=0x20001

HT Operating Mode : 0

pAd->MacTab.fAnyStationInPsm : 0
pAd->dequeu_fail_cnt : 0

MAC                     EntryType       AID     BSS     PSM     psm     ipsm    iips    sktx    redt    port    queu    pktnum        psnum   hinum#  hidrp#  TXOK/PER        APSD    rcount

```

We can also see the partitions and which one we have write permissions on, which is useful for transferring binaries. still, being the most privileged user, we could remount `ro` partitions as `rw` if we wanted to change some important binary or simply overwrite the filesystem.
```bash
~ # mount
rootfs on / type rootfs (rw)
/dev/root on / type squashfs (ro,relatime)
proc on /proc type proc (rw,relatime)
ramfs on /var type ramfs (rw,relatime)
devpts on /dev/pts type devpts (rw,relatime,mode=600)
/sys on /sys type sysfs (rw,relatime)
~ #
```

## Firmware Extraction
On the router's own web interface we can see the firmware version, a very old and vulnerable one:
```bash
Status

Firmware Version:
0.9.1 3.16 v0001.0 Build 161012 Rel.33002n

Hardware Version:
TL-WR841N v13 00000013

LAN

MAC Address:
D4:6E:0E:57:1E:E0

IP Address:
192.168.0.1

Subnet Mask:
255.255.255.0
```

Now we're going to try to extract the firmware, but for that it would be convenient to obtain the model of the router's flash.

![](imgs/blog/10TpLinkRouterResearch/20251111221321.png)

as we showed earlier it is **`25Q64CS16`**, so we can look for the datasheet to get more information

Here we have the [datasheet](https://www.tme.eu/Document/adfc3a1a269cb52cdae9532d711c82d9/gd25q64c.pdf). The first thing we can see is basic information about the flash memory.

![](imgs/blog/10TpLinkRouterResearch/20251018004145.png)

This is the connection diagram which tells us what each pin is:

![](imgs/blog/10TpLinkRouterResearch/20251018004216.png)

The communication protocol is i2c, which is why we are going to try to connect via pins and attempt to obtain the firmware without the need to desolder the microchip (spoiler: it was not possible)

the description of the aforementioned:

![](imgs/blog/10TpLinkRouterResearch/20251018004226.png)

Read protocol (`0x03`)

![](imgs/blog/10TpLinkRouterResearch/20251018004306.png)

Now we proceed to connect to the chip physically:

![](imgs/blog/10TpLinkRouterResearch/20251112135208.png)

If we pass it to a logic analyzer we see the outgoing data:

![](imgs/blog/10TpLinkRouterResearch/20251018010804.png)

![](imgs/blog/10TpLinkRouterResearch/20251018010814.png)

With this we can conclude that there is data movement when the router powers on, what we can do is connect a firmware extraction tool so we can start reverse engineering...

### Firmware CH341 Extraction
Now we're going to use the **CH341** device to extract the firmware:

![](imgs/blog/10TpLinkRouterResearch/20251112140515.png)

The problem with this device is that it runs at 5V while our chip runs at 3.3V, which is why using it as-is would fry the chip, so a modification is necessary.

We're going to switch the board to 3.3V; we simply have to make two joins as shown below

before:

![](imgs/blog/10TpLinkRouterResearch/20251112140846.png)

after:

![](imgs/blog/10TpLinkRouterResearch/20251112141111.png)

as we can see it's not the cleanest job I've done but the important thing is that it works, so now we can test it with the multimeter:

![](imgs/blog/10TpLinkRouterResearch/20251112141201.png)

From what we see it's fine, so we can connect the clips to the chip:

![](imgs/blog/10TpLinkRouterResearch/20251112141817.png)

this would be the setup:

![](imgs/blog/10TpLinkRouterResearch/20251112141706.png)

now we would have to obtain the firmware with the **`ch341`** program. Unfortunately I couldn't do it this way, it simply didn't detect the chip. I tried on both Windows and Linux and also repositioning the clips a thousand times and trying different boards but nothing in the end :(
### Firmware Extraction Alternative: tftp
As we saw earlier we are able to execute the `tftp` command, so we could try to set up a tftp server using `atftp` and upload a complete version of busybox.

We also saw that we can `r/w` permissions on the `/var` folder so we can use it as our personal storage on the UART console.

The binary is compiled for MIPS, which we will have to keep in mind if we want to modify, reflash, or tweak any part of the system.
```bash
root@ack:/srv/tftp# ls
busybox-mipsel
root@ack:/srv/tftp# file busybox-mipsel
busybox-mipsel: ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), statically linked, stripped
```

We successfully transferred `busybox` binary
```bash
/var # tftp -g -r busybox-mipsel 192.168.0.100
busybox-mipsel         0% |                               |  6144   0:04:15 ETAMTSmartCarrierSense(): CSC=L
busybox-mipsel       100% |*******************************|  1539k  0:00:00 ETA
/var # MTSmartCarrierSense(): CSC=H (Default)
ls
lock            run             Wireless        passwd          busybox-mipsel
log             tmp             dev             l2tp
/var #
```

We can start obtaining very useful info:
```bash
/var # ./busybox-mipsel uname -a
Linux TL-WR841N 2.6.36 #83 Wed Oct 12 08:54:10 HKT 2016 mips GNU/Linux
```

we can list internally open ports, both TCP and UDP, and the ports only open locally.
```bash
/var # ./busybox-mipsel netstat -lptnu
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:20002         0.0.0.0:*               LISTEN      1091/tmpd
tcp        0      0 0.0.0.0:1900            0.0.0.0:*               LISTEN      1065/upnpd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1053/httpd
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1135/dropbear
tcp        0      0 :::22                   :::*                    LISTEN      1135/dropbear
tcp        0      0 :::23                   :::*                    LISTEN      728/telnetd
udp        0      0 127.0.0.1:48400         0.0.0.0:*                           1065/upnpd
udp        0      0 0.0.0.0:20002           0.0.0.0:*                           1102/tdpd
udp        0      0 0.0.0.0:67              0.0.0.0:*                           1071/dhcpd
udp        0      0 0.0.0.0:1900            0.0.0.0:*                           1065/upnpd
udp        0      0 0.0.0.0:44402           0.0.0.0:*                           1065/upnpd
udp        0      0 :::547                  :::*                                1088/dhcp6s
/var #
/var #
```

As we saw before, every process is running as `admin`:
```bash
/var # ./busybox-mipsel ps ww
PID   USER     TIME   COMMAND
    1 admin      0:00 init
    2 admin      0:00 [kthreadd]
    3 admin      0:00 [ksoftirqd/0]
    4 admin      0:00 [kworker/0:0]
    5 admin      0:00 [kworker/u:0]
    6 admin      0:00 [khelper]
    7 admin      0:00 [kworker/u:1]
   42 admin      0:00 [sync_supers]
   44 admin      0:00 [bdi-default]
   46 admin      0:00 [kblockd]
   69 admin      0:00 [kswapd0]
   71 admin      0:00 [crypto]
  630 admin      0:00 [mtdblock0]
  635 admin      0:00 [mtdblock1]
  640 admin      0:01 [mtdblock2]
  645 admin      0:00 [mtdblock3]
  650 admin      0:00 [mtdblock4]
  655 admin      0:00 [mtdblock5]
  660 admin      0:00 [mtdblock6]
  678 admin      0:00 [kworker/0:1]
  728 admin      0:00 telnetd
  745 admin      0:00 cos
  746 admin      0:00 /bin/sh
  749 admin      0:00 igmpd
  752 admin      0:00 mldProxy
  839 admin      0:00 cos
  840 admin      0:00 cos
  841 admin      0:00 cos
  860 admin      0:00 ntpc
  865 admin      0:00 dyndns /var/tmp/dconf/dyndns.conf
  868 admin      0:00 noipdns /var/tmp/dconf/noipdns.conf
  871 admin      0:00 cmxdns /var/tmp/dconf/cmxdns.conf
 1017 admin      0:00 [RtmpCmdQTask]
 1018 admin      0:00 [RtmpWscTask]
 1019 admin      0:01 [RtmpMlmeTask]
 1030 admin      0:00 wlNetlinkTool
 1034 admin      0:00 wlNetlinkTool
 1035 admin      0:00 wlNetlinkTool
 1036 admin      0:00 wscd -i ra0 -m 1 -w /var/tmp/wsc_upnp/
 1053 admin      0:00 httpd
 1065 admin      0:00 upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port 80 -u
 1068 admin      0:00 dnsProxy
 1071 admin      0:00 dhcpd /var/tmp/dconf/udhcpd.conf
 1088 admin      0:00 dhcp6s -c /var/tmp/dconf/dhcp6s_br0.conf -P /var/run/dhcp
 1091 admin      0:00 tmpd
 1095 admin      0:00 upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port 80 -u
 1096 admin      0:00 upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port 80 -u
 1097 admin      0:00 upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port 80 -u
 1098 admin      0:00 upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port 80 -u
 1099 admin      0:00 upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port 80 -u
 1100 admin      0:00 upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port 80 -u
 1101 admin      0:00 upnpd -L br0 -W eth0.2 -en 1 -P eth0.2 -nat 0 -port 80 -u
 1102 admin      0:00 tdpd
 1108 admin      0:44 dhcpc
 1119 admin      0:00 zebra -d -f /var/tmp/dconf/zebra.conf
 1135 admin      0:00 dropbear -p 22 -r /var/tmp/dropbear/dropbear_rsa_host_key
 1136 admin      0:00 diagTool
 2794 admin      0:00 ./busybox-mipsel ps ww
```


Now we are going to transfer all the firmware blocks (`mtdblockX`) to the host machine using `tftp`
```bash
/var # ls -la /dev
crw-r--r--    1    1,   5 zero
crw-r--r--    1   10, 130 watchdog
crw-r--r--    1  215,   0 voip
crw-r--r--    1  245,   0 vdsp
crw-r--r--    1    1,   9 urandom
crw-r--r--    1    3,   2 ttyp2
crw-r--r--    1    3,   1 ttyp1
crw-r--r--    1    3,   0 ttyp0
crw-r--r--    1  188,   9 ttyUSB9
crw-r--r--    1  188,   8 ttyUSB8
crw-r--r--    1  188,   7 ttyUSB7
crw-r--r--    1  188,   6 ttyUSB6
crw-r--r--    1  188,   5 ttyUSB5
crw-r--r--    1  188,   4 ttyUSB4
crw-r--r--    1  188,   3 ttyUSB3
crw-r--r--    1  188,   2 ttyUSB2
crw-r--r--    1  188,  15 ttyUSB15
crw-r--r--    1  188,  14 ttyUSB14
crw-r--r--    1  188,  13 ttyUSB13
crw-r--r--    1  188,  12 ttyUSB12
crw-r--r--    1  188,  11 ttyUSB11
crw-r--r--    1  188,  10 ttyUSB10
crw-r--r--    1  188,   1 ttyUSB1
crw-r--r--    1  188,   0 ttyUSB0
crw-r--r--    1    4,  65 ttyS1
crw-r--r--    1    4,  64 ttyS0
crw-r--r--    1  166,   9 ttyACM9
crw-r--r--    1  166,   8 ttyACM8
crw-r--r--    1  166,   7 ttyACM7
crw-r--r--    1  166,   6 ttyACM6
crw-r--r--    1  166,   5 ttyACM5
crw-r--r--    1  166,   4 ttyACM4
crw-r--r--    1  166,   3 ttyACM3
crw-r--r--    1  166,   2 ttyACM2
crw-r--r--    1  166,  15 ttyACM15
crw-r--r--    1  166,  14 ttyACM14
crw-r--r--    1  166,  13 ttyACM13
crw-r--r--    1  166,  12 ttyACM12
crw-r--r--    1  166,  11 ttyACM11
crw-r--r--    1  166,  10 ttyACM10
crw-r--r--    1  166,   1 ttyACM1
crw-r--r--    1  166,   0 ttyACM0
crw-r--r--    1    4,   0 tty0
crw-r--r--    1    5,   0 tty
crw-r--r--    1  251,   0 slic
drwxrwxr-x    2         3 shm
brw-r--r--    1    8,  18 sdb2
brw-r--r--    1    8,  17 sdb1
brw-r--r--    1    8,  16 sdb
brw-r--r--    1    8,   2 sda2
brw-r--r--    1    8,   1 sda1
brw-r--r--    1    8,   0 sda
crw-r--r--    1  253,   0 rdm0
crw-r--r--    1    1,   8 random
crw-r--r--    1  111,   2 qostype
crw-r--r--    1    2,   2 ptyp2
crw-r--r--    1    2,   1 ptyp1
crw-r--r--    1    2,   0 ptyp0
drwxr-xr-x    2         0 pts
crw-r--r--    1    5,   2 ptmx
crw-r--r--    1  108,   0 ppp
crw-r--r--    1  200,   0 pmap
crw-r--r--    1    1,   3 null
drwxrwxr-x    2        26 net
crw-r--r--    1  250,   0 mtr0
brw-r--r--    1   31,   6 mtdblock6
brw-r--r--    1   31,   5 mtdblock5
brw-r--r--    1   31,   4 mtdblock4
brw-r--r--    1   31,   3 mtdblock3
brw-r--r--    1   31,   2 mtdblock2
brw-r--r--    1   31,   1 mtdblock1
brw-r--r--    1   31,   0 mtdblock0
crw-r--r--    1   90,  12 mtd6
crw-r--r--    1   90,  10 mtd5
crw-r--r--    1   90,   8 mtd4
crw-r--r--    1   90,   6 mtd3
crw-r--r--    1   90,   4 mtd2
crw-r--r--    1   90,   2 mtd1
crw-r--r--    1   90,   0 mtd0
brw-r--r--    1   31,   0 mtd
crw-r--r--    1   10, 151 led
crw-r--r--    1  220,   0 hwnat0
crw-r--r--    1  200,   0 flash0
crw-r--r--    1   63,   0 dk0
crw-r--r--    1    5,   1 console
brw-r--r--    1   31,   5 caldata
crw-r--r--    1  100,   0 adsl0
crw-r--r--    1  230,   0 acl0
crw-r--r--    1  240,   0 ac0
crw-r--r--    1  235,   0 FxsDrv
crw-r--r--    1  234,   0 AclDsp
drwxrwxr-x   13       177 ..
drwxrwxr-x    5      1274 .
/var # 
```

```bash
/var # ./busybox-mipsel tftp -p -r mtdblock0 -l ./mtdblock0 192.168.0.100
mtdblock0            100% |*******************************|   128k  0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtdblock1 -l ./mtdblock1 192.168.0.100
mtdblock1             13% |****                           |   167k  0:00:06 ETAMTSmartCarrierSense(): CSC=L
mtdblock1            100% |*******************************|  1280k  0:00:00 ETA
/var # MTSmartCarrierSense(): CSC=H (Default)

/var # ./busybox-mipsel tftp -p -r mtdblock2 -l ./mtdblock2 192.168.0.100
mtdblock2              2% |                               |   172k  0:00:36 ETAMTSmartCarrierSense(): CSC=L
mtdblock2            100% |*******************************|  6528k  0:00:00 ETA
/var # MTSmartCarrierSense(): CSC=H (Default)

/var # ./busybox-mipsel tftp -p -r mtdblock3 -l ./mtdblock3 192.168.0.100
mtdblock3            100% |*******************************| 65536   0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtdblock4 -l ./mtdblock4 192.168.0.100
mtdblock4            100% |*******************************| 65536   0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtdblock5 -l ./mtdblock5 192.168.0.100
mtdblock5            100% |*******************************| 65536   0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtdblock6 -l ./mtdblock6 192.168.0.100
mtdblock6            100% |*******************************| 65536   0:00:00 ETA
/var #
```

```bash
/var # ./busybox-mipsel tftp -p -r mtd -l ./mtd 192.168.0.100
mtd                  100% |*******************************|   128k  0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtd0 -l ./mtd0 192.168.0.100
mtd0                 100% |*******************************|   128k  0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtd1 -l ./mtd1 192.168.0.100
mtd1                   8% |**                             |   103k  0:00:11 ETAMTSmartCarrierSense(): CSC=L
mtd1                 100% |*******************************|  1280k  0:00:00 ETA
/var # MTSmartCarrierSense(): CSC=H (Default)

/var # ./busybox-mipsel tftp -p -r mtd2 -l ./mtd2 192.168.0.100
mtd2                   0% |                               | 47616   0:02:19 ETAMTSmartCarrierSense(): CSC=L
mtd2                 100% |*******************************|  6528k  0:00:00 ETA
/var # MTSmartCarrierSense(): CSC=H (Default)

/var # ./busybox-mipsel tftp -p -r mtd3 -l ./mtd3 192.168.0.100
mtd3                 100% |*******************************| 65536   0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtd4 -l ./mtd4 192.168.0.100
mtd4                 100% |*******************************| 65536   0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtd5 -l ./mtd5 192.168.0.100
mtd5                 100% |*******************************| 65536   0:00:00 ETA
/var # ./busybox-mipsel tftp -p -r mtd6 -l ./mtd6 192.168.0.100
mtd6                 100% |*******************************| 65536   0:00:00 ETA
/var #

```

We can check the md5 hashes to ensure data integrity

![](imgs/blog/10TpLinkRouterResearch/20251023231620.png)

We see that `mtdX` and `mtdblockX` are basically the same archives, then we can do the same on our host to ensure integrity:
```bash
root@ack:/srv/tftp# md5sum mtd*
8f1725b043f8aca888c5bc8e89a1a5a4  mtd
8f1725b043f8aca888c5bc8e89a1a5a4  mtd0
a4fa7e23afd5ffa32886fcd9405af23c  mtd1
813c6450e0304dd4bb70f71fcae8081c  mtd2
f076d2722f252f1312752af08bd645c6  mtd3
3f9e8c85155c50ae473d4e986d33e256  mtd4
ecb99e6ffea7be1e5419350f725da86b  mtd5
7064f71266e06dec129f7773e6eeed49  mtd6
8f1725b043f8aca888c5bc8e89a1a5a4  mtdblock0
a4fa7e23afd5ffa32886fcd9405af23c  mtdblock1
813c6450e0304dd4bb70f71fcae8081c  mtdblock2
f076d2722f252f1312752af08bd645c6  mtdblock3
3f9e8c85155c50ae473d4e986d33e256  mtdblock4
ecb99e6ffea7be1e5419350f725da86b  mtdblock5
7064f71266e06dec129f7773e6eeed49  mtdblock6
```
There are no I/O errors, we got the data as-is

Now we can analyze the files
```bash
root@ack:/srv/tftp# file mtd*
mtd:       data
mtd0:      data
mtd1:      data
mtd2:      Squashfs filesystem, little endian, version 4.0, xz compressed, 3281080 bytes, 590 inodes, blocksize: 131072 bytes, created: Wed Oct 12 01:10:05 2016
mtd3:      data
mtd4:      data
mtd5:      ISO-8859 text, with very long lines (65536), with no line terminators
mtd6:      data
mtdblock0: data
mtdblock1: data
mtdblock2: Squashfs filesystem, little endian, version 4.0, xz compressed, 3281080 bytes, 590 inodes, blocksize: 131072 bytes, created: Wed Oct 12 01:10:05 2016
mtdblock3: data
mtdblock4: data
mtdblock5: ISO-8859 text, with very long lines (65536), with no line terminators
mtdblock6: data
```
We notice that we have a `squashfs` there which we can extract the full filesystem from using `unsquashfs`

### Squash File System
```bash
root@ack:~/Desktop/Firmware/mtdblock2# unsquashfs mtdblock2.bin
Parallel unsquashfs: Using 8 processors
548 inodes (448 blocks) to write

[==========================================================================================|] 996/996 100%

created 399 files
created 42 directories
created 60 symlinks
created 89 devices
created 0 fifos
created 0 sockets
created 0 hardlinks
root@ack:~/Desktop/Firmware/mtdblock2# ls
mtdblock2.bin  mtdblock2.bin.bak  squashfs-root
root@ack:~/Desktop/Firmware/mtdblock2# 
```

```bash
root@ack:~/Desktop/Firmware/mtdblock2/squashfs-root# ls -la
total 52
drwxrwxr-x 13 root root 4096 oct 12  2016 .
drwxr-xr-x  3 root root 4096 oct 24 18:58 ..
drwxrwxr-x  2 root root 4096 oct 12  2016 bin
drwxrwxr-x  5 root root 4096 oct 12  2016 dev
drwxrwxr-x  5 root root 4096 oct 12  2016 etc
drwxrwxr-x  3 root root 4096 oct 12  2016 lib
lrwxrwxrwx  1 root root   11 oct 12  2016 linuxrc -> bin/busybox
drwxrwxr-x  2 root root 4096 oct 12  2016 mnt
drwxrwxr-x  2 root root 4096 oct 12  2016 proc
drwxrwxr-x  2 root root 4096 oct 12  2016 sbin
drwxrwxr-x  2 root root 4096 oct 12  2016 sys
drwxrwxr-x  4 root root 4096 oct 12  2016 usr
drwxrwxr-x  2 root root 4096 oct 12  2016 var
drwxrwxr-x  9 root root 4096 oct 12  2016 web
```

We can see that there are a lot of references to `busybox`, we can see the **Dropbear** binary, which is the open service on port 22 (SSH).
```bash
root@ack:~/Desktop/Firmware/mtdblock2/squashfs-root# tree | grep -i dropbear
│   │   ├── dropbear -> dropbearmulti
│   │   ├── dropbearkey -> dropbearmulti
│   │   ├── dropbearmulti
│   │   ├── scp -> dropbearmulti
root@ack:~/Desktop/Firmware/mtdblock2/squashfs-root#
```

#### Dropbear sshd 2012.55
We found Dropbear configuration files and private keys, we also found a hash which we can try to crack
```bash
/var/tmp/dropbear # ls
dropbearpwd            dropbear_rsa_host_key  dropbear_dss_host_key
/var/tmp/dropbear # cat dropbearpwd
username:admin
password:21232f297a57a5a743894a0e4a801fc3
/var/tmp/dropbear #
```

We transferred the files as before and proceeded to analyze the hash.
```bash
root@ack:~/Desktop/blog/routerTpLink/dropbear# hashid dropbearhash
--File 'dropbearhash'--
Analyzing '21232f297a57a5a743894a0e4a801fc3'
[+] MD2
[+] MD5
[+] MD4
[+] Double MD5
[+] LM
[+] RIPEMD-128
[+] Haval-128
[+] Tiger-128
[+] Skein-256(128)
[+] Skein-512(128)
[+] Lotus Notes/Domino 5
[+] Skype
[+] Snefru-128
[+] NTLM
[+] Domain Cached Credentials
[+] Domain Cached Credentials 2
[+] DNSSEC(NSEC3)
[+] RAdmin v2.x
```

Now we will use `hashcat` to break the password.
```bash
root@ack:~/Desktop/blog/routerTpLink/dropbear# hashcat -a 3 dropbearhash -m 0
hashcat (v6.2.6) starting

nvmlDeviceGetFanSpeed(): Not Supported

CUDA API (CUDA 11.4)
====================
* Device #1: NVIDIA GeForce RTX 3060 Laptop GPU, 5833/5946 MB, 30MCU

OpenCL API (OpenCL 3.0 CUDA 11.4.557) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #2: NVIDIA GeForce RTX 3060 Laptop GPU, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Brute-Force
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

...
...
Candidates.#1....: sarv -> Xqxv
Hardware.Mon.#1..: Temp: 56c Util: 72% Core:1552MHz Mem:6000MHz Bus:4

21232f297a57a5a743894a0e4a801fc3:admin

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 21232f297a57a5a743894a0e4a801fc3
Time.Started.....: Sun Nov  2 20:04:29 2025 (0 secs)
Time.Estimated...: Sun Nov  2 20:04:29 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?1?2?2?2?2 [5]
Guess.Charset....: -1 ?l?d?u, -2 ?l?d, -3 ?l?d*!$@_, -4 Undefined
Guess.Queue......: 5/15 (33.33%)
Speed.#1.........:  3094.9 MH/s (6.82ms) @ Accel:64 Loops:62 Thr:512 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 60948480/104136192 (58.53%)
Rejected.........: 0/60948480 (0.00%)
Restore.Point....: 0/1679616 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-62 Iteration:0-62
Candidate.Engine.: Device Generator
Candidates.#1....: sarie -> Xc05k
Hardware.Mon.#1..: Temp: 56c Util: 69% Core:1582MHz Mem:6000MHz Bus:4

Started: Sun Nov  2 20:04:26 2025
Stopped: Sun Nov  2 20:04:30 2025
root@ack:~/Desktop/blog/routerTpLink/dropbear#
```

The password is `admin`, now we can try to connect via ssh
```bash
root@ack:~/Desktop/blog/routerTpLink/dropbear# ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss -c 3des-cbc admin@192.168.0.1
The authenticity of host '192.168.0.1 (192.168.0.1)' can't be established.
DSA key fingerprint is SHA256:sRpKaBgMeeBrdrMqR5HXbnNklh2ViqJn8Y3CKwusxSM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.1' (DSA) to the list of known hosts.
admin@192.168.0.1's password:
PTY allocation request failed on channel 0
shell request failed on channel 0
root@ack:~/Desktop/blog/routerTpLink/dropbear#
```
The configuration does not allow remote connection.

### `745/cos` bug
```bash
/var # ./busybox-mipsel netstat -lnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:20002         0.0.0.0:*               LISTEN      1106/tmpd
tcp        0      0 0.0.0.0:1900            0.0.0.0:*               LISTEN      1072/upnpd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1060/httpd
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1147/dropbear
tcp        0      0 :::22                   :::*                    LISTEN      1147/dropbear
tcp        0      0 :::23                   :::*                    LISTEN      728/telnetd
udp        0      0 0.0.0.0:48400           0.0.0.0:*                           745/cos
udp        0      0 127.0.0.1:47640         0.0.0.0:*                           1072/upnpd
udp        0      0 0.0.0.0:20002           0.0.0.0:*                           1109/tdpd
udp        0      0 0.0.0.0:33195           0.0.0.0:*                           1072/upnpd
udp        0      0 0.0.0.0:67              0.0.0.0:*                           1078/dhcpd
udp        0      0 0.0.0.0:1900            0.0.0.0:*                           1072/upnpd
udp        0      0 :::547                  :::*                                1105/dhcp6s
raw        0      0 0.0.0.0:2               0.0.0.0:*               2           749/igmpd
raw        0      0 0.0.0.0:255             0.0.0.0:*               255         745/cos
raw        0      0 0.0.0.0:255             0.0.0.0:*               255         1072/upnpd
raw        0      0 :::58                   :::*                    58          752/mldProxy
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
unix  2      [ ACC ]     STREAM     LISTENING        635 1128/zebra          /var/tmp/.zserv
/var #
```

After running `nc -u 192.168.0.1 48400 < /dev/urandom`
```bash
/var # ./busybox-mipsel netstat -lnp
Algorithmics/MIPS FPU Emulator v1.5
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:20002         0.0.0.0:*               LISTEN      1093/tmpd
tcp        0      0 0.0.0.0:1900            0.0.0.0:*               LISTEN      1066/upnpd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1054/httpd
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1136/dropbear
tcp        0      0 :::22                   :::*                    LISTEN      1136/dropbear
tcp        0      0 :::23                   :::*                    LISTEN      728/telnetd
udp        0      0 127.0.0.1:48400         0.0.0.0:*                           1066/upnpd
udp        0      0 0.0.0.0:20002           0.0.0.0:*                           1103/tdpd
udp        0      0 0.0.0.0:67              0.0.0.0:*                           1072/dhcpd
udp        0      0 0.0.0.0:1900            0.0.0.0:*                           1066/upnpd
udp        0      0 0.0.0.0:44402           0.0.0.0:*                           1066/upnpd
udp        0      0 :::547                  :::*                                1089/dhcp6s
raw        0      0 0.0.0.0:2               0.0.0.0:*               2           749/igmpd
raw        0      0 0.0.0.0:255             0.0.0.0:*               255         745/cos
raw        0      0 0.0.0.0:255             0.0.0.0:*               255         1066/upnpd
raw        0      0 :::58                   :::*                    58          752/mldProxy
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node PID/Program name    Path
unix  2      [ ACC ]     STREAM     LISTENING        639 1120/zebra          /var/tmp/.zserv
/var #

```
so there is something potentially exploitable there since the process seems to have crashed.

the following command:
```bash
nc -u 192.168.0.1 48400 < /dev/urandom
```
I use as a very crude "fuzzer" just to do quick tests or a general sweep.

### BusyBox v1.19.2 `/sbin/init`
We also notice that the `/sbin/init` binary is actually `busybox`, it is exactly the same, it only spawns a shell within that same busybox.
```bash
/var # ./busybox-mipsel md5sum /sbin/init /bin/busybox
Algorithmics/MIPS FPU Emulator v1.5
0ea9fcd8dfd39e663ba0af25b9cdcb97  /sbin/init
0ea9fcd8dfd39e663ba0af25b9cdcb97  /bin/busybox
/var #
```

Also, testing the `init` command we notice that the configuration file is `/etc/inittab`, the firmware could be modified, altered, and reflashed to weaponize the router.
```bash
~ # /sbin/init -q
reloading /etc/inittab
~ #
~ # ls /etc/inittab
/etc/inittab
~ # cat /etc/inittab
::sysinit:/etc/init.d/rcS
ttyS1::respawn:/bin/sh
~ #
```

#### Busybox Char escape vuln
We also have an external vulnerability which is the Busybox char escape issue but I couldn't trigger it sufficiently to provide anything conclusive. Still, it was worth a small mention.
```bash
/var # busybox 2>&1 | { IFS= read -r first || true; echo "$first"; }
```

## Desoldering the Flash
Getting the firmware via `tftp` and failing with the **CH341** felt insufficient, so we desoldered the chip and read it with the **XGECU T48**

Once desoldered we adapt the chip to the **XGECU**:

![](imgs/blog/10TpLinkRouterResearch/20251112155543.png)

This would be the setup:

![](imgs/blog/10TpLinkRouterResearch/20251112155241.png)

Once we have the setup we can proceed with the program to read the flash:

![](imgs/blog/10TpLinkRouterResearch/20251104001711.png)

Here we have the flash contents:

![](imgs/blog/10TpLinkRouterResearch/20251104001801.png)

Once downloaded we can start analyzing the firmware and extract it with binwalk:
```bash
root@ack:~/Desktop/blog/routerTpLink/firmware/physical# binwalk GD25Q64C.BIN

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
79968         0x13860         U-Boot version string, "U-Boot 1.1.3 (Oct 12 2016 - 08:49:46)"
131584        0x20200         LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size:3511364 bytes
1441792       0x160000        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3281080 bytes, 590 inodes, blocksize: 131072 bytes, created: 2016-10-12 01:10:05

root@ack:~/Desktop/blog/routerTpLink/firmware/physical# md5sum GD25Q64C.BIN ../firmware
8d0f869f9f1fcee35192ef857f47319b  GD25Q64C.BIN
bfc99913851b4db89571f215d4074067  ../firmware

root@ack:~/Desktop/blog/routerTpLink/firmware/physical#
```
We also see that both images differ, the one obtained physically and the one obtained via `tftp`

Here we have the firmware entropy, so it seems nothing is encrypted

![](imgs/blog/10TpLinkRouterResearch/20251104151656.png)

### U-BOOT RE
```bash
root@ack:~/Desktop/blog/routerTpLink/firmware/physical# dd if=GD25Q64C.BIN of=u-boot.bin bs=1 skip=$((0x13860)) count=$((0x20200 - 0x13860))
51616+0 records in
51616+0 records out
51616 bytes (52 kB, 50 KiB) copied, 0,0394169 s, 1,3 MB/s
root@ack:~/Desktop/blog/routerTpLink/firmware/physical# file u-boot.bin
u-boot.bin: data
root@ack:~/Desktop/blog/routerTpLink/firmware/physical#
```
We can obtain the `u-boot.bin`. We can also search for potential strings to later load it into IDA

```bash
root@ack:~/Desktop/blog/routerTpLink/firmware/physical# strings -n 10 u-boot.bin | grep -i "mips"
MIPS 64 Bit
No Linux MIPS Ramdisk Image
root@ack:~/Desktop/blog/routerTpLink/firmware/physical# strings -n 10 u-boot.bin | grep -i "cpu"
Software CPU Reset Occurred
 ##### The CPU freq = %d MHZ ####
 Normal Mode,Packet received from CPU port,plen=%d
reset   - Perform RESET of the CPU
Invalid CPU
```

once loaded in IDA we can find the `Init` function quite easily by size:

![](imgs/blog/10TpLinkRouterResearch/20251112160718.png)

**IMPORTANT: we must load the binary with the base address `0xBC000000` to fix the imports, otherwise it's a complete mess**

This is the boot initialization function:
```c
// write access to const memory has been detected, the output may be wrong!
int __fastcall Init(int a1, int a2)
{
  int v2; // $k0
  int v4; // $v0
  unsigned int v5; // $v0
  int *v6; // $s4
  int v7; // $v1
  int v8; // $a1
  char *v9; // $a2
  char *v10; // $v1
  _DWORD *v11; // $s3
  int v12; // $v1
  int v13; // $s1
  int v14; // $s0
  char *v15; // $s2
  _BYTE **v16; // $a1
  int v17; // $a2
  char v18; // $v0
  int v19; // $v0
  int v20; // $v0
  unsigned __int32 v21; // $s0
  int v22; // $v1
  int v23; // $t0
  int v24; // $v1
  int v25; // $t0
  int v26; // $s3
  int v27; // $v0
  int v28; // $s2
  int v30; // $s1
  int v31; // $s0
  int v33; // $s1
  int v34; // $v0
  _BYTE v35[16]; // [sp+20h] [-40h] BYREF
  unsigned __int8 v36; // [sp+30h] [-30h] BYREF
  char v37[7]; // [sp+31h] [-2Fh] BYREF
  char v38[4]; // [sp+38h] [-28h] BYREF
  _BYTE *v39; // [sp+3Ch] [-24h]
  _BYTE v40[8]; // [sp+40h] [-20h] BYREF
  _BYTE *v41; // [sp+48h] [-18h]
  char v42[4]; // [sp+50h] [-10h] BYREF
  _BYTE *v43; // [sp+54h] [-Ch]
  _BYTE *v44; // [sp+58h] [-8h] BYREF
  int v45; // [sp+5Ch] [-4h] BYREF

  sub_BC010F70(0x83FF0000, v2, 36);
  MEMORY[0x83FF0004] |= 1u;
  if ( ((MEMORY[0xB000002C] >> 1) & 1) != 0 )
  {
    v4 = 480000000;
LABEL_7:
    dword_BC047BD0 = v4;
    goto LABEL_9;
  }
  if ( (MEMORY[0xB000002C] & 1) != 0 )
  {
    if ( ((MEMORY[0xB0000010] >> 6) & 1) != 0 )
      v4 = 40000000;
    else
      v4 = 25000000;
    goto LABEL_7;
  }
  dword_BC047BD0 = 575000000;
LABEL_9:
  MEMORY[0xB000003C] |= 0x100u;
  MEMORY[0xB0000064] &= 0xFFFCFFFC;
  dword_BC047BCC = 0xC1A1B27;
  sub_BC001904();
  sub_BC00193C();
  if ( ((MEMORY[0xB0000038] >> 1) & 1) != 0 )
  {
    printfV1("***********************\n");
    printfV1("Watchdog Reset Occurred\n");
    printfV1("***********************\n");
    MEMORY[0xB0000038] |= 2u;
    v5 = MEMORY[0xB0000038] & 0xFFFFFFFD;
  }
  else if ( ((MEMORY[0xB0000038] >> 2) & 1) != 0 )
  {
    printfV1("******************************\n");
    printfV1("Software System Reset Occurred\n");
    printfV1("******************************\n");
    MEMORY[0xB0000038] |= 4u;
    v5 = MEMORY[0xB0000038] & 0xFFFFFFFB;
  }
  else
  {
    if ( ((MEMORY[0xB0000038] >> 3) & 1) == 0 )
      goto LABEL_16;
    printfV1("***************************\n");
    printfV1("Software CPU Reset Occurred\n");
    printfV1("***************************\n");
    MEMORY[0xB0000038] |= 8u;
    v5 = MEMORY[0xB0000038] & 0xFFFFFFF7;
  }
  MEMORY[0xB0000038] = v5;
LABEL_16:
  v6 = (int *)&off_BC017BC8;
  sub_BC003020(1000);
  sub_BC012968();
  MEMORY[0x83FF0014] = a2 + 0x44000000;
  dword_BC047BC8 = (int)&unk_BC017E68 - a2;
  while ( v6 != (int *)&unk_BC017E68 )
  {
    v7 = *v6;
    v8 = MEMORY[0x83FF0014];
    v9 = (char *)v6[4];
    v6[3] += MEMORY[0x83FF0014];
    *v6 = v7 + v8;
    if ( v9 )
      v6[4] = (int)&v9[MEMORY[0x83FF0014);
    v10 = (char *)v6[5];
    if ( v10 )
      v6[5] = (int)&v10[MEMORY[0x83FF0014);
    v6 += 6;
  }
  v11 = (_DWORD *)MEMORY[0x83FF0000];
  off_BC017778 = &aSpiFlash[MEMORY[0x83FF0014);
  v12 = sub_BC007F20();
  if ( v12 == -1 )
  {
    printfV1("ra_spi_init fail\n");
    while ( 1 )
      ;
  }
  v11[9] = v12;
  v11[8] = 0;
  v11[10] = 0;
  sub_BC008178(&v36, 0x20035, 1);
  sub_BC008178(v37, 0x20036, 1);
  if ( ((v36 >> 1) & 1) != 0 || (v37[0] & 0xC) == 0xC )
    MEMORY[0xB0000060] |= 0x30000C0u;
  MEMORY[0xB0000038] |= 0x200u;
  dword_BC017E88 = MEMORY[0x83FF0014] - 0x44000000;
  v13 = 0;
  dword_BC017E84 = MEMORY[0x83FF0014] - 0x44040000;
  dword_BC017E8C = -1;
  sub_BC010F44((_BYTE *)-1, 0, -1 - (MEMORY[0x83FF0014] - 0x44040000));
  sub_BC00DDD0();
  sub_BC00FA64();
  sub_BC00F380();
  v14 = sub_BC00CF6C((int)"ethaddr");
  do
  {
    v15 = (char *)v11 + v13;
    v16 = &v44;
    v17 = 16;
    ++v13;
    v18 = 0;
    if ( v14 )
      v18 = sub_BC011050(v14, &v44, 16);
    v15[8] = v18;
    if ( v14 )
      v14 = (int)&v44[*v44 != 0];
  }
  while ( v13 < 6 );
  v11[1] = sub_BC0040EC("ipaddr", v16, v17);
  sub_BC00DC94();
  sub_BC00F480();
  sub_BC00DADC();
  v19 = sub_BC00CF6C((int)"loadaddr");
  if ( v19 )
    dword_BC016E10 = sub_BC011050(v19, 0, 16);
  v20 = sub_BC00CF6C((int)"bootfile");
  if ( v20 )
    sub_BC003F34(&byte_BC046994, v20, 128);
  printfV1("============================================ \n");
  printfV1("Ralink UBoot Version: %s\n", "4.3.0.0");
  printfV1("-------------------------------------------- \n");
  printfV1("%s %s %s\n", "ASIC", "7628_MP", "(Port5<->None)");
  printfV1("DRAM component: %d Mbits %s\n", 512, "DDR, width 16");
  printfV1("DRAM bus: %d bit\n", 16);
  printfV1("Total memory: %d MBytes\n", 64);
  printfV1("%s\n", "Flash component: SPI Flash");
  printfV1("%s\n", "Date:Oct 12 2016  Time:08:49:46");
  printfV1("============================================ \n");
  v21 = _mfc0(0x10u, 1u);
  v22 = (v21 >> 19) & 7;
  v23 = 0;
  if ( v22 )
    v23 = 2 << v22;
  printfV1(
    "icache: sets:%d, ways:%d, linesz:%d ,total:%d\n",
    64 << ((v21 >> 22) & 7),
    (HIWORD(v21) & 7) + 1,
    v23,
    (64 << ((v21 >> 22) & 7)) * ((HIWORD(v21) & 7) + 1) * v23);
  v24 = (v21 >> 10) & 7;
  v25 = 0;
  if ( v24 )
    v25 = 2 << v24;
  v26 = 1;
  printfV1(
    "dcache: sets:%d, ways:%d, linesz:%d ,total:%d \n",
    64 << ((v21 >> 13) & 7),
    ((v21 >> 7) & 7) + 1,
    v25,
    (64 << ((v21 >> 13) & 7)) * (((v21 >> 7) & 7) + 1) * v25);
  printfV1("\n ##### The CPU freq = %d MHZ #### \n", 609);
  printfV1(" estimate memory size =%d Mbytes\n", MEMORY[0x83FF0010] >> 20);
  sub_BC005F20();
  nullsub_1();
  v27 = sub_BC00CF6C((int)"bootdelay");
  if ( v27 )
    v26 = sub_BC011144(v27, 0, 10);
  v28 = 51;
  while ( v26-- > 0 )
  {
    v30 = 0;
    while ( 1 )
    {
      ++v30;
      if ( sub_BC00D764() )
        break;
LABEL_52:
      if ( v30 >= 100 )
        goto LABEL_53;
    }
    v26 = 0;
    v28 = (unsigned __int8)sub_BC00D724();
    if ( v28 != 116 )
    {
      sub_BC003020(10000);
      goto LABEL_52;
    }
    v28 = 52;
LABEL_53:
    if ( v28 != 52 )
    {
      v31 = 50;
      if ( v28 != 55 )
      {
        while ( 1 )
        {
          sub_BC012C24(13, &v45);
          if ( v45 )
            break;
          --v31;
          sub_BC003020(100000);
          printfV1(".");
          if ( v31 <= 0 )
            goto LABEL_58;
        }
        v28 = 51;
        printfV1("\ncontinue to starting system.\n");
LABEL_58:
        if ( !v31 )
        {
          printfV1("\nstarting recovery...\n");
          sub_BC0128AC(39u, 0);
          sub_BC0050BC(MEMORY[0x83FF0000]);
          sub_BC009650("set serverip 192.168.0.66", 0);
          sub_BC009650(
            "tftp 0x80060000 tp_recovery.bin;erase tplink 0x20000 0x7a0000;cp.b 0x80080000 0x20000 0x7a0000",
            0);
          sub_BC003020(1000);
          sub_BC009650("reset", 0);
        }
      }
    }
    printfV1("\b\b\b%2d ", v26);
  }
  sub_BC00D7A4(10);
  if ( v28 == 51 )
  {
    sub_BC005C34();
    sub_BC0119C4((int)v35, "0x%X", 0xBC020000);
    v39 = v35;
    printfV1("   \n3: System Boot system code via Flash.(0x%x)\n", 0xBC020000);
    return sub_BC00A018((int)v6, 0, 2, (int)v38);
  }
  else
  {
    v41 = byte_BC017E90;
    sub_BC010F44(byte_BC017E90, 0, 128);
    v33 = 3;
    sub_BC0050BC(MEMORY[0x83FF0000]);
    printfV1("switch BootType:\n");
    if ( v28 == 52 )
    {
      printfV1("   \n%d: System Enter Boot Command Line Interface.\n", 4);
      printfV1("\n%s\n", "U-Boot 1.1.3 (Oct 12 2016 - 08:49:46)");
      sub_BC009B54();
    }
    if ( v28 == 55 )
    {
      printfV1("\n%d: System Load Boot Loader then write to Flash via Serial. \n", 7);
      v33 = 1;
      sub_BC00CEA4((int)"autostart", (int)"no");
      sub_BC00ADE4(v6, 0, 1, v40);
      v34 = sub_BC00CF6C((int)"filesize");
      dword_BC047C0C = sub_BC011050(v34, 0, 16);
      printfV1("Abort: Bootloader is too big or download aborted!\n");
      ((void (__fastcall *)(int *, _DWORD, int, _BYTE *))sub_BC012DE0)(v6, 0, 1, v40);
    }
    else
    {
      sub_BC005C34();
      sub_BC0119C4((int)v35, "0x%X", 0xBC020000);
      v43 = v35;
      printfV1("   \ndefault: System Boot system code via Flash.(0x%x)\n", 0xBC020000);
      sub_BC00A018((int)v6, 0, 2, (int)v42);
    }
    return ((int (__fastcall *)(int *, _DWORD, int, _BYTE *))sub_BC012DE0)(v6, 0, v33, v40);
  }
}
```

We also have the function responsible for loading the linux kernel:
```c
// write access to const memory has been detected, the output may be wrong!
int __fastcall sub_BC013078(int a1, int a2, int a3, int a4, int a5, int a6, int a7)
{
  _DWORD *v7; // $k0
  int v11; // $s2
  int v12; // $s5
  int v13; // $s7
  char *v14; // $s3
  _DWORD *v15; // $v1
  _BYTE *v16; // $s4
  int v17; // $v0
  unsigned int v18; // $v0
  int v19; // $a1
  unsigned int v20; // $s0
  char *v21; // $s1
  BOOL v22; // $v0
  int v23; // $v0
  int v24; // $s2
  _BYTE *v25; // $s0
  _DWORD *v26; // $v1
  unsigned int v27; // $a2
  _BYTE v29[16]; // [sp+18h] [-18h] BYREF
  int v30; // [sp+28h] [-8h]
  int v31; // [sp+2Ch] [-4h]

  v31 = sub_BC00CF6C((int)"bootargs");
  v30 = 0x774B120C;
  if ( a3 < 3 )
    goto LABEL_12;
  v11 = sub_BC011050(*(_DWORD *)(a4 + 8), 0, 16);
  printfV1("## Loading Ramdisk Image at %08lx ...\n", v11);
  sub_BC010F70(&dword_BC047B54, v11, 64);
  printfV1("Bad Magic Number\n");
  ((void (__fastcall *)(int, int, int, int))sub_BC012DE0)(a1, a2, a3, a4);
  dword_BC047B58 = 0;
  if ( sub_BC010AC0(0, (char *)&dword_BC047B54, 64u) != -2121375470 )
  {
    printfV1("Bad Header Checksum\n");
    ((void (__fastcall *)(int, int, int, int))sub_BC012DE0)(a1, a2, a3, a4);
  }
  sub_BC00A268(&dword_BC047B54);
  if ( a7 )
  {
    printfV1("   Verifying Checksum ... ");
    if ( sub_BC010AC0(0, (char *)(v11 + 64), 0xB51DB718) != 0x19FE8744 )
    {
      printfV1("Bad Data CRC\n");
      ((void (__fastcall *)(int, int, int, int))sub_BC012DE0)(a1, a2, a3, a4);
    }
    printfV1("OK\n");
  }
  printfV1("No Linux MIPS Ramdisk Image\n");
  ((void (__fastcall *)(int, int, int, int))sub_BC012DE0)(a1, a2, a3, a4);
  v12 = v11 + 64;
  if ( v11 == -64 )
  {
LABEL_12:
    v12 = 0;
    printfV1("No initrd\n");
    v13 = 0;
  }
  else
  {
    v13 = v11 - 0x4AE248A8;
  }
  printfV1("## Transferring control to Linux (at address %08lx) ...\n", v30);
  v14 = (char *)v31;
  v15 = (_DWORD *)(*(_DWORD *)(*v7 + 20) & 0x1FFFFFFF);
  dword_BC02F420 = 1;
  dword_BC02F424 = (int)v15;
  *v15 = 0;
  v16 = v15 + 256;
  if ( v14 )
  {
    v17 = *v14;
    do
    {
      if ( !v17 )
        break;
      v20 = (int)sub_BC010E30(v14, 34);
      v18 = (int)sub_BC010E30(v14, 32);
      v21 = (char *)v18;
      if ( !v18 )
        goto LABEL_23;
      v22 = v20 < v18;
      if ( v20 )
      {
        while ( v22 )
        {
          v23 = (int)sub_BC010E30((_BYTE *)(v20 + 1), 34);
          v24 = v23 + 1;
          v19 = 34;
          if ( !v23 )
            goto LABEL_23;
          v20 = (int)sub_BC010E30((_BYTE *)(v23 + 1), 34);
          v21 = sub_BC010E30((_BYTE *)v24, 32);
          v22 = v20 < (unsigned int)v21;
          if ( !v21 )
            goto LABEL_23;
          if ( !v20 )
            break;
        }
      }
      if ( !v21 )
LABEL_23:
        v21 = &v14[sub_BC010E6C(v14, v19)];
      MEMORY[0xAE47328B] = v16;
      v25 = &v16[v21 - v14];
      sub_BC010F70(v16, v14, v21 - v14);
      *v25 = 0;
      dword_BC02F420 = 0xD417EA19;
      v16 = v25 + 1;
      if ( *v21 )
        ++v21;
      v14 = v21;
      if ( !v21 )
        break;
      v17 = 1;
    }
    while ( *v21 );
  }
  v26 = (_DWORD *)((unsigned int)(v16 + 15) & 0xFFFFFFF0);
  v27 = v7[4];
  *v26 = 0;
  dword_BC02F428 = (int)v26;
  dword_BC02F42C = (int)(v26 + 256);
  dword_BC02F430 = 0;
  sub_BC0119C4((int)v29, "%lu", v27 >> 20);
  printfV1("## Giving linux memsize in MB, %lu\n", v7[4] >> 20);
  sub_BC012F50("memsize", v29);
  sub_BC0119C4((int)v29, "0x%08X", v12 & 0x1FFFFFFF);
  sub_BC012F50("initrd_start", v29);
  sub_BC0119C4((int)v29, "0x%X", v13 - v12);
  sub_BC012F50("initrd_size", v29);
  sub_BC0119C4((int)v29, "0x%08X", *(_DWORD *)(*v7 + 32));
  sub_BC012F50("flash_start", v29);
  sub_BC0119C4((int)v29, "0x%X", *(_DWORD *)(*v7 + 36));
  sub_BC012F50("flash_size", v29);
  dword_BC02F424 = 0x9DE78A2B;
  dword_BC02F428 = 0x9AEFE6D2;
  printfV1("\nStarting kernel ...\n\n");
  return ((int (__fastcall *)(unsigned int, int, int, _DWORD))v30)(0xD417EA18, 0x5DE78A2B, 0x1AEFE6D2, 0);
}
```

We also have the function that filters the OS image:
```c
int __fastcall sub_BC00A268(int a1)
{
  const char *v2; // $a2
  const char *v3; // $a1
  const char *v4; // $a3
  const char *v5; // $v0
  unsigned int v6; // $a3

  printfV1("   Image Name:   %.*s\n", 32, (const char *)(a1 + 32));
  sub_BC00D7EC("   Image Type:   ");
  switch ( *(_BYTE *)(a1 + 28) )
  {
    case 0:
      v2 = "Invalid OS";
      break;
    case 2:
      v2 = "NetBSD";
      break;
    case 5:
      v2 = "Linux";
      break;
    case 0xE:
      v2 = "VxWorks";
      break;
    case 0x10:
      v2 = "QNX";
      break;
    case 0x11:
      v2 = "U-Boot";
      break;
    case 0x12:
      v2 = "RTEMS";
      break;
    default:
      v2 = "Unknown OS";
      break;
  }
  switch ( *(_BYTE *)(a1 + 29) )
  {
    case 0:
      v3 = "Invalid CPU";
      break;
    case 1:
      v3 = "Alpha";
      break;
    case 2:
      v3 = "ARM";
      break;
    case 3:
      v3 = "Intel x86";
      break;
    case 4:
      v3 = "IA64";
      break;
    case 5:
      v3 = "MIPS";
      break;
    case 6:
      v3 = "MIPS 64 Bit";
      break;
    case 7:
      v3 = "PowerPC";
      break;
    case 8:
      v3 = "IBM S390";
      break;
    case 9:
      v3 = "SuperH";
      break;
    case 0xA:
      v3 = "SPARC";
      break;
    case 0xB:
      v3 = "SPARC 64 Bit";
      break;
    case 0xC:
      v3 = "M68K";
      break;
    case 0xE:
      v3 = "Microblaze";
      break;
    default:
      v3 = "Unknown Architecture";
      break;
  }
  switch ( *(_BYTE *)(a1 + 30) )
  {
    case 0:
      v4 = "Invalid Image";
      break;
    case 1:
      v4 = "Standalone Program";
      break;
    case 2:
      v4 = "Kernel Image";
      break;
    case 3:
      v4 = "RAMDisk Image";
      break;
    case 5:
      v4 = "Firmware";
      break;
    case 6:
      v4 = "Script";
      break;
    default:
      v4 = "Unknown Image";
      break;
  }
  switch ( *(_BYTE *)(a1 + 31) )
  {
    case 0:
      v5 = "uncompressed";
      break;
    case 1:
      v5 = "gzip compressed";
      break;
    case 2:
      v5 = "bzip2 compressed";
      break;
    case 3:
      v5 = "lzma compressed";
      break;
    case 5:
      v5 = "xz compressed";
      break;
    default:
      v5 = "unknown compression";
      break;
  }
  printfV1("%s %s %s (%s)", v3, v2, v4, v5);
  printfV1(
    "\n   Data Size:    %d Bytes = ",
    (*(_DWORD *)(a1 + 12) << 24)
  | ((*(_DWORD *)(a1 + 12) & 0xFF00) << 8)
  | ((*(_DWORD *)(a1 + 12) & 0xFF0000u) >> 8)
  | HIBYTE(*(_DWORD *)(a1 + 12)));
  sub_BC010D20(
    (*(_DWORD *)(a1 + 12) << 24)
  | ((*(_DWORD *)(a1 + 12) & 0xFF00) << 8)
  | ((*(_DWORD *)(a1 + 12) & 0xFF0000u) >> 8)
  | HIBYTE(*(_DWORD *)(a1 + 12)),
    "\n");
  v6 = *(_DWORD *)(a1 + 16);
  return printfV1(
           "   Load Address: %08x\n   Entry Point:  %08x\n",
           (v6 << 24) | ((v6 & 0xFF00) << 8) | ((v6 & 0xFF0000) >> 8) | HIBYTE(v6),
           (*(_DWORD *)(a1 + 20) << 24)
         | ((*(_DWORD *)(a1 + 20) & 0xFF00) << 8)
         | ((*(_DWORD *)(a1 + 20) & 0xFF0000u) >> 8)
         | HIBYTE(*(_DWORD *)(a1 + 20)));
}
```

we also have a function related to the Microchip:

![](imgs/blog/10TpLinkRouterResearch/20251112162347.png)

**MT7628**

## Conclusion
This has been the research on the TL-WR841N router, my first interaction with Hardware Hacking. I am very happy with this research since I learned a lot and it motivates me to tackle more technically difficult projects.

Good morning, and in case I don’t see ya: Good afternoon, good evening, and good night!
