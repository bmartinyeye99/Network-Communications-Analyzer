# Network-Communications-Analyzer

Code provides an Ethernet network analyzer that analyzes network communications recorded in a .pcap file
and provides the following information about the communications:

**Listing all frames in hexadecimal**

**For Ethernet Type II and IEEE 802.3 frames, writes out the nested protocol**

**Analysis for Ethernet II frames and TCP/IPv4 family protocols are performed through the layers**

**The following communication protocols are analyzed**
-(a) HTTP
-b) HTTPS
-c) TELNET
-d) SSH
-e) FTP control
-f) FTP data
	
I used pcap.h library, which contains commands with which I was able to analyze packets. 
The pcap_next_ex function allows loading packets to the end of the pcap file, pcap_open_offline opens the pcap file.
For loading, I parse the packets and output parameters such as ip addresses, mac addresses, frame number, logs...etc.

I analyze each packet by the values that are foundin the hexadecimal data nodes. 
All the parameters I analyzed are stored in these hexadecimal numbers.
Mostly I used conditions and comparisons, but to make the code clearer, I stored some of the key values in a text document.

I analyze the types of the frames , whether it is Ethernet 2 or IEEE 802.3.
Next, I analyze the frames according to whether they are IPV4, IPV6, or ARP.
For the TCP, TFTP and ARP protocols I have created structures where I store the corresponding frames for further analysis and listing.

