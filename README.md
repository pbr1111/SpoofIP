# Spoof IP
## Introduction
Code developed in C that allows the creation of User Datagrams (UDP) using the technique of IP spoofing. To create the sockets it uses WinSock2, as a result, it can be used only in Windows OS (and only works in little endian architectures: Windows x86 and x64). 

Unlike many other tools, it is able to correctly generate the user datagram using a pseudo-header IP and carrying out the calculation of the UDP checksum field.

## To keep in mind
- The data sent are *hardcoded* in the variable ```char *data```.
- TCP segments cannot be created.
- Does not work if your router does NAT.
