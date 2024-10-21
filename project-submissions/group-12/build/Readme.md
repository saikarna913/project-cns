 server_addr.sin_addr.s_addr = inet_addr("<ip_address>");

If the client(logappend, logread) and server programs are run on same machine, then replace <ip_address> with " 127.0.0.1 " in the above line of code in logappend and logread code files

If the client and server programs are run on different machines, then enter the IP address of server machine which is obtained by using the following commands in place of <ip_address> in logread and logapped code files

FOR LINUX : "ip a"

FOR MAC : "ipconfig getifaddr en0"

Invoke Makefile to run the program.

Usage of logread and loappend commands : https://github.com/IITGN-CS431/problems/blob/main/securityguard/EXAMPLES.md  

References :
RSA algorithm : https://www.geeksforgeeks.org/rsa-algorithm-cryptography/ 
