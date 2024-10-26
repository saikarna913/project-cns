# CS431 : Security Guard

## Team Members:
- Chakradhar Basani
- Koleti Eswar Sai Ganesh
- Sriman Reddy
- Manav Jain
- Nakka Naga Bhuvith
- Pavan Deekshith
- Venigalla Harshith

 server_addr.sin_addr.s_addr = inet_addr("<ip_address>");

If the client (logappend, logread) and server programs are run on the same machine, replace <ip_address> with 127.0.0.1 in the respective lines of code in the logappend and logread code files.

If the client and server programs are run on different machines, replace <ip_address> in the logappend and logread code files with the IP address of the server machine, which can be obtained using the following commands:

FOR LINUX : "ip a"

FOR MAC : "ipconfig getifaddr en0"

Invoke Makefile to run the program.

Usage of logread and loappend commands : https://github.com/IITGN-CS431/problems/blob/main/securityguard/EXAMPLES.md  

References :
RSA algorithm : https://www.geeksforgeeks.org/rsa-algorithm-cryptography/ 
SHA256 algorithm : http://www.zedwood.com/article/cpp-sha256-function 
