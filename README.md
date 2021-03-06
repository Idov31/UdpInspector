# UdpInspector
![image](https://img.shields.io/badge/C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white) ![image](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
## What's all the fuss about?
Unlike most of the programs that are giving the current UDP connections, this program gives also the remote address!<br />Any bugs and improvements will be welcomed!<br /><b>NOTE: You will need to run the program as administrator.</b><br />
<b>Another note: You can read more about it in: https://idov31.github.io/papers/udp_connections.html</b>

## Okay, cool but... still what's the fuss?
As part of my research on network protocols I wanted to get all active UDP connections, but I encountered a problem:<br />
I could not get the remote address (which is very important) when somebody connected via UDP (without sniffing - Just good ol' winapi)! This was thought to be impossible... Until now.<br/> 
I went on a quest to find the answer once and for all - How to do it?<br /><br />
With the help of the amazing repositories and article (listed below) and people that helped me, I found a way!

## Don't leave us like that! What is the way?
These are the logical steps (of course, you can always see the source code as well):
* Get all the PIDs that are currently communicating via UDP (via GetExtendedUdpTable).
* Enumerate the PIDs and extract their handles table (NtQueryInformation, NtQueryObject).
* Duplicate the handle to the socket (identified with \Device\Afd).
* Extract from the socket the remote address.

## Compiling
I was using Visual Studio 2019, strongly recommand to use this for compilation.

## References
I strongly recommand to read and see the interesting article about ShadowMove:
* https://www.usenix.org/system/files/sec20summer_niakanlahiji_prepub.pdf
* https://github.com/0xcpu/winsmsd

A really good answer that gave me the hope that it is possible:
* https://stackoverflow.com/questions/16262114/c-get-handle-of-open-sockets-of-a-program

Thanks for this repo for giving an example of how to use GetExtendedUdpTable:
* https://github.com/w4kfu/whook/blob/master/src/network.cpp
