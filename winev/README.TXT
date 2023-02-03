---------------------------------- This tool has been developed from scratch byt DTUM ----------------------------------------------

* This tool is built with bash scripting to generate a fileless malware which has the ability to bypass the latest version of Windows Defender with the highest previliges.
* This tool has been specifically developed to bypass Windows Defender so it wasn`t tested on other AVs.
* This tool has been tested on all Windows Defender versions until WIN10 19044.2251.


* To use this tool you need to do the following:

1- Clone the repository to your desktop.
2- After the cloning is done, Open op the terminal and direct to the repository file.
3- Inside the file, run the tool by typing ./winev.sh     ps: You may need to change the permissions of the file to make it executable. You can make it with sudo chmod +x winev.sh
4- Complete the steps required by the tool to generate the malware you need.
5- After that, you'll find a directory on your Desktop name WinEvFIles, inside it you'll find the malware generated.
6- To start the attack, first start a netcat listening session with the command sudo nc -nvlp (The port you generated your malware to establish connection on. ex:443).
7- Then you need to start a server on your home directory "Not Desktop, HOME" please don`t miss with this step.       The server can be implemented with the command python -m http.server
8- After the server is implemented, You just need to send the WinSecutiyUpdate file to the target machine and run it.
9- You`re Done !!! Have fun.

