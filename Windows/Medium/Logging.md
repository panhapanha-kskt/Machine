** Start Enumeration 
nmap -sV -sC --reason -oA nmap/logging <IP-Address>
less nmap/logging
ntpdate <IP-Address>

nxc smb dc1.logging.htb -u usernaem -p password
nxc smb dc1.logging.htb -u usernaem -p password --shares

smbclient.py 'username:password'@dc01.logging.htb
  get all smbclient file: mget *.log (analyze logs)
  
nxc smb dc1.logging.htb -u usernaem -p password
nxc smb dc1.logging.htb -u usernaem -p password -k 
-k get object scr
bloodyad -d logging.htb -u username -p 'password' -H DO01.Loggging.htb -H DC01.Logging.htb -k get object svc_recovery


rusthound-ce -d logging.htb -u username -p 'password'
certipy find =i username@logging.htb -p 'password' -dc-ip <ip address>
