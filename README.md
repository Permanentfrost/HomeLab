# raspberry
All Code / Write-ups and Documentation related to homelab setups. 

# Why? 
1.Learning About Networks, SysAdmin etc. 
2.Track learning progress. 

# SSH Hardening
## Fail2Ban
install Fail2Ban with this command 
sudo apt install fail2ban

**/etc/fail2ban/fail2ban.conf
This is the configuration file for the operational settings of the Fail2Ban daemon. Settings like loglevel, log file, socket and pid file is defined here.

**/etc/fail2ban/jail.conf
This is where all the magic happens. This is the file where you can configure things like default ban time, number of reties before banning an IP, whitelisting IPs, mail sending information etc. Basically you control the behavior of Fail2Ban from this file.

