# HomeLab Best-practices and Guide
All Code / Write-ups and Documentation related to homelab setups. 

## Proxmox
<details>
<summary> # Hardening Guide </summary>

  **Host Security:** 
  
-Cluster not reachable by Outside
  
-Fail2Ban with Monitoring and Email Alerts

-Encrypted Hosts with Luks

-Encrypted Swap

-IP based Access Control

-Behind a Pfsense Firewall

-2FA for each User

**VM Security:**

-Vlan for each critical VM / non Critical VMs are based in Application grouped Vlans

-Fail2Ban with Monitoring and Email Alerts

-Encrypted VM

-VMs dont have any Networkstorage (only the ve host provides Storage)

-Custom Ports

-Behind a pfsense Firewall

-Swap Encryption

-Services get published by haproxy with another Layer of Access control

**Backup Security:**

-No unencrypted Backups

-Backups are never stored on the same site as the encryption key

-Coldstorage Backups perfromed weekly

-Off-site Backups are performed encrypted and protected against Changes


  
</details>

<details>
<summary> # SSH Hardening </summary>

### SSH Hardening

##### Fail2Ban Install

install Fail2Ban with this command 
`sudo apt install fail2ban`

Navigate to `/etc/fail2ban/jail.conf`

This is where all the **magic** happens. This is the file where you can configure things like default ban time, number of retries before banning an IP, whitelisting IPs, mail sending information etc. --> Basically you control the behavior of Fail2Ban from this file.

**Note:** If you disable the password based SSH login, you may not need to go for Fail2Ban. 

The SSH configuration files are located at `/etc/ssh/sshd_config.`

Most of the SSH hardening tips mentioned here will require you to edit this config file. This is why it will be a good idea to back up the original file. You’ll also need to restart the SSH service if you make any changes to the SSH config file.

Let’s see what steps you can take to secure your SSH server.

###### 1. Disable empty passwords

Yes. It is possible to have user accounts in Linux without any passwords. If those users try to use SSH, they won’t need passwords for accessing the server via SSH as well.

That’s a security risk. You should forbid the use of empty passwords. In the /etc/ssh/sshd_config file, make sure to set `PermitEmptyPasswords` option to no.

###### 2. Change default SSH ports

The default SSH port is 22 and most of the attack scripts check are written around this port only. Changing the default SSH port should add an additional security layer because the number of attacks (coming to port 22) may reduce.

Search for the port information in the config file and change it to something different:

Example: Port 2345
You must remember or note down the port number otherwise you may also not access your servers with SSH.

###### 3. Disable root login via SSH

To be honest, using server as root itself should be forbidden (By Default deactivated in UBUNTU). It is risky and leaves no audit trail. Mechanism like sudo exist for this reason only.

If you have sudo users added on your system, you should use that sudo user to access the server via SSH instead of root.

You can disable the root login by modifying the PermitRootLogin option and setting it as no:

PermitRootLogin no

###### 4. Disable ssh protocol 1

This is if you are using an older Linux distribution. Some older SSH version might still have SSH protocol 1 available. This protocol has known vulnerabilities and must not be used.

Newer SSH versions automatically have SSH protocol 2 enabled but no harm in double checking it.

Protocol 2

###### 5. Configure idle timeout interval

The idle timeout interval is the amount of time an SSH connection can remain active without any activity. Such idle sessions are also a security risk. It is a good idea to configure idle timeout interval.

The timeout interval is count in seconds and by default it is 0. You may change it to 300 for keeping a five minute timeout interval.

ClientAliveInterval 300
After this interval, the SSH server will send an alive message to the client. If it doesn’t get a response, the connection will be closed and the end user will be logged out.

You may also control how many times it sends the alive message before disconnecting:

ClientAliveCountMax 2

###### 6. Allow SSH access to selected users only

When it comes to security, you should follow the principal of least privilege. Don’t give rights when it is not required.

You probably have several users on your Linux system. Do you need to allow SSH access to all of them? Perhaps not.

An approach here would be to allow SSH access to a selected few users and thus restricting for all the other users.

AllowUsers User1 User2
You may also add selected users to a new group and allow only this group to access SSH.

AllowGroups ssh_group
You may also use the DenyUsers and DenyGroups to deny SSH access to certain users and groups.

###### 7. Disable X11 Forwarding

The X11 or the X display server is the basic framework for a graphical environment. The X11 forwarding allows you to use a GUI application via SSH.

Basically, the client runs the GUI application on the server but thanks to X11 forwarding, a channel is opened between the machines and the GUI applications is displayed on the client machine.

The X11 protocol is not security oriented. If you don’t need it, you should disable the X11 forwarding in SSH.

X11Forwarding no

###### 8. Mitigate brute force attacks automatically

To thwart SSH bruteforce attacks, you can use a security tool like Fail2Ban.

Fail2Ban checks the failed login attempts from different IP addresses. If these bad attempts cross a threshold within a set time interval, it bans the IP from accessing SSH for a certain time period.

You can configure all these parameters as per your liking and requirement. I have written a detailed introductory guide on using Fail2Ban which you should read.

###### 9. Disable password based SSH login

No matter how much you try, you’ll always see bad login attempts via SSH on your Linux server. The attackers are smart and the scripts they use often take care of the default settings of Fail2Ban like tools.

To get rid of the constant brute force attacks, you can opt for only key-based SSH login.

In this approach, you add the public key of the remote client systems to the known keys list on the SSH server. This way, those client machines can access SSH without entering the user account password.

When you have this setup, you can disable password based SSH login. Now, only the clients machines that have the specified SSH keys can access the server via SSH.

Before you go for this approach, make sure that you have added your own public key to the server and it works. Otherwise, you’ll lock yourself out and may lose access to the remote server specially if you are using a cloud server like Linode where you don’t have physical access to the server.

> [!WARNING]
> Before disabling ssh password authentication. Make sure your access with private key works as expected. Once confirmed, disable password authentication.


Edit file with: `sudo nano /etc/ssh/sshd_config`

Please make sure you have following values enabled in the file:

```
PermitRootLogin no

PasswordAuthentication no

ChallengeResponseAuthentication no

UsePAM no
```

Save file and then restart ssh service
`sudo service ssh restart`
or
`sudo systemctl restart ssh`

###### 10. Two-factor authentication with SSH

To take SSH security to the next level, you may also enable two-factor authentication. In this approach, you receive a one-time password on your mobile phone, email or through a third-party aunthentication app.

You may read about setting up two-factor authentication with SSH here.

Conclusion

You can see all the parameters of your SSH server using this command:

sshd -T
This way, you can easily see if you need to change any parameter to enhance the security of the SSH server.

You should also keep the SSH install and system updated.

</details>

<details> 
<summary> Fail2Ban DetailInstall </summary>
## Fail2Ban Detailierte Anleitung

Install Fail2Ban on Ubuntu & Debian

First, make sure your system is updated:

sudo apt update && sudo apt upgrade -y
Now, install Fail2Ban with this command:

sudo apt install fail2ban
DigitalOcean – The developer cloud
Helping millions of developers easily build, test, manage, and scale applications of any size – faster than ever before.
Get started on DigitalOcean with a $100, 60-day credit for new users.
Understanding Fail2Ban configuration file

There are two main configuration files in Fail2Ban: /etc/fail2ban/fail2ban.conf and /etc/fail2ban/jail.conf. Let me explain what they do.

/etc/fail2ban/fail2ban.conf: This is the configuration file for the operational settings of the Fail2Ban daemon. Settings like loglevel, log file, socket and pid file is defined here.

/etc/fail2ban/jail.conf: This is where all the magic happens. This is the file where you can configure things like default ban time, number of reties before banning an IP, whitelisting IPs, mail sending information etc. Basically you control the behavior of Fail2Ban from this file.

Now, before you go and change these files, Fail2Ban advise making a copy with .local file for these conf files. It’s because the default conf files can be overwritten in updates and you’ll lose all your settings.

sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
Now let’s understand the jail.conf file. If you use the less command to read this big file, it may seem quite confusing. The conf file tries to explain everything with way too many comments. So, let me simplify this for you.

The jail.conf file is divided into services. There is a [Default] section and it applies to all services. And then you can see various services with their respective settings (if any). All these services are in brackets. You’ll see sections like [sshd], [apache-auth], [squid] etc.

If I remove the comments, the default section looks like this:
```
[DEFAULT]
ignorecommand =
bantime = 10m
findtime = 10m
maxretry = 5
backend = auto
usedns = warn
logencoding = auto
enabled = false
mode = normal
filter = %(name)s[mode=%(mode)s]
destemail = root@localhost
sender = root@
mta = sendmail
protocol = tcp
chain =
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
banaction = iptables-multiport
banaction_allports = iptables-allports
action_abuseipdb = abuseipdb
action = %(action_)s
```


Let me tell you the meaning of some of these parameters.

bantime: Set the length of the ban. Default is 10 minutes.
findtime: The window in which the action on an IP will be taken. Default is 10 minutes. Suppose a bad login was attempted by a certain IP at 10:30. If the same IP reaches the maximum number of retries before 10:40, it will be banned. Otherwise, the next failed attempt after 10:40 will be counted as first failed attempt.
maxretry: The number of failed retries before an action is taken
usedns: The “warn” setting attempts to use reverse-DNS to look up the hostname and ban it using hostname. Setting it to no will ban IPs, not hostname.
destemail: The email address to which the alerts will be sent (needs to be configured)
sender: The sender name in the notification email
mta: Mail Transfer Agent used for notification email
banaction: This parameter uses the /etc/fail2ban/action.d/iptables-multiport.conf file to set the action after maximum failed retries
protocol: The type of traffic that will be dropped after the ban
🗒️

If you want to make any changes for any jail (or for all the jail), like the maximum retries, ban time, find time etc., you should edit the jail.local file.

How to use Fail2Ban to secure Linux server

Let me show you some of the ways you can use Fail2Ban to harden Linux security.

Note that you need to be root user or have sudo access to run the fail2ban commands.

Enable Fail2Ban on your server and check all running jails

You can use systemd commands to start and enable Fail2Ban on your Linux server:
```
systemctl start fail2ban
systemctl enable fail2ban
```
Once Fail2Ban is enabled, you can see the status and the active jails with fail2ban-client command:

fail2ban-client status
Status
|- Number of jail: 1
`- Jail list: sshd
In case you were wondering, sshd jail is enabled by default.

See Fail2Ban log

Fail2Ban log is located at /var/log/fail2ban.log. The log files are in the following format:
```
2019-03-25 07:09:08,004 fail2ban.filter [25630]: INFO [sshd] Found 139.59.69.76 – 2019-03-25 07:09:07
2019-03-25 07:09:36,756 fail2ban.filter [25630]: INFO [sshd] Found 159.89.205.213 – 2019-03-25 07:09:36
2019-03-25 07:09:36,757 fail2ban.filter [25630]: INFO [sshd] Found 159.89.205.213 – 2019-03-25 07:09:36
2019-03-25 07:09:36,774 fail2ban.actions [25630]: NOTICE [sshd] Ban 159.89.205.213
2019-03-25 07:09:36,956 fail2ban.filter [25630]: INFO [sshd] Found 182.70.253.202 – 2019-03-25 07:09:36
2019-03-25 07:09:36,957 fail2ban.filter [25630]: INFO [sshd] Found 182.70.253.202 – 2019-03-25 07:09:36
2019-03-25 07:09:36,981 fail2ban.actions [25630]: NOTICE [sshd] Ban 182.70.253.202
2019-03-25 07:09:37,247 fail2ban.filter [25630]: INFO [sshd] Found 112.64.214.90 – 2019-03-25 07:09:37
2019-03-25 07:09:37,248 fail2ban.filter [25630]: INFO [sshd] Found 112.64.214.90 – 2019-03-25 07:09:37
2019-03-25 07:09:37,589 fail2ban.actions [25630]: NOTICE [sshd] Ban 112.64.214.90
```
You can see that it identifies the IPs and bans them when they cross the threshold of maximum retry.

See banned IPs by Fail2Ban

One way is to check the status of a certain jail. You can use the Fail2Ban client for this purpose.

fail2ban-client status <jail_name>
For example, if you have to see all the bad ssh logins banned by Fail2Ban, you can use it in the following manner. The output would show the total failed attempts and the total banned IPs.

root@test-server:~# fail2ban-client status sshd
Status for the jail: sshd
|- Filter
| |- Currently failed: 14
| |- Total failed: 715
| `- File list: /var/log/auth.log
`- Actions
|- Currently banned: 7
|- Total banned: 17
`- Banned IP list: 177.47.115.67 118.130.133.110 68.183.62.73 202.65.154.110 106.12.102.114 61.184.247.3 218.92.1.150
The system that is try to login via SSH from the failed login should get an error like this

ssh: connect to host 93.233.73.133 port 22: Connection refused
How to permanently ban an IP with Fail2Ban

By now you know that the ban put on an IP by Fail2Ban is a temporary one. By default it’s for 10 minutes and the attacker can try to login again after 10 minutes.

This poses a security risk because attackers could use a script that tries logging in after an interval of 10 minutes.

So, how do you put a permanent ban using Fail2Ban? There is no clear answer for that.

Starting Fail2Ban version 0.11, the ban time will be automatically calculated and the persistent IPs will have their ban time increased exponentially.

But if you check your Fail2Ban version, you probably are running the version 0.10.

fail2ban-server --version 
Fail2Ban v0.10.2
Copyright (c) 2004-2008 Cyril Jaquier, 2008- Fail2Ban Contributors
Copyright of modifications held by their respective authors.
Licensed under the GNU General Public License v2 (GPL).
In earlier versions, you could use a negative bantime (bantime = -1) and that would have been equivalent to a permanent ban but if you try this method, you’ll probably see an error like ‘Starting fail2ban: ERROR NOK: (‘database disk image is malformed’,)’.

One not so clean workaround would be to increase the bantime to something like 1 day, 1 week, 1 month or 1 year. This could circumvent the problem until the new version is available on your system.

UptimeRobot: Free Website Monitoring Service
Start monitoring in 30 seconds. Use advanced SSL, keyword and cron monitoring. Get notified by email, SMS, Slack and more. Get 50 monitors for FREE!
How to unban IP blocked by Fail2Ban

First check if the IP is being blocked or not. Since Fail2Ban works on the iptables, you can look into the iptable to view the IPs being banned by your server:

iptables -n -L
You may have to use grep command if there are way too many IPs being banned.

If you find the specified IP address in the output, it is being banned:

So, the next step is to find which ‘jail’ is banning the said IP. You’ll have to use Grep command with the fail2ban logs here.

As you can see in the output below, the IP is being banned by sshd jail.

root@test-server:~# grep -E ‘Ban.*61.184.247.3’ /var/log/fail2ban.log
2019-03-14 13:09:25,029 fail2ban.actions [25630]: NOTICE [sshd] Ban 61.184.247.3
2019-03-14 13:52:56,745 fail2ban.actions [25630]: NOTICE [sshd] Ban 61.184.247.3
Now that you know the name of the jail blocking the IP, you can unban the IP using the fail2ban-client:

fail2ban-client set <jail_name> unbanip <ip_address>
How to whitelist IP in Fail2Ban

It won’t be a good thing if you ban yourself, right? To ignore an IP address from being banned by the current session of Fail2Ban, you can whitelist the IP using a command like this:

fail2ban-client set <JAIL_NAME> addignoreip <IP_Address>
You can find your IP address in Linux easily. In my case, it was

sudo fail2ban-client set sshd addignoreip 203.93.83.113
These IP addresses/networks are ignored:
`- 203.93.83.113
If you want to permanently whitelist the IP, you should edit the jail configuration file. Go to the said jail section and add the ignoreip line like this:

ignoreip = 127.0.0.1/8 <IP_TO_BE_WHITELISTED>
If you want to whitelist an IP from all the jails on your system, it would be a better idea to edit the /etc/fail2ban/jail.local file and add a line under the DEFAULT section like what we saw above.

You’ll have to restart Fail2Ban to take this change into effect.

How to see the IP whitelist by a jail

You can see all the IPs whitelisted by a jail using this command:

fail2ban-client get <JAIL_NAME> ignoreip
It should show all the IPs being ignored by Fail2Ban for that jail:

sudo fail2ban-client set sshd addignoreip 203.93.83.113
These IP addresses/networks are ignored:
|- 127.0.0.0/8
|- ::1
`- 203.93.83.113
How to remove an IP from Fail2Ban whitelist

If you are removing the IP from a certain jail’s whitelist, you can use this command:

fail2ban-client set <JAIL_NAME> delignoreip <IP_Address>
If you want to permanently remove the IP, you should edit the /etc/fail2ban/jail.local file.
</details>

<details> 
<summary> General Tipps </summary>

  ### Bluetooth 
- sudo systemctl status bluetooth
- sudo systemctl stop bluetooth
- sudo systemctl disable bluetooth


</details>

**Temperature Management**
Display: Ubuntu Server /sys/class/thermal/thermal_zone0$ cat temp --> shows in centigrade

**Common Parameters**

mpstat per processor utilization

vmstat processs, CPU, memory statistics (two arguments: NR of secs to monitor, AMT of reports) 

also: `sar -n DEV 30 2`

#### sysdig

Container-Aware kernel Monitoring 

<details> 
<summary>User Management</summary>

##### user deletion incl. homefolder

cat /etc/passwd | cut -d: -f1

**Explanation**

cat: Displays the contents of a file.
/etc/passwd: Path of the passwd file that contains user information.
Pipe(|): Redirects the output of one command into another.
cut: Extracts parts of lines from a file or piped data.
d:: Specifies colon (“:”) as a delimiter.
f1: Specifies a field. Here number 1 means the first field.

Now: `sudo deluser --remove-home myuser`


</details>


### Local Encryption via GnuPG
1. Generate Keys via `gpg --full-generate-key`
2. encrypt the file as follow `gpg -se -r username FILE`
3. decrypt `gpg -se -r username FILE` then `>` into another doc
   
### chmod and chown 

Let's say we have example-file and directory below: 

-File: `-rw-rw-r-- 1 user group 1.2K Apr 25 22:18 travelItaly.txt`

-Directory `drwxrwxr-x  2 user group 4.0K Apr 26 22:15 exampleItaly`

File Type `d`	User `rwx`	Group	`rwx` Global `r-x`

**chmod** 

Basic Syntax would be `chmod WHO[+,-,=]PERMISSIONS FILENAME`

Whereby `WHO` could be
```
u	= user
g	= group
o	= others
a	= all
```

so in our example to make the file travelItaly.txt readable for **all** we could write `chmod a+rwx travelItaly.txt `

Result: 
`-rwxrwxrwx  1 user group   10 Apr 26 22:06 travelItaly.txt`

> [!TIP]
> Using Octal Notation is much faster.

```
Binary	Octal	Permission
000	0	—
001	1	–x
010	2	-w-
011	3	-wx
100	4	r–
101	5	r-x
110	6	rw-
111	7	rwx

Example: chmod 600 = (rw-------)
Example: chmod 664 = (rw-rw-r--)
Example: chmod 777 = (rwxrwxrwx)
```


**chown** 








> [!NOTE]
> Useful information that users should know, even when skimming content.

> [!TIP]
> Helpful advice for doing things better or more easily.

> [!IMPORTANT]
> Key information users need to know to achieve their goal.

> [!WARNING]
> Urgent info that needs immediate user attention to avoid problems.

> [!CAUTION]
> Advises about risks or negative outcomes of certain actions.


