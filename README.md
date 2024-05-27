# HomeLab Best-practices and Guide

This "Guide" should document all knowledge I find useful for setting up, configuring and navigating in a HomeLab Setup (Cybersecurity-Focused) 

*Revised structure to be completed. by end of May.*


**Most important: Have fun doing it!**

## General Linux Tips 

#### System Infos and Diagnostics

##### Change hostname

You may want to change the hostname for identification purposes so that it fits a naming scheme. 

The command `hostnamectl`displays the current hostname configuration in detail. 

You can change it the command `hostnamectl set-hostname new-hostname`

Also update the "pretty" hostname using `hostnamectl set-hostname "new-hostname" --pretty` alongside so that this matches and is consistent. This is presented to the user only but makes it clean and concise. 

From here on, `reboot` and verify again with `hostnamectl` . 

##### Uptime Tracking

You may want to track your systems uptime (how long is/was it running before crash). 

By adding the below into your crontab you can track this. This will runn every hour and write the `uptime` command output into the file uptime_log.txt.

`0 * * * * uptime >> /path/to/uptime_log.txt`

> [!TIP]  
> Make sure to invoke the crontab as `sudo crontab -e`. Otherwise you will edit the USERs crontab. 

Check if it worked by running `sudo crontab -u root -l` to list the ACTIVE cron jobs. 


##### Bluetooth

Start and stop the module as follows (power optimization): 
```
sudo systemctl status bluetooth
sudo systemctl stop bluetooth
sudo systemctl disable bluetooth
```

##### Backup Management

###### General Mounting Knowledge

Before you proceed with any Backup/External-Drive related task it essential to know how to mount, format and use drives via the command line. The general steps outlined follow the procedure of creating a partition, formating the drive, setting up the mount points and then actually using it in the following sub-chapters (backups etc.). 

First, get an overview of the actual drives. Do this with the command `sudo lshw -C disk` lshw=Hardware-Listener Class "Disk". Take note of the `logical name`. In my case this is ` /dev/mmcblk0`. This is used throughout the whole mounting,formating, partinioning and using process.


**Command Line Partitioning**  

We will use the tool `parted` for this purpose. 

Start parted with `sudo parted LOGICAL NAME`

create a new disklabel `(parted) mklabel gpt` --> Note GPT here means GPT (GUID Partition Table) which allows certain functionalities that standard MBR would not (large, multiple partitions). 

Then we need to set the default unit on this drive to either Terrabyte or Gigabyte `(parted) unit TB`

Create one partition occupying all the space from 0 to 2 terrabytes with command `parted LOGICALNAME unit TB mkpart primary ext4 0 2`

Breakdown: 

```
Starts the parted utility on the specified disk (/dev/sdX).
Sets the unit to terabytes (TB) for all subsequent operations within this parted session.
Creates a primary partition intended for the ext4 file system.
The new partition starts at 0 TB (the very beginning of the disk).
The partition ends at 2 TB, making it a 2 terabyte partition.
```

Check, verify and then quit `parted` with `(parted) print` followed by `(parted) quit`

*Alternatively you can use `fdisk`* 

Start with `sudo fdisk LOGICALNAME`. a selection will appear. choose `n`= add a new partition. Then select `p   primary partition (1-4)` then enter 1 (will be the only partition) 


**Command Line Formatting**  

ASSUMPTION: `LOGICALNAME = /dev/sdb1`

`sudo mkfs -t ext4 /dev/sdb1`  Note: ext4 is ubuntu/debians standard filesystem. 
`sudo mkfs -t fat32 /dev/sdb1` Note: use this for interoperability with windows. 


**Mounting the Drive**  

> [!IMPORTANT]
> Create a mount point before mounting!

**After (!)** partitioning and formatting choose a mount point. This will be the location from which the drive is accessed. Ubuntu Default is "/media". Ubuntu suggests using "/media/mynewdrive"

Create the directory with `sudo mkdir /media/mynewdrive`

Now to set up automatic mount at boot edit the `fstab`file (file systems table -> lists the filesystems and directories)

Use the command `sudo nano -Bw /etc/fstab`

> [!WARNING]
> Always use `-Bw`. This will create a file backup. 

Add this line to the end (for ext4 file system) `/dev/sdb1    /media/mynewdrive   ext4    defaults     0        2`

Add this line to the end (for fat32 file system): `/dev/sdb1    /media/mynewdrive   vfat    defaults     0        2`

After you are done, simply reboot for the changes to take effect. 


###### Bootable SD Backup

You can backup directly from the running RasPi onto a SD Card and then boot from there in case the other one fails. 

1.USB SD card device will be located under `/dev`

2.`sda` will be the card

3.`sudo dd bs=4M if=/dev/mmcblk0 of=/dev/sda`

Commands Explained:

`dd` command reads input from a file or a device, and writes it to another file or device

`bs=4M` sets our block size to 4 megabytes

`if=/dev/mmcblk0` sets our input file

`of=/dev/sda` sets our output file

Note: 
If you listed the devices in the `/dev` folder you probably noticed other partitions named `mmcblk0p1` and `mmcblk0p2`. You want the **entire** SD card backed-up and that is why you need to reference `mmcblk0`. The same goes for the destination `sda` as you may have seen `sda1` and `sda2`. 


###### HardDrive
```
#!/bin/bash
# Source directory (Raspberry Pi filesystem)
SOURCE="/"
# Destination directory (external SSD mount point)
DESTINATION="/mnt/external_ssd"
# Log file path
LOG_FILE="/var/log/backup.log"
# Execute rsync command
rsync -av --delete --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} $SOURCE $DESTINATION >> $LOG_FILE 2>&1
```

`SOURCE`: Specifies the root directory of your Raspberry Pi's filesystem. Change this if your filesystem is located elsewhere.

`DESTINATION`: Specifies the mount point of your external SSD. Adjust this to match the actual mount point of your SSD.

`LOG_FILE`: Specifies the path where the log of the backup operation will be saved.

`rsync`: Performs the actual synchronization. Here's a breakdown of the options used:

`-a`: Archive mode, preserves permissions, ownership, timestamps, etc.

`-v`: Verbose mode, shows the files being copied.

`--delete`: Deletes files from the destination that no longer exist in the source (ensures an exact mirror).

`--exclude`: Excludes certain directories from being copied. This list includes system directories that are not necessary for a backup.

To set this up as a weekly cron job use the following steps:

Save the script to a file, for example, `backup_script.sh`.

Make the script executable with the command `chmod +x backup_script.sh`

Open your crontab file with the command: crontab -e.

Add the following line to schedule the script to run weekly:

`0 0 * * 0 /path/to/backup_script.sh`

This cron schedule means the script will run every Sunday at midnight (0 minutes, 0 hours).

Make sure to replace `/path/to/backup_script.sh` with the actual path where you saved the script.

With this setup, your Raspberry Pi will automatically perform a weekly backup to your external SSD at the scheduled time, and the log of the backup operation will be saved to the specified log file.

##### Prevent Auto-Sleep

It happens that a System or specific parts (ie. Raspberry) go into auto-sleep. 
This can happen to the **wlan** module which is unacceptable if you are running it headless and only log in via SSH as there is no option to troubleshoot. 

Make sure the `iw` utility tool is installed, if not `sudo apt install iw`. This assists in general wlan device troubleshooting. 

Now you can just `iw wlan0 set power_save off`. 

**Note**: This is only temporary. To fix this permantently you can add the following into the root crontab

`sudo crontab -e`
which opens the root crontab in your chosen editor and add the following line at the bottom of the root crontab:

`@reboot /usr/sbin/iw wlan0 set power_save off > /home/<user>/power_save_log.txt 2>&1`
be sure to substitute a valid folder name for `<user>` 

This tells linux at every boot sequence to turn the power save off. 

You could also create a regular ping to a device OR router so that the raspberry would stay awake. 


```
0 */3 * * * ping -c 1 <router_ip_address> >/dev/null 2>&1
```

Replace `<router_ip_address>` with the IP address of your router.

Explanation of the job: 

The command `ping -c 1 <router_ip_address> >/dev/null 2>&1` pings the router once (`-c 1`) count = 1 and redirects the output to `/dev/null` to suppress any output. This command then runs every 3 hours as per the cron schedule.

##### Temperature Management

Display: Ubuntu Server `/sys/class/thermal/thermal_zone0$` cat temp --> shows in centigrade

You could create a script to read this centigrade value regularly and use as you like. 

##### Common Parameters

`mpstat` per processor utilization

`vmstat` processs, CPU, memory statistics (two arguments: NR of secs to monitor, AMT of reports) 

`sysdig` provides Container-Aware kernel Monitoring 

also: `sar -n DEV 30 2`



#### Log-Files

In your setup and configs you will be doing a lot of troubleshooting and digging into the system. As such it is key to "**Know your Logs!**"

Below a small list of the most important logs and what they do: 

- **Authorization Log**
  - `Location: /var/log/auth.log`
  - This log records all authorization mechanisms, including password checks, usage of the sudo command, and remote access attempts.

- **Daemon Log**
  - `Location: /var/log/daemon.log`
  - This log captures activities of background services (mostly known as daemons) which operate without direct user engagement. Stuff like managing the display server, SSH connections, print jobs, Bluetooth services + others.

- **Debug Log**
  - `Location: /var/log/debug`
  - This log collects detailed debugging information related to the OS and various applications for troubleshooting.

- **Kernel Log**
  - `Location: /var/log/kern.log`
  - This log is dedicated to messages directly from the Linux kernel, providing insights into the core system operations.

- **System Logs**
  - `Location: /var/log/syslog` 
  - This log includes a broader array of system information. If details are not in other logs, they are likely to be found here.
  - Also try `journalctl` which pulls from `journald` as in `journalctl --since "1 hour ago"`

- **Monitor / View logs**
  - There are several commands to make viewing or tracking the logs easier. 
  - `cat` of course to just read the log file
  - `less`command opens the file in a "less" environment, navigate through it with arrow keys
  - `tail -n 15` will show you the last 15 log entries, conversely `head -n 15` the first 15 entries.
  - `tail -f` will "follow" and keep printing the new entries.


 
#### Encryption 

##### Local File Encryption via GnuPG

1. Generate Keys via `gpg --full-generate-key`
2. encrypt the file as follow `gpg -se -r username FILE`
3. decrypt `gpg -se -r username FILE` then `>` into another doc

##### Full Disk Encryption via LUKS

> [!WARNING]
> During initial setup ALL your data will be lost!
> 
> LUKS or other Full-Disk-Encryption can have severe performance impacts. 

Ask whether this is really needed for your case (Raspberry or Server). 

Process for setup: 

*To be completed...*

##### Encrypted / Secure file transfer via SSH

You will occasionally transfer data, via machines. For this you can use Secure Copy Protocol (SCP) which opens an encrypted tunnel and then copies (as in `cp`) the data. 

Syntax is `scp + source + target` so assuming you have the SSH Keys set up already an example would be: 

`scp user@123.123.123.123:/path/to/myfile.txt /home/user/Downloads/` 



> [!WARNING]
> Avoid FTP protocol at all costs: see below explanation.  

FTP was not designed with security in mind. It is widely regarded as an insecure protocol because it uses clear-text usernames and passwords for authentication and lacks encryption. Consequently, data transmitted via FTP is susceptible to sniffing, spoofing, and brute force attacks, among other basic attack methods.


##### crontab

crontab allows for planned execution of commands and scripts. 

Example: 

`30 1 * * * /path/to/command` means run /path/to/command at 1:30 AM every day

`0 15 * * * /path/to/command` means run /path/to/command every day at 3:00 PM

`0 16 * * 5 /path/to/command` means run /path/to/command every Friday at 4:00 PM

Reminder: 

- A script needs to be made **executable** with command `chmod +x script.sh`

- Asterisk `*` means "every possible value" Example `month = *` means the command will run every month

- In principle you can save these scripts everywhere. However, there are cron-designated folders located on the system with naming scheme such as `cron.daily` and `cron.weekly`. Save your scripts there as best practice! Make sure the folder and script are executable and that running the folder or script is actually in the cron job. 

```
first number = minutes.
The second number = hours (24 hour format).
The third number = days of the month.
The fourth number = months.
The fifth number = days of the week.
```

Tip on timestamps and crontab:

For occasions where you will `echo` something with the crontab and you need timestamps you can refer to below commands. 

-YYYY-MM-DD	= `date -I`	

-YYYY-MM-DD_hh:mm:ss	= `date +%F_%T`	

-YYYYMMSShhmmssnnnnnnnnn (nanoseconds) = `date +%Y%m%d%H%M%S%N`


#### User Management

##### User deletion incl. homefolder

Use `cat /etc/passwd | cut -d: -f1`

**Explanation**

-cat: Displays the contents of a file.

-/etc/passwd: Path of the passwd file that contains user information.

-Pipe(|): Redirects the output of one command into another.

-cut: Extracts parts of lines from a file or piped data.

-d:: Specifies colon (“:”) as a delimiter.

-f1: Specifies a field. Here number 1 means the first field.

Now: `sudo deluser --remove-home myuser`

##### chmod and chown 

Let's say we have example-file and directory below: 

-File: `-rw-rw-r-- 1 user group 1.2K Apr 25 22:18 travelItaly.txt`

-Directory `drwxrwxr-x  2 user group 4.0K Apr 26 22:15 exampleItaly`

File Type `d`	User `rwx`	Group	`rwx` Global `r-x`

**chmod** 

The command `chmod` stands for change mode and allows to change the rights of a file. 

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
> Using Octal Notation is **much** faster.

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

The command `chown` stands for change owner and allows to change the owner and group of a file.

Syntax is `chown USER FILE` whereby `USER` is the **new** user of the file. To assign the group as well use `chown USER:GROUP FILE`



#### Misc Controlls CLI

##### pipe, grep, sort

- The pipe command invoked by using `|` redirects output from one command to another for further processing. Example command `cat greptestfile.txt | grep "World"` Will read `cat` a textfile and then "pipe" `|`the file to `grep` to search for "World" and then display the line. 

- The `grep` command allows for searching text and strings and is **case-sensitive**.

- The `sort` command can sort a given file content alphabetically (default) or as specified per argument. Syntax `sort filename`

#### Mail Setup

There will be cases where you'll want automatic reminders sent based on system-events or similiar. 

Example: CPU Temperature exceeds 75 Degrees -> Send mail to myself.

Prerequisites: 

1. **Separate** G-Mail Account. Do not risk your Main Account for a small DIY project, always assume the worst case and segregate wherever possible! The Account needs to have 2FA enabled. If you don't want to use your phone number you can use the Authenticator App (MS or Google Auth). 

2. App-password  **or** actual mail account password (not suggested: if this PW leaks your account is open!) Also GMAIL does not support this anymore by end of 2024. Switch to App-password if possible. That way the possible damaged is limited to only the App that uses it. Create passwords per App and do not use interchangable! Again: segregate where possible! 
  
3. `apt-get install ssmtp mailutils` provides the appropriate software. 

4. Your mail address and app-password are entered in the ssmtp config file `/etc/ssmtp/ssmtp.conf` and revaliases file `/etc/ssmtp/revaliases`. Note that in order to edit you may need to temporary change the access rights of both the directory and the folder via `chmod 777` and then back again with `chmod 640`. I had to keep the folder at `chmod 777` to keep it working. The files were ok with `chmod 640`. 

5. Important: The App-Password is one string (even though google separates it). Therefore: `abcd defg abdd defg` becomes `abcdefgabcdefg` in the config file. 

6. You find your hostname by just using the `hostname`command. 

**Config File Setup ssmtp.conf**

```
# Config file for sSMTP sendmail
#
# The person who gets all mail for userids < 1000
# Make this empty to disable rewriting.
root=username@gmail.com

TLS_CA_FILE=/etc/pki/tls/certs/ca-bundle.crt

# The place where the mail goes. The actual machine name is required no 
# MX records are consulted. Commonly mailhosts are named mail.domain.com
mailhub=smtp.gmail.com:587

# Where will the mail seem to come from?
rewriteDomain=gmail.com

# The full hostname
hostname=HOSTNAMEOFYOURSYSTEM

# Are users allowed to set their own From: address?
# YES - Allow the user to specify their own From: address
# NO - Use the system generated From: address
FromLineOverride=YES

AuthUser=gmailusername
AuthPass=APP-Password
UseTLS=Yes
UseSTARTTLS=YES
```

Revaliases File Setup revaliases

```
# sSMTP aliases
# 
# Format:	local_account:outgoing_address:mailhub
#
# Example: root:your_login@your.domain:mailhub.your.domain[:port]
# where [:port] is an optional port number that defaults to 25.
root:username@gmail.com:smtp.gmail.com:587
localuser:username@gmail.com:smtp.gmail.com:587
www-data:username@gmail.com:smtp.gmail.com:587
```

> [!TIP]
> If possible always segregate! Set up a Relay address so that your MAIN address is not visible to any intercepting/malicious traffic. Example setup : Rasbperry Mail -> Relay Mail (ie. SimpleLogin) -> MAIN Address.

Testing: To test your configuration setup, simply send a mail via `mail -s "Subject" RECIPIENT` followed by the Body of the Message, then press `ctrl + D`to send. 

Of course this makes a lot more sense in a `cron-job` context that runs daily/weekly/monthly. 

**Examples**

-Failed Login Attempts: Include information about failed login attempts from the authentication log `(/var/log/auth.log)`. Can help you identify potential brute-force attacks or unauthorized access attempts.

-SSH Sessions: Monitor SSH sessions for any unusual activity, such as multiple sessions from the same IP address or connections from unfamiliar locations.

-System Resource Usage: Include information about CPU (temp), memory, and disk usage to identify any abnormal spikes or resource exhaustion.

-Network Traffic: Monitor network traffic to detect any unusual or suspicious patterns, such as a sudden increase in traffic or connections to known malicious IPs.

-System Updates: Check for available system updates and include information about pending updates or security patches that need to be applied.

-File Integrity: Perform periodic checks to ensure the integrity of critical system files and configurations. Unexpected changes could indicate a compromise. Be creative with this one ;) 

-Backup Status: Include information about the status of your system backups to ensure that critical data is being properly backed up and can be restored in case of a security incident.

-User Account Management: Monitor user account activity, such as new account creations or changes to user privileges, to detect any unauthorized changes.

-System Logs Analysis: Analyze various system logs, including application logs and web server logs, for any suspicious activities or anomalies. You could `grep`for certain keywords and let the appropiate lines be mailed to you. 

###### Daily security-report cron

Add below to the cron job

```
0 0 * * * grep 'Accepted\|Failed' /path/to/auth.file /path/to/fail2ban.log /var/log/auth.log /var/log/syslog > /path/to/outputfile
```

> [!CAUTION]
> There is a security risk transmitting this unencrypted. See below how to mitigate.

Transmitting these log entries unencrypted is a risk. If the logs are intercepted during transmission, an attacker could gain information about your system's users and their activities. 

To mitigate this risk, you could:

- Use secure, encrypted protocols for transmission (like SCP, SFTP, or HTTPS).

- Encrypt the log files before transmission, using tools like `gpg`.

- Only transmit the logs over networks you trust.(But still, be careful - better to encrypt) 


###### Daily system-report cron 

It would make sense to receive a daily status report of how the system is doing (include all possible sensor readings etc.) . Such is the purpose of below report 

```
#!/bin/bash

# Run the commands
OUTPUT=$(uptime && vcgencmd measure_temp && vcgencmd get_throttled && df -TH && free -h && ss -to state established && ss -tulnp)

# Send the output via email
echo "$OUTPUT" | mail -s "Daily Report" RECIPIENT
```
Save this script to a file named `daily_report.sh` then make it executable with `chmod +x daily_report.sh`.

Then add this script to the daily cron job. Open the crontab file with `crontab -e` and add the following line:

```
0 0 * * * /path/to/daily_report.sh
```

This script will run every day at midnight. Replace `/path/to/` with the actual path to the `daily_report.sh` script and `RECIPIENT` with the actual email address.

Note that you need to have the `mail` command installed and properly configured (also in this guide) to send emails. As far as I know, `vcgencmd` is specific to Raspberry Pi devices, so make sure you're running this on a Raspberry Pi, or remove those lines if you're not. 

Always test your script manually before adding it to cron to make sure it works as expected: 

`cd` into the place where you saved the script. Run it directly with the command `./daily_report.sh`. 

Note that `./` needs to preceed the script name. 



## Networking 

### IP Addresses 

### Subnetting 

### VLAN Setup 

> [!CAUTION]
> On the Topic of VLANS: Consider all caveats and ask whether this is really necessary or if there is no workaround. The cost (monetary and time) to setup and maintain are really high.

###### Tagged

###### Untagged

###### Trunks



### pfsense Setup 

## Proxmox Setup

#### Host Security

1. **Cluster Isolation**:
   - Ensure that the Proxmox cluster is **not reachable from outside** the trusted network.
   - Implement network segmentation to prevent unauthorized access.

2. **Fail2Ban with Monitoring and Email Alerts**:
   - Set up **Fail2Ban** to monitor and block suspicious login attempts.
   - Configure email alerts for security events.

3. **Host Encryption**:
   - Encrypt the Proxmox hosts using **LUKS (Linux Unified Key Setup)** full disk encryption (FDE).
   - This protects data at rest and prevents unauthorized access to the host.

4. **Encrypted Swap**:
   - Enable swap encryption to secure sensitive data in memory.

5. **IP-Based Access Control**:
   - Restrict access to the Proxmox hosts based on IP addresses.
   - Whitelist trusted IPs and block unauthorized ones.

6. **Firewall Protection**:
   - Place the Proxmox hosts behind a **Pfsense Firewall** for additional security.
   - Configure firewall rules to allow only necessary traffic.

7. **Two-Factor Authentication (2FA)**:
   - Enforce 2FA for each user accessing the Proxmox hosts.
   - This adds an extra layer of authentication.

#### VM Security

1. **VLAN Segmentation**:
   - Assign a separate VLAN for each critical VM.
   - Group non-critical VMs into application-specific VLANs.

2. **Fail2Ban for VMs**:
   - Implement **Fail2Ban** within VMs to protect against brute-force attacks.
   - Monitor and receive email alerts for suspicious activity.

3. **VM Encryption**:
   - Encrypt VMs to safeguard their data.
   - Use encryption mechanisms available within the VMs.

4. **Network Storage Isolation**:
   - VMs should not have direct access to network storage.
   - Only the Proxmox host should provide storage to VMs.

5. **Custom Ports**:
   - Configure custom ports for VM services.
   - Avoid using default ports to reduce exposure.

6. **Firewall for VMs**:
   - Place VMs behind a **Pfsense Firewall** to filter traffic.
   - Apply access control rules to allow necessary communication.

7. **Swap Encryption for VMs**:
   - Enable swap encryption within VMs to protect sensitive data.

8. **Service Publication via HAProxy**:
   - Publish services through **HAProxy** with an additional layer of access control.
   - HAProxy can handle load balancing and provide security features.

####Backup Security

1. **Encrypted Backups**:
   - Ensure that backups are always encrypted.
   - Use encryption mechanisms provided by backup tools.

2. **Off-Site Storage**:
   - Store backups off-site, away from the primary location.
   - Prevent data loss due to local disasters.

3. **Cold Storage Backups**:
   - Perform weekly cold storage backups.
   - Cold storage ensures data availability even if the live system fails.

4. **Protection Against Changes**:
   - Protect off-site backups against unauthorized changes.
   - Implement access controls and integrity checks.
  

##### SSL Certificate via Let's Encrypt

Problem: You don’t want to see certificate warnings all the time. How do you get the green lock locally?

Solution: Generate your own certificate, either self-signed or signed by a local root, and trust it in your operating system’s trust store. Then use that certificate in your local web server. See below for details. You can actually make your own certificates without help from a CA. Only difference is that certificates you make yourself **won’t be trusted by anyone else** (which makes sense, no CA involved). **For local development, that’s fine.**

A way to generate a private key and self-signed certificate for localhost is with this command:

```
openssl req -x509 -out localhost.crt -keyout localhost.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
```
 
**Explanation**: 

- `openssl req`: This is the command to create and process certificate requests in PKCS#10 format.

- `-x509`: This option specifies that a self-signed certificate is to be generated.

- `-out localhost.crt`: This designates the output filename for the certificate.

- `-keyout localhost.key`: This specifies the output filename for the private key.

- `-newkey rsa:2048`: This creates a new certificate request and a new private key. `rsa:2048` indicates an RSA key of 2048 bits.

- `-nodes`: This tells OpenSSL to not encrypt the private key, meaning "no DES".

- `-sha256`: This specifies the use of the SHA-256 hash algorithm.

- `-subj '/CN=localhost'`: This sets the subject field for the certificate to have a common name (CN) of 'localhost'.

- `-extensions EXT`: This specifies the extensions to be added to the certificate.

- `-config <(...)`: This is a shell feature called process substitution, which allows the output of a command to be used as a file. The `printf` command inside generates the necessary configuration on the fly.

The `printf` command generates a minimal configuration file with the following contents:

- `[dn]` and `CN=localhost` set the distinguished name to 'localhost'.

- `[req]` and `distinguished_name = dn` tell the request to use the distinguished name specified earlier.

- `[EXT]` defines a section for extensions, where `subjectAltName=DNS:localhost` adds an alternative name for the certificate, which is important for matching the certificate to the domain name.

- `keyUsage=digitalSignature` restricts the key's usage to digital signatures.

- `extendedKeyUsage=serverAuth` indicates that the key is used for server authentication.

Of course: For production environments, it's recommended to use certificates issued by a trusted Certificate Authority (CA) like Lets Encrypt.

##### Setting up a rsyslog server 

###### Target

The Raspberry in question needs to have a static IP so that the TARGET is clear. 

If not installed make sure it is from `sudo apt install rsyslog`

Make sure raspberry listens on Port 514 `sudo nano /etc/rsyslog.conf` You can do this by uncommenting these lines 

```
module(load="imudp")
input(type="imudp" port="514")

module(load="imtcp")
input(type="imtcp" port="514")
```

*Placeholder--> Both Protocols necessary? Security Risk? Why does the sender need an ACK ?* 

###### Template Creation

Now we need to create a template. This template tells syslog where to route the messages it’s receiving. For this, you will need to know your device’s **static** IP address.

Create a config file within the `/etc/rsyslog.d` directory. Config files writen within this directory will be read automatically by **rsyslog** when we (re)start it.
Within this file, we will define a new template. Additionally, we also specify some configuration to route syslog messages to our new log file.
For this example, we will call this file `SuperSafeRouterLog.conf`. You can give this file any name you want, but it must end in `.conf`.

Therefore just: `sudo nano /etc/rsyslog.d/SuperSafeRouterLog`

Now, a template tells the syslog server where to save the logs to.

`$template NameForTemplate, "DirectoryWhereLogIs/logName.log`

To route the syslog messages to our template, we need configure as follows:

Swap out “IPADDRESSTOUSE” with the IP of the device you are expecting to receive the syslog messages **from**.

Additionally, you will need to also swap out “templatename” with the name you specified in the previous step.

`if $fromhost-ip startswith "IPADDRESSTOUSE" then -?templatename & stop`

Example File: 
```
$template routerlog, "/var/log/router.log"

if $fromhost-ip startswith "192.168.0.1" then -?routerlog
& stop
```

Then restart the rsyslog service with `sudo systemctl restart rsyslog`

###### Sender

Note: Now enable the syslog protocol on the device you are using and point it towards your Raspberry Pi’s IP. 
The Raspberry Pi will start receiving the log messages from the device and start saving them to the log file you specified for that template.

How to Point towards syslog server? 

Edit the rsyslog Config File located in `/etc/rsyslog.conf` which also relates to `/etc/rsyslog.d/50-default.conf` 

```
#Note: Taken from Rainers Guide on rsyslog setup: 
#this is the simplest forwarding action:
# *.* action(type="omfwd" target="192.X.X.X" port="514" protocol="tcp")
# it is equivalent to the following obsolete legacy format line:
*.* @@192.0.2.1:10514 # do NOT use this any longer!
# Note: if the remote system is unreachable, processing will block here
# and discard messages after a while
# so a better use is
*.*  action(type="omfwd" target="192.X.X.X" port="514" protocol="tcp"
            action.resumeRetryCount="100"
            queue.type="linkedList" queue.size="10000")
# this will de-couple the sending from the other logging actions,
# and prevent delays when the remote system is not reachable. Also,
# it will try to connect 100 times before it discards messages as
# undeliverable.
# the rest below is more or less a plain vanilla rsyslog.conf as 
# many distros ship it - it's more for your reference...
# Log anything (except mail) of level info or higher. 
# Don't log private authentication messages!
*.info;mail.none;authpriv.none;cron.none      /var/log/messages
# The authpriv file has restricted access.
authpriv.*                                    /var/log/secure
# Log all the mail messages in one place.
mail.*                                        /var/log/maillog
# Log cron stuff
cron.*                                        /var/log/cron
# Everybody gets emergency messages
*.emerg                                       :omusrmsg:*
# Save news errors of level crit and higher in a special file.
uucp,news.crit                                /var/log/spooler
# Save boot messages also to boot.log
local7.*                                      /var/log/boot.log

```
By the way: 
```
authpriv – non-system authorization messages

auth - authentication and authorization related commands
```


###### Encrypting the Log Traffic

In order to transmit these log files securely and encrypted (as you should) find below the setup. 

Like many things, this works also via TLS(SSL) Certificate. Therefore this is needed. Check this part of the Repo/Github Page. 

To be completed with info from `https://www.rsyslog.com/doc/tutorials/tls.html`


### SSH Hardening

Note: Any SSH configuration files are located at `/etc/ssh/sshd_config.`

Most of the SSH hardening tips will require editing this config file. It is good practice to back up the original file. After a change you also need to restart the SSH service if you make any changes to the SSH config file.

##### Fail2Ban Install Guide

**Note:** If you disable the password based SSH Login, using Fail2Ban doesn't really make sense. Why? Because it is intended for BruteForce, and with a Key-Only setup that wouldn't even happen (but of course, better safe than sorry). 

install Fail2Ban with the command `sudo apt install fail2ban`

As always make sure your system is updated:

`sudo apt update && sudo apt upgrade -y`

Navigate to `/etc/fail2ban/jail.conf`

Main configuration files that dictate Fail2Ban Behaviour are `/etc/fail2ban/fail2ban.conf` and `/etc/fail2ban/jail.conf` Number of retries before banning an IP, whitelisting IPs, mail sending information and general controls come from these files.

It is advised to make a copy with .local for for these conf files. Remember: the default conf files can be overwritten in updates and you would risk loosing all your settings.

```
sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

The `jail.conf` file is divided into services. There is a [Default] section which applies to all services. There are also various services with their respective setting. All these services are in brackets. You’ll see sections like [sshd], [apache-auth], [squid] etc.

Without the respective comments the default section looks like this:

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


Meanings explained: 

`bantime`: Set the length of the ban. Default is 10 minutes.
`findtime`: The window in which the action on an IP will be taken. Default is 10 minutes. Suppose a bad login was attempted by a certain IP at 10:30. If the same IP reaches the maximum number of retries before 10:40, it will be banned. Otherwise, the next failed attempt after 10:40 will be counted as first failed attempt.
`maxretry`: The number of failed retries before an action is taken
`usedns`: The “warn” setting attempts to use reverse-DNS to look up the hostname and ban it using hostname. Setting it to no will ban IPs, not hostname.
`destemail`: The email address to which the alerts will be sent (needs to be configured)
`sender`: The sender name in the notification email
`mta`: Mail Transfer Agent used for notification email
`banaction`: This parameter uses the /etc/fail2ban/action.d/iptables-multiport.conf file to set the action after maximum failed retries
`protocol`: The type of traffic that will be dropped after the ban

If you want to make any changes for any jail (or for all the jail) edit the `jail.local` file.

How does fail2ban work in the context of hardening: 

You can use systemd commands to start and enable Fail2Ban on your Linux server:
```
systemctl start fail2ban
systemctl enable fail2ban
```
Once Fail2Ban is enabled, you can see the status and the active jails with fail2ban-client command:

`fail2ban-client status`

Status
|- Number of jail: 1
`- Jail list: sshd

Note that sshd jail is enabled by default -> which is good :). 

Fail2Ban logs are located at `/var/log/fail2ban.log`. 

You can use the Fail2Ban client to check the status of banned IPs and clients to give you an overview. 

`fail2ban-client status <jail_name>`

For example, if you want to see all the "bad" ssh logins banned by Fail2Ban, use the below command. The output would show the total failed attempts and the total banned IPs.

```
user@test-server:~# sudo fail2ban-client status sshd
Status for the jail: sshd
|- Filter
| |- Currently failed: 33
| |- Total failed: 700
| `- File list: /var/log/auth.log
`- Actions
|- Currently banned: 3
|- Total banned: 20
`- Banned IP list: xxx.xxx.xxx.xxx.
```

Fail2Ban does ban on a temporary level. It is not advised to change this to permanent. You can simply change this to a longer interval or make it incrementally "worse" for the attacker. 

Example: 
```
# initial ban time:
bantime = 1h
# incremental banning:
bantime.increment = true
# default factor (causes increment - 1h -> 1d 2d 4d 8d 16d 32d ...):
bantime.factor = 24
# max banning time = 5 week:
bantime.maxtime = 5w
```


How to unban blocked IPs

First check if the IP is being blocked or not. Since Fail2Ban works on the iptables, you can look into the iptable to view the IPs being banned by your server:

`iptables -n -L` (Work with the `grep`command detailed above in case there are too many IPs.

So, the next step is to find which service or jail is banning the IP we are looking for.

Once found simply unban with `fail2ban-client set <jail_name> unbanip <ip_address>`

Whitelist IP in Fail2Ban

We are all clumsy and could ban ourselves. To ignore/whitelist specific IP address from being banned by Fail2Ban, you can temporarily whitelist the IP using a command like this:

`fail2ban-client set <JAIL_NAME> addignoreip <IP_Address>`

Note: Locate your own IP with `ip a` command

Whitelist permanently by editing the actual config file located in `/etc/fail2ban/jail.local`  and add a line under the DEFAULT section like this: 

`ignoreip = 127.0.0.1 <IP_TO_BE_WHITELISTED>`

Make sure to to restart Fail2Ban to take this change into effect.

You can see all the IPs whitelisted by a jail using this command:

`fail2ban-client get <JAIL_NAME> ignoreip`

If you want to remove the IP from a certain jail’s whitelist, you can use this command:

`fail2ban-client set <JAIL_NAME> delignoreip <IP_Address>`

###### Disable empty passwords

It is partially possible to have user accounts in Linux without any passwords. If those users try to use SSH, they won’t need passwords for accessing the server via SSH as well.

This is of course a security risk and should be corrected. In the `/etc/ssh/sshd_config` file, make sure to set `PermitEmptyPasswords` option to no.

###### Change default SSH ports

The default SSH port is 22, therefore most of the attack scripts are written around this port. Changing the default SSH port should add an additional security layer because the number of attacks (coming to port 22) may be reduce.

Search for the port information in the config file and change it to something different:

Example: Port 1234

> [!TIP]
> Remember to note down the port number.

###### Disable root login via SSH

Root Login is by default deactivated in UBUNTU (as it should be!). It is a grave security risk and leaves no audit trail. Think about it: No trace of who did what! A mechanism like sudo exists specifically for this reason.

Always force all users to SSH via their user and completely disable root. 

If you have sudo users added on your system, you should use that sudo user to access the server via SSH instead of root.

Cisable the root login by modifying the `PermitRootLogin` option and setting it as no:

`PermitRootLogin = no`

###### Disable ssh protocol 1

In case an older Linux distribution is used some older SSH version might still be in use (SSH protocol 1 vs 2). This protocol has known vulnerabilities and must **not** be used.

Newer SSH versions automatically have SSH protocol 2 enabled. 

Check with command `ssh -V` for a Verbose output of ssh version. 

###### Configure idle timeout interval

The idle timeout interval is the amount of time an SSH connection remains active without any activity. Idle sessions are considered a security risk. It is a good idea to configure idle timeout interval and bring this down to 5 minutes. The interval is indicated in seconds in the config file. 

`ClientAliveInterval 300`will give you 300 seconds = 5 minutes of idle activity. 

`ClientAliveCountMax 2` will send two alive messages. 

After this 300 second interval, the SSH server will send two alive messages to the client. If it doesn’t get a response, the connection will be closed and the end user will be logged out.

###### Allow SSH access to selected users only

Always follow the principle of least privilege. Do not give rights when it is not required.

Ask yourself: Do you need to allow SSH access to all of your users? 

A best practice approach here would be to allow SSH access to only a handful of selected users and restricting for all the other users.

`AllowUsers User1 User2`
Note that you could also add selected users to a new group and allow only this group to access SSH.

`AllowGroups ssh_group`
Note that you could also use the DenyUsers and DenyGroups to deny SSH access to certain users and groups.

###### Disable X11 Forwarding

The X11 or the X display server is the basic framework for a graphical environment forwarding, meading that it allows you to use a GUI application via SSH.

How this works is that the client runs the GUI application on the server and then a channel is opened between the machines and the GUI applications is displayed on the client machine.

The X11 protocol is not security oriented. If you don’t need it, disable the X11 forwarding in SSH.

`X11Forwarding no`

Interesting excerpt from IBMs X11 page: 

```
An important security issue associated with the X11 server is unauthorized silent monitoring of a remote server.

The xwd and xwud commands can be used to monitor X server activity because they have the ability to capture keystrokes, which can expose passwords and other sensitive data. To solve this problem, remove these executable files unless they are necessary under your configuration, or, as an alternative, change access to these commands to be root only.
```

###### Disable password based SSH login

No matter how much a system is protected there is a high likelyhood of brute-force attempts via SSH. Tools like Fails2Ban are well known so it is good practice to opt-in for Key-Based Login only. 

> [!IMPORTANT]
> Again because this is one of my favourite topics: If you can, set up ssh-keys for your Login and disable password based logins.

In this approach, you add the public key of the remote client systems to the known keys list on the SSH server. This way, those client machines can access SSH without entering the user account password.

When you have this setup, you can disable password based SSH login. Now, only the clients machines that have the specified SSH keys can access the server via SSH.

Before you go for this approach, make sure that you have added your own public key to the server and it works. Otherwise, you will lock yourself out and run the risk of losing access to the remote server. Especially cumbersome if you are using a cloud server like Linode where there is no physical access to the server.

> [!WARNING]
> Before disabling ssh password authentication. Make sure your access with private key works as expected. Once confirmed, disable password authentication.

Edit file with: `sudo nano /etc/ssh/sshd_config`

Make sure you have following values enabled in the file:

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

###### Two-factor authentication with SSH

To take your servers SSH security to a higher level, you could enable two-factor authentication. In this approach, you receive a OTP (one-time password) on your mobile phone, via email or through a third-party aunthentication app.

*To-Be Completed...* with MS Auth Code.  

###### Conclusion

You can see all the parameters of your SSH server using the command `sshd -T`

This way, you can easily see if you need to change any parameter to enhance the security of the SSH server. Also remember to keep the SSH install and system updated regularly.



















## Writeup Help
 
> [!NOTE]  
> Useful information that users should know, even when skimming content.

> [!TIP]  
> Helpful advice for doing things better or more easily.

> [!IMPORTANT]  
> Key information users need to know to achieve their goal.

> [!WARNING]  
> Urgent info that needs immediate user attention to avoid problems.

> [!CAUTION]
> 
> Advises about risks or negative outcomes of certain actions.




