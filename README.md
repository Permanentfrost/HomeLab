# raspberry
All Code / Write-ups and Documentation related to homelab setups. 

# Why? 
1.Learning About Networks, SysAdmin etc. 
2.Track learning progress. 

# SSH Hardening
## Fail2Ban
install Fail2Ban with this command 
sudo apt install fail2ban


### /etc/fail2ban/jail.conf
This is where all the magic happens. This is the file where you can configure things like default ban time, number of reties before banning an IP, whitelisting IPs, mail sending information etc. Basically you control the behavior of Fail2Ban from this file.
----

### Do not go and blindly follow all the SSH hardening tips mentioned here. Read all of them and then see which ones fit your need. Also keep in mind that some tips might not be compatible with others.

For example, if you disable the password based SSH login, there is no need to go for Fail2Ban kind of solution.

If you are aware of SSH basics, you know that the SSH configuration files are located at /etc/ssh/sshd_config.

Most of the SSH hardening tips mentioned here will require you to edit this config file. This is why it will be a good idea to back up the original file. You’ll also need to restart the SSH service if you make any changes to the SSH config file.

Let’s see what steps you can take to secure your SSH server.

### 1. Disable empty passwords

Yes. It is possible to have user accounts in Linux without any passwords. If those users try to use SSH, they won’t need passwords for accessing the server via SSH as well.

That’s a security risk. You should forbid the use of empty passwords. In the /etc/ssh/sshd_config file, make sure to set PermitEmptyPasswords option to no.

PermitEmptyPasswords no
### 2. Change default SSH ports

The default SSH port is 22 and most of the attack scripts check are written around this port only. Changing the default SSH port should add an additional security layer because the number of attacks (coming to port 22) may reduce.

Search for the port information in the config file and change it to something different:

Port 2345
You must remember or note down the port number otherwise you may also not access your servers with SSH.

### 3. Disable root login via SSH

To be honest, using server as root itself should be forbidden. It is risky and leaves no audit trail. Mechanism like sudo exist for this reason only.

If you have sudo users added on your system, you should use that sudo user to access the server via SSH instead of root.

You can disable the root login by modifying the PermitRootLogin option and setting it as no:

PermitRootLogin no

### 4. Disable ssh protocol 1

This is if you are using an older Linux distribution. Some older SSH version might still have SSH protocol 1 available. This protocol has known vulnerabilities and must not be used.

Newer SSH versions automatically have SSH protocol 2 enabled but no harm in double checking it.

Protocol 2
### 5. Configure idle timeout interval

The idle timeout interval is the amount of time an SSH connection can remain active without any activity. Such idle sessions are also a security risk. It is a good idea to configure idle timeout interval.

The timeout interval is count in seconds and by default it is 0. You may change it to 300 for keeping a five minute timeout interval.

ClientAliveInterval 300
After this interval, the SSH server will send an alive message to the client. If it doesn’t get a response, the connection will be closed and the end user will be logged out.

You may also control how many times it sends the alive message before disconnecting:

ClientAliveCountMax 2
### 6. Allow SSH access to selected users only

When it comes to security, you should follow the principal of least privilege. Don’t give rights when it is not required.

You probably have several users on your Linux system. Do you need to allow SSH access to all of them? Perhaps not.

An approach here would be to allow SSH access to a selected few users and thus restricting for all the other users.

AllowUsers User1 User2
You may also add selected users to a new group and allow only this group to access SSH.

AllowGroups ssh_group
You may also use the DenyUsers and DenyGroups to deny SSH access to certain users and groups.

### 7. Disable X11 Forwarding

The X11 or the X display server is the basic framework for a graphical environment. The X11 forwarding allows you to use a GUI application via SSH.

Basically, the client runs the GUI application on the server but thanks to X11 forwarding, a channel is opened between the machines and the GUI applications is displayed on the client machine.

The X11 protocol is not security oriented. If you don’t need it, you should disable the X11 forwarding in SSH.

X11Forwarding no
### 8. Mitigate brute force attacks automatically

To thwart SSH bruteforce attacks, you can use a security tool like Fail2Ban.

Fail2Ban checks the failed login attempts from different IP addresses. If these bad attempts cross a threshold within a set time interval, it bans the IP from accessing SSH for a certain time period.

You can configure all these parameters as per your liking and requirement. I have written a detailed introductory guide on using Fail2Ban which you should read.

### 9. Disable password based SSH login

No matter how much you try, you’ll always see bad login attempts via SSH on your Linux server. The attackers are smart and the scripts they use often take care of the default settings of Fail2Ban like tools.

To get rid of the constant brute force attacks, you can opt for only key-based SSH login.

In this approach, you add the public key of the remote client systems to the known keys list on the SSH server. This way, those client machines can access SSH without entering the user account password.

When you have this setup, you can disable password based SSH login. Now, only the clients machines that have the specified SSH keys can access the server via SSH.

Before you go for this approach, make sure that you have added your own public key to the server and it works. Otherwise, you’ll lock yourself out and may lose access to the remote server specially if you are using a cloud server like Linode where you don’t have physical access to the server.

Read this detailed tutorial to learn how to disable password based SSH authentication.

### 10. Two-factor authentication with SSH

To take SSH security to the next level, you may also enable two-factor authentication. In this approach, you receive a one-time password on your mobile phone, email or through a third-party aunthentication app.

You may read about setting up two-factor authentication with SSH here.

Conclusion

You can see all the parameters of your SSH server using this command:

sshd -T
This way, you can easily see if you need to change any parameter to enhance the security of the SSH server.

You should also keep the SSH install and system updated.

I have listed some practical ways of SSH hardening. Of course, there can be several other ways you can secure SSH and your Linux server. It’s not possible to list all of them in a single article.

I hope you find these tips helpful. Do let me know which tips you find useful.

Do you know any additional tips on SSH security? Why not share it with us in the comment section?
