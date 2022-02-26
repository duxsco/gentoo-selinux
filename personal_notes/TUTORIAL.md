# Quick and dirty writedown of SELinux tutorial

This document contains a quick and dirty copy&paste of the most important aspects of the [SElinux Tutorial](https://wiki.gentoo.org/wiki/SELinux/Tutorials).

## Cheat sheet

Credits: https://wiki.gentoo.org/wiki/SELinux/Tutorials/

List:
- Processes: `pz -Z`
- Filesystem content:
  - `ls -Z <FILE|DIR>`
  - `stat <FILE|DIR>`
  - `getfattr -m security.selinux -d <FILE|DIR>`

### Type enforcement

In SELinux vocabulary, we say that ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/How_SELinux_controls_file_and_directory_accesses#SELinux-ifying_the_examples)):
1. the context of the process that is acting upon something is called the `domain`
2. the context of the resource on which the process is acting is called the `type`
3. the object class of the resource (e.g. file or socket) is called the `class`
4. the permission or permissions that are allowed given the domain, type and class are the `permissions`

With this vocabulary in mind, an SELinux allow statement is structured as follows:

```
allow <domain> <type>:<class> { <permissions> };
```

`auditd_t` is the domain ([source](Source: https://wiki.gentoo.org/wiki/SELinux/Tutorials/How_SELinux_controls_file_and_directory_accesses#SELinux_domains_and_types)):

```bash
➤ ps -eZ | grep auditd
system_u:system_r:auditd_t      24008 ?        00:00:00 auditd
```

And behold, we can ask SELinux if this rule is enabled on our system, using sesearch ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/How_SELinux_controls_file_and_directory_accesses#An_example_type_enforcement_rule)).

```bash
➤ sesearch --allow --source auditd_t --target auditd_log_t --class file --perm write
Found 1 semantic av rules:
   allow auditd_t auditd_log_t : file { ioctl read write create getattr setattr lock append unlink link rename open } ; 
```

## Hidden denials

We've told you already that denial logs can be cosmetic. Since they do not reflect real problems, SELinux policy writers can hide those denials from regular logging so that users are not baffled by the various denials they get. This is done through dontaudit statements. A default SELinux policy in most distributions will already have a lot of such statements active, which you can verify through seinfo ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Where_to_find_SELinux_permission_denial_details#Hidden_denials)).

```bash
➤ seinfo | grep audit
   Auditallow:          1    Dontaudit:        5341
```

In some cases, the SELinux policy writers can be wrong (of course, they are still human) so it might make sense to disable these dontaudit statements for a short while (while you are reproducing the permission problem you are facing). This can be done using the semodule command:

```bash
➤ semodule --disable_dontaudit --build
```

The shorter version of this command is semodule -DB, btw. What happens here is that the SELinux management utility semodule rebuilds the SELinux policy, but ignores the dontaudit statements. The policy is then loaded in memory. Once you disable the dontaudit statements, effectively all denials are logged. 

When you are tired of seeing all those denials, you can re-enable the dontaudit statements, by rebuilding the policy:

```bash
➤ semodule --build
```

If you want to see all the dontaudit statements, run sesearch --dontaudit. You will notice that they follow the same structure as the allow statements we have seen earlier on.

```bash
➤ sesearch --dontaudit

...
   dontaudit httpd_t user_tty_device_t : chr_file { ioctl read write getattr append open } ; 
   dontaudit mta_user_agent httpd_sys_script_t : fd use ;
```

## Other ways to read denial information

https://wiki.gentoo.org/wiki/SELinux/Tutorials/Where_to_find_SELinux_permission_denial_details#Other_ways_to_read_denial_information

### ausearch

The ausearch utility is not an SELinux-specific utility. It is a Linux audit related utility, which parses the audit logs and allows you to query the entries in the logs. One of the advantages that it shows is that it already converts the time stamp into a human readable one.

```bash
➤ ausearch -m avc --start recent

time->Thu Mar 14 21:15:57 2013
type=AVC msg=audit(1363292157.560:188): avc:  denied  { read } for  pid=29495 comm="Trace"
name="online" dev="sysfs" ino=30 scontext=staff_u:staff_r:googletalk_plugin_t
tcontext=system_u:object_r:sysfs_t tclass=file
```

### sealert

The sealert command is not provided on an SELinux-enabled Gentoo system by default, but it is available on RedHat Enterprise Linux and related distributions. It integrates together with a specific daemon called setroubleshootd, which gives a translation of an AVC denial similar to the human translation given earlier in this tutorial. For instance, the following message can be displayed in the system logs:

```
setroubleshoot: SELinux is preventing httpd (httpd_t) "getattr" to /var/www/html/file1
(samba_share_t). For complete SELinux messages.
run sealert -l 84e0b04d-d0ad-4347-8317-22e74f6cd020
```

The sealert tool then gives a more detailed explanation of the denial:

```bash
➤ sealert -l 84e0b04d-d0ad-4347-8317-22e74f6cd020
```

## Query file context definitions

With semanage fcontext, we can query the existing SELinux file context definitions. To get to the definition for the audit logs ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Controlling_file_contexts_yourself#Building_a_file_context_definition.2Fexpression)):

```bash
➤ semanage fcontext -l | grep auditd_log_t
/var/log/audit(/.*)?                               all files          system_u:object_r:auditd_log_t
```

The semanage utility uses the files in /etc/selinux/*/contexts/files as its source ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Controlling_file_contexts_yourself#All_file_context_definitions)).

To get information on what the context ought to be (according to the SELinux configuration files), you can use matchpathcon.

```bash
user $/usr/sbin/matchpathcon /home/swift/.config
/home/swift/.config      staff_u:object_r:xdg_config_home_t
```

### Applying contexts on files

The `restorecon` utility will check the contexts of the files and match those against the contexts that are defined in the SELinux policy. It uses a special mapping algorithm to make sure that it matches the expression that is most likely applicable to the file, checks its should-be context against the existing context and, if it doesn't match, changes the context of the file. You can also use `matchpathcon` to display all matching expressions ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Controlling_file_contexts_yourself#Applying_contexts_on_files)).

Not all contexts will be reset by default through `restorecon`. Certain types, called customizable types, are types that are meant to be set anywhere on the system so that a fixed location is difficult to define. `restorecon` will not reset the context of a file whose context contains a customizable type, unless you add in the `-F` option. You also need to specify the `-F` option if you want to reset all the context instead of just the type (third field) of the security context.

Another method is to use `chcon`. This tool, which stands for change context, allows you to change the SELinux context of a file directly, without consulting the SELinux context definitions from the policy. This has the downside that the next `restorecon` will reset the context back to what is defined in the SELinux context definitions. The `chcon` command is only recommended to test out context changes before really registering them against the context definitions, or when you are dealing with the before mentioned customizable types (we'll get to that in a later tutorial) ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Controlling_file_contexts_yourself#Other_methods_for_applying_contexts)). 

### Adding your own definition rules

Let's say that you configured the audit daemon to log on /srv/logs/audit instead of /var/log/audit. By default, SELinux will probably assume that this directory should have the var_t context ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Controlling_file_contexts_yourself#Adding_your_own_definition_rules)).

```bash
➤ matchpathcon /srv/logs/audit
/srv/logs/audit system_u:object_r:var_t:s0
```

This will cause problems, since the auditd_t domain has little rights to do anything with var_t. We can query the currently loaded SELinux policy using sesearch (we have done that a few times in the previous tutorials as well).

```bash
➤ sesearch -s auditd_t -t var_t -SA
Found 9 semantic av rules:
   allow auditd_t file_type : filesystem getattr ;
   allow domain var_t : file { read getattr } ;
   allow daemon var_t : dir { getattr search open } ;
   allow domain var_t : dir { getattr search open } ;
   allow domain var_t : sock_file { read write getattr } ;
   allow auditd_t var_t : dir { getattr search open } ;
```

So what we need to do is to mark /srv/logs as var_log_t and /srv/logs/audit and subdirectories/files as auditd_log_t. This can be accomplished using semanage followed by a restorecon.

```bash
➤ semanage fcontext -a -t var_log_t "/srv/logs(/.*)?"
➤ semanage fcontext -a -t auditd_log_t "/srv/logs/audit(/.*)?"
➤ restorecon -Rv /srv/logs
restorecon reset /srv/logs context unconfined_u:object_r:var_t->unconfined_u:object_r:var_log_t
restorecon reset /srv/logs/audit context unconfined_u:object_r:var_t->unconfined_u:object_r:auditd_log_t
```

What we did was tell the SELinux management utilities to add (-a) a file context definition (fcontext) with type var_log_t (-t var_log_t) and auditd_log_t, for the given expressions at the end. Then, we used restorecon to update the contexts of the files according to the newly created definitions. Note that SELinux' management tools will accept and quierly convert types such as 'var_log_t' into a full security context such as unconfined_u:object_r:var_log_t.

The semanage utility is the main utility you will use to modify and alter SELinux settings on your system. So it comes to no surprise that deleting context definitions you set earlier on is done through this utility as well. All we need to do is use -d (to delete) instead of -a.

```bash
➤ semanage fcontext -d -t var_log_t "/srv/logs(/.*)?"
```

## Process context (domain) transition

What an SELinux policy writer can do in these cases is to define a domain transition, like so ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/How_does_a_process_get_into_a_certain_context#Transitioning)):

```
type_transition init_t initrc_exec_t : process initrc_t;
```

Which reads:

```
When an init_t process executes a file with context initrc_exec_t, then the resulting process should run in the initrc_t context.
```

Or, illustrated as an ASCII-art flowchart:

```
[init_t] --(execute initrc_exec_t)--> [initrc_t]
```

### Real-life example: startup of SSH

Let's look at a real-life example: the start-up of the SSH daemon ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/How_does_a_process_get_into_a_certain_context#Real-life_example:_startup_of_SSH)).

Basically, what happens when the SSH daemon is started through its service, is

1. the Linux kernel executes /sbin/init, resulting in the init process
2. the init process executes /etc/init.d/sshd, resulting in this init service script running for a (short) while
3. this sshd init service script executes /usr/sbin/sshd, resulting in the sshd daemon

For SELinux, with the common policy loaded, this could be illustrated as:

```
[kernel_t] --(execute init_exec_t)--> [init_t]
[init_t] --(execute initrc_exec_t)--> [initrc_t]
[initrc_t] --(execute sshd_exec_t)--> [sshd_t]
```

What we are defining here are domain transitions from one domain to another, through the execution of a file. 

### When is a transition allowed

Now, such a transition can only occur when the following three requirements are satisfied ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/How_does_a_process_get_into_a_certain_context#When_is_a_transition_allowed)).

1. The origin domain has execute permission on the file
2. The file context itself is identified as an entry point for the target domain
3. The origin domain is allowed to transition to the target domain

If, and only if, all three requirements are satisfied, will such a domain transition be allowed to occur. Let's look at these three rules in more detail. 

#### Execute permission on the file

So in case of the init script (initrc_t) calling the SSHd binary (sshd_exec_t) ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/How_does_a_process_get_into_a_certain_context#Execute_permission_on_the_file)):

```
➤ sesearch -s initrc_t -t sshd_exec_t -c file -p execute -Ad
Found 1 semantic av rules:
   allow initrc_t sshd_exec_t : file { read getattr execute open } ;
```

Great, so the init service script is allowed to execute the SSHd binary.

#### Entrypoint permission for a domain on the file

So we need to tell it that sshd_exec_t and sshd_t are related, by saying that the sshd_exec_t file is an entrypoint for the sshd_t domain.

```
➤ sesearch -s sshd_t -t sshd_exec_t -c file -p entrypoint -Ad
Found 1 semantic av rules:
   allow sshd_t sshd_exec_t : file { ioctl read getattr lock execute execute_no_trans entrypoint open } ;
```

What we can do is ask sesearch for what domains the ssh_exec_t type is an entrypoint for.

```
➤ sesearch -t ssh_exec_t -c file -p entrypoint -Ad
Found 5 semantic av rules:
   allow xm_ssh_t ssh_exec_t : file { ioctl read getattr lock execute entrypoint open } ;
   allow ssh_t ssh_exec_t : file { ioctl read getattr lock execute execute_no_trans entrypoint open } ;
   allow sge_job_ssh_t ssh_exec_t : file { ioctl read getattr lock execute entrypoint open } ;
   allow condor_startd_ssh_t ssh_exec_t : file { ioctl read getattr lock execute entrypoint open } ;
   allow nx_server_ssh_t ssh_exec_t : file { ioctl read getattr lock execute entrypoint open } ;
```

#### Process domain transition permission

The third requirement is that there must be an SELinux policy saying that that a transition from the source domain to the target domain is allowed. Let's look at the one from initrc_t to sshd_t:

```
➤ sesearch -s initrc_t -t sshd_t -c process -p transition -Ad
Found 1 semantic av rules:
   allow initrc_t sshd_t : process { transition siginh } ;
```

## Using SELinux booleans https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans

An SELinux boolean is a single string (hopefully sufficiently interpretable) that changes how SELinux reacts. With getsebool you can get a list of booleans and their current value ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans#Using_SELinux_booleans)).

```bash
➤ getsebool -a
abrt_anon_write --> off
abrt_handle_event --> off
allow_console_login --> on
allow_cvs_read_shadow --> off
...
```

With semanage boolean -l you can get the description of a boolean ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans#Getting_boolean_information)).

```bash
➤ semanage boolean -l | grep abrt_anon_write
abrt_anon_write                (off  ,  off)  Allow ABRT to modify public files
                                              used for public file transfer services.
```

The boolean status too is displayed in this output, but you can also get it from getsebool or even from reading the pseudo-file in the SELinux file system at /sys/fs/selinux/booleans.

### Checking boolean effect

By passing the boolean name itself (through --bool or -b) together with the ---show_cond (or -C) option, sesearch can show you what rules are influenced. For instance, to get the allow statements that are triggered with a change of the abrt_anon_write boolean ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans#What_does_a_boolean_change.3F)):

```bash
➤ sesearch -b abrt_anon_write -AC
Found 3 semantic av rules:
DT allow abrt_t public_content_rw_t : file { ioctl read write ... } ; [ abrt_anon_write ]
DT allow abrt_t public_content_rw_t : dir { ioctl read write ... } ; [ abrt_anon_write ]
DT allow abrt_t public_content_rw_t : lnk_file { ioctl read write ... } ; [ abrt_anon_write ]
```

The output of the command shows that, right now, the boolean is disabled (D at the beginning of the rules) and that the rule itself will become active if the boolean becomes true (T as second letter). If the boolean is enabled, it would be ET or, if a statement would become active if the boolean was false, the second letter would be F.

Because of booleans, we suggest that you always add in the -C operand to a sesearch command so that you can notice if something would be triggered through a boolean and, if so, what this boolean is. In many cases, toggling a boolean is sufficient for a system to continue working.

For instance, if you notice that the firefox browser is not able to read in user files, and you get a denial saying that mozilla_t is denied read access on user_home_t files, then the following sesearch command helps you by telling you there is a boolean called mozilla_read_content that allows the browser to read user files.

```bash
user $sesearch -s mozilla_t -t user_home_t -AC
Found 4 semantic av rules:
   allow application_domain_type user_home_t : file { getattr append } ;
DT allow mozilla_t user_home_t : file { ioctl read getattr lock open } ; [ mozilla_read_content ]
DT allow mozilla_t user_home_t : dir { ioctl read getattr lock search open } ; [ mozilla_read_content ]
DT allow mozilla_t user_home_t : lnk_file { read getattr } ; [ mozilla_read_content ]
```

### Changing boolean status

Changing SELinux booleans can be done through setsebool (where you add the desired state of the boolean, such as on or off) or togglesebool (which flips the current value of a boolean) ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans#Changing_boolean_status)).

```bash
➤ setsebool abrt_anon_write on
➤ togglesebool abrt_anon_write
```

### Persisting boolean changes

Of course, when you do want to persist the changes across reboots, you don't want to have to run the necessary commands over and over again. With the SELinux management utilities, you can persist such changes using the -P option ([source](https://wiki.gentoo.org/wiki/SELinux/Tutorials/Using_SELinux_booleans#Persisting_boolean_changes)).

```bash
➤ setsebool -P abrt_anon_write on
```

This command will take a while to complete, as the SELinux policy itself is rebuilt and stored, and the requested value for the boolean is registered as well. However, once completed, the boolean value remains active even across reboots. 

## Gentoo Linux install customisations

SELinux customizable types are types which are meant to persist through a standard relabel operation (whether through restorecon or through a complete system relabel operation). Because of this behavior, such contexts are most frequently used on files whose location is not fixed on the system. Because their location is not fixed, the policy writer cannot use a context mapping definition to manage the file context.

```bash
user $cat /etc/selinux/targeted/contexts/customizable_types

sandbox_file_t
svirt_image_t
virt_content_t
httpd_user_htaccess_t
httpd_user_script_exec_t
httpd_user_content_ra_t
httpd_user_content_rw_t
httpd_user_content_t
git_session_content_t
home_bin_t
user $ls -Z getinfo.sh
-rwxr-x---. swift users user_u:object_r:user_home_t:s0 getinfo.sh
user $chcon -t home_bin_t getinfo.sh
user $ls -Z getinfo.sh
-rwxr-x---. swift users user_u:object_r:home_bin_t:s0 getinfo.sh
user $restorecon -v getinfo.sh
user $ls -Z getinfo.sh
-rwxr-x---. swift users user_u:object_r:home_bin_t:s0 getinfo.sh
```

To see examples of relabel permission granted to users on your system's policy, examine the output of the following commands:

```bash
user $sesearch -s user_t -t user_home_t -c file -p relabelfrom -A
user $sesearch -s user_t -t home_bin_t -c file -p relabelto -A
```

When you need to override the customizable contexts, you can use the -F (which stands for force) option with restorecon. This not only resets the type back to the context mapping definition, but it also resets all the other fields of the context accordingly. The purpose of context fields other than the type will be explained in a later tutorial.

```bash
➤ restorecon -RF /home/swift
```

## Permissive vs enforcing

```bash
➤ getenforce
Enforcing
➤ sestatus
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             strict
Current mode:                   enforcing
Mode from config file:          enforcing
Policy MLS status:              disabled
Policy deny_unknown status:     denied
Max kernel policy version:      28
```

To switch from enforcing to permissive and back, you can use the setenforce command. This command supports Enforcing, Permissive, 1 or 0 as argument.

```bash
➤ setenforce 1
```

The default value (enforcing or permissive) when the system boots is defined in the /etc/selinux/config file, through the SELINUX parameter. Another method to define how to boot is using the enforcing= boot parameter. This parameter overrides the setting in the configuration file, so even with SELINUX=enforcing set, if you boot with enforcing=0 then the system will boot in SELinux permissive mode.

SELinux-aware applications are usually linked with the libselinux.so library, which can be checked with ldd.

```bash
user $ldd crond
libselinux.so.1
libpam.so.0
...
```

Luckily, SELinux has a neat feature where you can tell it one particular domain should be permissive whereas the rest runs in enforcing mode. All you need to do is tell semanage what domain you want to put in permissive mode.

```bash
➤ semanage permissive -a xbmc_t
```

You can get an overview of the current permissive domains as well, using semanage permissive -l.

If CONFIG_SELINUX_BOOTPARAM is enabled in the kernel, then you can boot with SELinux disabled using selinux=0 as boot parameter. If you want to boot with SELinux disabled without boot parameter, you can edit /etc/selinux/config and set the SELINUX parameter to disabled.

## Unconfined

You will probably have already noticed that domains or types that do not end in _t regularly appear in the output produced by the sesearch utility, When this is the case, the shown domain or type is actually a type attribute (the convention is that these attributes do not get a suffix). To query the type attributes currently in the policy, you may use the seinfo tool. For instance, to get an overview of all types that have the userdomain attribute set:

```bash
user $seinfo -auserdomain -x
   userdomain
      sysadm_t
      staff_t
      user_t
```

Vice versa, you can ask seinfo to show all attributes assigned to a particular type or domain. So for the user_t domain:

```bash
user $seinfo -tuser_t -x
   user_t
      privfd
      process_user_target
      xserver_unconfined_type
      xdrawable_type
      userdomain
      xcolormap_type
      dbusd_system_bus_client
      ubac_constrained_type
      unpriv_userdomain
      nsswitch_domain
      x_domain
      domain
```

Policy writers can mark a domain as unconfined by assigning it the unconfined_domain_type attribute. Although attribute is always defined in the policy, it only takes effect when unconfined domains are allowed. Then, any domain bearing this attribute will be granted the necessary privileges to become unconfined.

You can list all the domains which bear the unconfined_domain_type' attribute with seinfo:

```bash
user $seinfo -aunconfined_domain_type -x
  unconfined_domain_type
    kernel_t
    initrc_t
    ...
```

In this case, the output shows unconfined_t is not available on the system, which means unconfined domains are not allowed.

```bash
user $seinfo -tunconfined_t
ERROR: could not find datum for type unconfined_t
```

In this case, the unconfined_t domain is available, which means unconfined domains are allowed.

```bash
user $seinfo -tunconfined_t
  unconfined_t
```

## Policies

The list of SELinux modules that are currently loaded on a system can be obtained with semodule -l.

```bash
➤ semodule -l
alsa    1.11.4
apache  2.6.10
apm     1.11.4
application     1.2.0
...
```

SELinux uses a policy store to keep track of its loaded policy modules and related settings. The active policy store name can be obtained from sestatus (look for the Loaded policy name line):

```
➤ sestatus | grep Loaded
Loaded policy name:    strict
```

The policy store that should be active upon boot is configured in /etc/selinux/config through the SELINUXTYPE setting.

```bash
➤ grep ^SELINUXTYPE /etc/selinux/config
SELINUXTYPE=strict
```

On most systems, the policy files are stored in /usr/share/selinux/strict. If you take a look in this directory, you will find lots of files with the .pp suffix:

```
user $ls /usr/share/selinux/targeted
alsa.pp
apache.pp
apm.pp
application.pp
...
```

Effectively loading the policies in memory is done through the distribution support of SELinux. In Gentoo, this is done at install time of the various sec-policy packages, which calls semodule with the proper arguments.

```bash
➤ cd /usr/share/selinux/strict; semodule -i alsa.pp
```

Similarly, deinstalling the package removes the policy from memory (in this case, the module name is used, not the module file name).

```bash
➤ semodule -r alsa
```

Sometimes an update requires the entire policy (including base policy) to be loaded. SELinux supports full reloads - all you need to do is add in -b base.pp to tell the management utilities where the base policy module can be found. But again, most of the time this is done through the distribution.

```bash
➤ cd /usr/share/selinux; semodule -b base.pp -i alsa.pp -i apache.pp -i apm.pp -i application.pp -i ...
```

You can also opt to disable policy modules. This way, the part of the policy that is provided by the policy module is not active anymore.

```bash
➤ semodule -d alsa
➤ semodule -l
alsa    1.11.4  Disabled
apache  2.6.10
...
```

## Roles

With the seinfo tool, you can list what domains are allowed for a particular role.

```bash
user $seinfo -ruser_r -x
   user_r
      Dominated Roles:
         user_r
      Types:
         chromium_renderer_t
         user_gkeyringd_t
         ...
```

Users can switch roles if they want. However, they can only do so if their SELinux user is allowed to "be" in the other role. With semanage user -l you can see if that is the case.

```bash
➤ semanage user -l
SELinux User    SELinux Roles

root            staff_r sysadm_r
staff_u         staff_r sysadm_r
sysadm_u        sysadm_r
system_u        system_r
unconfined_u    unconfined_r
user_u          user_r
```

Switching roles is done using newrole -r <targetrole>. It is most commonly used to switch from the staff_r role to the sysadm_r role:

```bash
user $newrole -r sysadm_r
Password:
```

## User

Just like with the SELinux role (which defines what the possible domains are), it is the SELinux user that defines what the possible roles are.

The roles that are assigned to a particular SELinux user can be seen from semanage user -l.

```
➤ semanage user -l
SELinux User    SELinux Roles

root            staff_r sysadm_r
staff_u         staff_r sysadm_r
sysadm_u        sysadm_r
system_u        system_r
unconfined_u    unconfined_r
user_u          user_r
```

You can see the mapping of Linux accounts to SELinux users using semanage login -l.

```
➤ semanage login -l

Login Name                SELinux User             

__default__               user_u
root                      root
swift                     staff_u
system_u                  system_u
```

First of all, to manage login mappings, we use the semanage login set of commands. For instance, to create the operators group mapping:

```
➤ semanage login -a -s staff_u %operators
```

Removing mappings is done with the -d instead of -a option. You can also modify a mapping using -m.

However, if you change a mapping for a user that already owns files on the file system, it is very important to reset the context of these files completely (i.e. using -F with restorecon) or set the new SELinux owner and role using chcon.

```
➤ chcon -R -u staff_u -r staff_r /home/oper
```

If not, then the files are owned by the 'wrong' SELinux user which might cause permission troubles later on. 

Similar as with the login mappings, we now use semanage user to modify the user/role mappings. For instance, to create a new SELinux user called infra_u and grant it the staff_r and sysadm_r roles:

```
➤ semanage user -a -R "staff_r sysadm_r" infra_u
```

## Services

To force the change in user/role, you need to call the run_init command for this (if you are allowed this command), like so:

```
➤ run_init /etc/init.d/nscd status
Authenticating root.
Password:
 * nscd: started
```

## Putting constraints on operations

Unlike type enforcement, which uses one particular field in a security context (third field, the type), constraints use the entire context as their rules and are more targeting operations rather than domains. Let's immediately look at an example:

```
constrain dir_file_class_set { create relabelto relabelfrom }
(
        u1 == u2
        or t1 == can_change_object_identity
);
```

What we see above is a constraint that says that a domain can only create or relabel (to or from) directories and files if either the SELinux user part of the two contexts' match (u1 == u2) or if the domain has the can_change_object_identity attribute assigned to it. The latter attribute can be checked, as we have seen, with seinfo:

```
user $seinfo -acan_change_object_identity -x
```

If these constraints are not met, then the operation will be denied, even if you would explicitly allow it (through another type enforcement rule). 

We have made a small overview of the constraints enabled to make this a bit easier. You can ask your system to list the constraints using seinfo, but this immediately gives fully expanded output and uses a more arithmetical expression syntax than the one shown before. For instance, the above constrain:

```
user $seinfo --constrain
constrain { file } { create relabelfrom relabelto  } 
(  u1 u2 ==  t1 { logrotate_t policykit_auth_t sysadm_t lvm_t rpm_t xdm_t krb5kdc_t newrole_t portage_t 
local_login_t rpm_script_t sysadm_passwd_t policykit_t portage_sandbox_t groupadd_t kpropd_t passwd_t 
updpwd_t chfn_t cupsd_t gssd_t httpd_t slapd_t sshd_t udev_t virtd_t puppetmaster_t restorecond_t 
setfiles_t kadmind_t sulogin_t useradd_t } ==  || );
```

## MLS and MCS

uninteresting? mcs, perhaps not (categories per vm guest)

## Network ports

The unreserved_port_t type is a domain assigned to ports that are not reserved for particular services in the SELinux policy. And that implies that ports that are assigned for a particular service are named differently.

Within SELinux, ports are labeled, just like other resources. The semanage port command displays the rules for port assignment.

```
➤ semanage port -l
SELinux Port Type              Proto    Port Number

afs3_callback_port_t           tcp      7001
afs3_callback_port_t           udp      7001
afs_bos_port_t                 udp      7007
...
ssh_port_t                     tcp      22
...
unreserved_port_t              tcp      1024-65535
unreserved_port_t              udp      1024-65535
```

The third column gives the port number, or port number range. If it is a range, it has a lower priority than a specific port number (so in case of port 7001, the port type will be afs3_callback_port_t and not unreserved_port_t). Also, if none of the rules match, then the port falls back to port_t.

When we update daemons to run on different ports, there are two things we can do in order for SELinux to allow this.
1. Either we allow the domain additional access rules (on other port labels), or
2. we assign the label to the new port.

The first choice requires a policy update (which we will discuss as part of the second series of tutorials) and is most of the time not what you need. After all, allowing the domain rights on other ports is actually increasing the rights of the domain, whereas we don't want to increase the rights - only change the port.

The second choice is often the preferred - and most simple. With semanage, we can map a port label on a different port. Let's assign ssh_port_t to port 1122.

```
➤ semanage port -a -t ssh_port_t -p tcp 1122
```
