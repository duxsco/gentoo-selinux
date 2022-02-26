# Quick and dirty cheat sheet on tutorial writedown

Logs:

```bash
➤ ausearch -m avc --start boot
```

Manual install:

```bash
➤ cd /usr/share/selinux/strict; semodule -i alsa.pp
➤ cd /usr/share/selinux; semodule -b base.pp -i alsa.pp -i apache.pp -i apm.pp -i application.pp -i ...
```

Reset:

```bash
➤ restorecon -RF /home/swift
➤ restorecon -Rv /srv/logs
```

Stats:

```bash
➤ getenforce # setenforce 1
➤ getsebool -a # get booleans
➤ seinfo
➤ sestatus
```

Properties:

```bash
➤ matchpathcon /srv/logs/audit # default properties
➤ ps -eZ | grep auditd
```

Prozess start:

```bash
➤ run_init /etc/init.d/nscd status
```

List:

```bash
➤ semanage boolean -l
➤ semanage fcontext -l
➤ semanage login -l
➤ semanage port -l
➤ semanage user -l
```

Apply:

```bash
➤ semanage fcontext -a -t auditd_log_t "/srv/logs/audit(/.*)?"
➤ semanage fcontext -a -t var_log_t "/srv/logs(/.*)?"
➤ semanage login -a -s staff_u %operators
➤ semanage permissive -a xbmc_t
➤ semanage port -a -t ssh_port_t -p tcp 1122
➤ semanage user -a -R "staff_r sysadm_r" infra_u
➤ chcon -R -u staff_u -r staff_r /home/oper
```

Delete:

```bash
➤ semanage fcontext -d -t var_log_t "/srv/logs(/.*)?"
```

Modules:

```bash
➤ semodule -DB # verbose logging
➤ semodule --build
➤ semodule --disable_dontaudit --build
➤ semodule -d alsa
➤ semodule -l
➤ semodule -r alsa
```

Search:

```bash
➤ sesearch --allow --source auditd_t --target auditd_log_t --class file --perm write
➤ sesearch --dontaudit
➤ sesearch -b abrt_anon_write -AC
➤ sesearch -s auditd_t -t var_t -SA
➤ sesearch -s initrc_t -t sshd_exec_t -c file -p execute -Ad
➤ sesearch -s initrc_t -t sshd_t -c process -p transition -Ad
➤ sesearch -s sshd_t -t sshd_exec_t -c file -p entrypoint -Ad
➤ sesearch -t ssh_exec_t -c file -p entrypoint -Ad
```

Set boolean:

```bash
➤ setsebool -P abrt_anon_write on
➤ setsebool abrt_anon_write on
➤ togglesebool abrt_anon_write
```
