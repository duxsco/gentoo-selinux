## nftables

https://bugs.gentoo.org/840230

## cron

```bash
➤ semanage fcontext -l -C

➤ ausearch -m avc --start boot
----
time->Sat Apr 23 02:58:53 2022
type=PROCTITLE msg=audit(1650675533.683:26): proctitle=63726F6E746162002D6C
type=PATH msg=audit(1650675533.683:26): item=0 name="/proc/sys/kernel/cap_last_cap" nametype=UNKNOWN cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1650675533.683:26): cwd="/home/david"
type=SYSCALL msg=audit(1650675533.683:26): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7f995c5cf02a a2=0 a3=0 items=1 ppid=4133 pid=4179 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=460 sgid=460 fsgid=460 tty=pts0 ses=1 comm="crontab" exe="/usr/bin/crontab" subj=staff_u:sysadm_r:admin_crontab_t key=(null)
type=AVC msg=audit(1650675533.683:26): avc:  denied  { search } for  pid=4179 comm="crontab" name="kernel" dev="proc" ino=12534 scontext=staff_u:sysadm_r:admin_crontab_t tcontext=system_u:object_r:sysctl_kernel_t tclass=dir permissive=0
----
time->Sat Apr 23 02:58:53 2022
type=PROCTITLE msg=audit(1650675533.683:27): proctitle=63726F6E746162002D6C
type=PATH msg=audit(1650675533.683:27): item=0 name="/var/spool/cron/crontabs/root" inode=638642 dev=00:1c mode=0100600 ouid=0 ogid=460 rdev=00:00 obj=system_u:object_r:cron_spool_t nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1650675533.683:27): cwd="/home/david"
type=SYSCALL msg=audit(1650675533.683:27): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7fff5bb07d00 a2=0 a3=0 items=1 ppid=4133 pid=4179 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=460 sgid=460 fsgid=460 tty=pts0 ses=1 comm="crontab" exe="/usr/bin/crontab" subj=staff_u:sysadm_r:admin_crontab_t key=(null)
type=AVC msg=audit(1650675533.683:27): avc:  denied  { read } for  pid=4179 comm="crontab" name="root" dev="dm-0" ino=638642 scontext=staff_u:sysadm_r:admin_crontab_t tcontext=system_u:object_r:cron_spool_t tclass=file permissive=0

➤ ls -laZ /var/spool/cron/crontabs
total 4
drwx-wx--T. 1 root crontab system_u:object_r:cron_spool_t  60 23. Apr 02:43 ./
drwxr-xr-x. 1 cron cron    system_u:object_r:cron_spool_t 130 16. Apr 13:31 ../
-rw-r--r--. 1 root root    system_u:object_r:cron_spool_t   0 16. Apr 13:31 .keep_sys-process_cronie-0
-rw-------. 1 root crontab system_u:object_r:cron_spool_t 118 16. Apr 13:31 root

➤ semanage fcontext -l | grep "/var/spool/cron/crontabs"
/var/spool/cron/crontabs        directory     system_u:object_r:cron_spool_t
/var/spool/cron/crontabs/.*     regular file  <<None>>
/var/spool/cron/crontabs/munin  regular file  system_u:object_r:system_cron_spool_t

➤ semanage fcontext -m -f f -t user_cron_spool_t "/var/spool/cron/crontabs/.*"
libsemanage.dbase_llist_query: could not query record value (No such file or directory).

➤ restorecon -R -F -v /var/spool/cron/crontabs
Relabeled /var/spool/cron/crontabs/.keep_sys-process_cronie-0 from system_u:object_r:cron_spool_t to system_u:object_r:system_cron_spool_t
Relabeled /var/spool/cron/crontabs/root from system_u:object_r:cron_spool_t to system_u:object_r:system_cron_spool_t
```
