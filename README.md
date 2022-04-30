# SELinux rules for my custom Gentoo Linux installation (WIP)

Here, SELinux related changes applied to my [custom Gentoo Linux installation](https://github.com/duxsco/gentoo-installation) are documented. This documentation expects for [SELinux already being enabled](https://github.com/duxsco/gentoo-installation#enable-selinux). At this point, the system is in "permissive" mode.

## SSH port label assignment

In the [custom Gentoo Linux installation](https://github.com/duxsco/gentoo-installation), the SSH port has been changed to 50022. This needs to be considered for no SELinux denials to occur:

```bash
➤ semanage port -l | grep -e ssh -e Port
SELinux Port Type              Proto    Port Number
ssh_port_t                     tcp      22
➤ semanage port -a -t ssh_port_t -p tcp 50022
➤ semanage port -l | grep -e ssh -e Port
SELinux Port Type              Proto    Port Number
ssh_port_t                     tcp      50022, 22
```

## OpenRC patch

The OpenRC patch was suggested as a possible solution by [perfinion](https://github.com/perfinion) to fix bootup. Thx for that 🙂 Save the patch:

```bash
➤ tree /etc/portage/patches
/etc/portage/patches
└── sys-apps
    └── openrc
        └── init-early.sh.patch

2 directories, 1 files
```

... and run `emerge -1 sys-apps/openrc`. Such a line should be printed:

```
 * ===========================================================
 * Applying user patches from /etc/portage/patches ...
 * Applying init-early.sh.patch ...                    [ ok ]
 * User patches applied.
 * ===========================================================
```

## Creating SELinux policies

I created a script to simplify policy creation for denials printed out by `dmesg` and `ausearch`. Reboot after `semodule -i ...` and create the next SELinux policy. The script creates the `.te` file in the current directory!

```bash
➤ bash ../create_policy.sh
"my_00001_permissive_dmesg-systemd_tmpfiles_t-self.te" has been created!

Please, check the file, create the policy module and install it:
make -f /usr/share/selinux/strict/include/Makefile my_00001_permissive_dmesg-systemd_tmpfiles_t-self.pp
semodule -i my_00001_permissive_dmesg-systemd_tmpfiles_t-self.pp
```

In certain cases, a warning is printed and no `.te` file is created:

```bash
➤ bash ../create_policy.sh
audit2allow printed a warning:


#============= systemd_tmpfiles_t ==============

#!!!! This avc can be allowed using the boolean 'systemd_tmpfiles_manage_all'
allow systemd_tmpfiles_t portage_cache_t:dir { getattr open read relabelfrom relabelto };

Aborting...
```

The policies created with `create_policy.sh` are in the "policy" folder. In addition to building and installing them, enable following booleans:

```bash
setsebool -P allow_mount_anyfile on
setsebool -P systemd_tmpfiles_manage_all on
```

## Non-policy based fixes

Executing `create_policy.sh` resulted in following `ausearch` outputs with non-policy based fixes shows in the following.

### 1. Cronie

`ausearch` output:

```
----
time->Fri Apr 29 23:25:34 2022
type=PROCTITLE msg=audit(1651267534.933:7): proctitle="/usr/sbin/crond"
type=PATH msg=audit(1651267534.933:7): item=0 name="/var/spool/cron/crontabs/root" inode=641849 dev=00:1c mode=0100600 ouid=0 ogid=460 rdev=00:00 obj=system_u:object_r:unlabeled_t nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1651267534.933:7): cwd="/"
type=SYSCALL msg=audit(1651267534.933:7): arch=c000003e syscall=262 success=yes exit=0 a0=ffffff9c a1=7ffdefcdd160 a2=7ffdefcdd0d0 a3=0 items=1 ppid=1 pid=5437 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="crond" exe="/usr/sbin/crond" subj=system_u:system_r:crond_t key=(null)
type=AVC msg=audit(1651267534.933:7): avc:  denied  { getattr } for  pid=5437 comm="crond" path="/var/spool/cron/crontabs/root" dev="dm-0" ino=641849 scontext=system_u:system_r:crond_t tcontext=system_u:object_r:unlabeled_t tclass=file permissive=1
----
time->Fri Apr 29 23:25:34 2022
type=PROCTITLE msg=audit(1651267534.933:8): proctitle="/usr/sbin/crond"
type=PATH msg=audit(1651267534.933:8): item=0 name="/var/spool/cron/crontabs/root" inode=641849 dev=00:1c mode=0100600 ouid=0 ogid=460 rdev=00:00 obj=system_u:object_r:unlabeled_t nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1651267534.933:8): cwd="/"
type=SYSCALL msg=audit(1651267534.933:8): arch=c000003e syscall=257 success=yes exit=7 a0=ffffff9c a1=7ffdefcdd5d0 a2=800 a3=0 items=1 ppid=1 pid=5437 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="crond" exe="/usr/sbin/crond" subj=system_u:system_r:crond_t key=(null)
type=AVC msg=audit(1651267534.933:8): avc:  denied  { open } for  pid=5437 comm="crond" path="/var/spool/cron/crontabs/root" dev="dm-0" ino=641849 scontext=system_u:system_r:crond_t tcontext=system_u:object_r:unlabeled_t tclass=file permissive=1
type=AVC msg=audit(1651267534.933:8): avc:  denied  { read } for  pid=5437 comm="crond" name="root" dev="dm-0" ino=641849 scontext=system_u:system_r:crond_t tcontext=system_u:object_r:unlabeled_t tclass=file permissive=1
```

Policies:

```bash
➤ sesearch --allow --source crond_t --class file --perm getattr,open,read | grep "_cron_spool_t"
allow crond_t system_cron_spool_t:file { append create getattr ioctl link lock open read rename setattr unlink write }; [ fcron_crond ]:True
allow crond_t system_cron_spool_t:file { getattr ioctl lock open read watch };
allow crond_t user_cron_spool_t:file { append create getattr ioctl link lock open read rename setattr unlink write }; [ fcron_crond ]:True
allow crond_t user_cron_spool_t:file { getattr ioctl lock open read };
```

List file context mapping definitions:

```bash
➤ semanage fcontext -l | grep "/var/spool/cron/crontabs"
/var/spool/cron/crontabs                           directory          system_u:object_r:cron_spool_t
/var/spool/cron/crontabs/.*                        regular file       <<None>>
/var/spool/cron/crontabs/munin                     regular file       system_u:object_r:system_cron_spool_t
```

Modify:

```bash
➤ semanage fcontext -m -f f -t user_cron_spool_t "/var/spool/cron/crontabs/.*"
```

Restore:

```bash
➤ restorecon -F -v /var/spool/cron/crontabs/*
Relabeled /var/spool/cron/crontabs/root from system_u:object_r:unlabeled_t to system_u:object_r:user_cron_spool_t
```

### 2. nftables

`ausearch` output:

```
----
time->Sat Apr 30 02:04:05 2022
type=PROCTITLE msg=audit(1651277045.116:7): proctitle=6E6674002D63002D66002F7661722F6C69622F6E667461626C65732F72756C65732D73617665
type=PATH msg=audit(1651277045.116:7): item=0 name="/var/lib/nftables/rules-save" inode=647577 dev=00:1c mode=0100600 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:var_lib_t nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1651277045.116:7): cwd="/"
type=SYSCALL msg=audit(1651277045.116:7): arch=c000003e syscall=257 success=yes exit=4 a0=ffffff9c a1=7ffc809cbb06 a2=0 a3=0 items=1 ppid=5466 pid=5467 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="nft" exe="/sbin/nft" subj=system_u:system_r:iptables_t key=(null)
type=AVC msg=audit(1651277045.116:7): avc:  denied  { open } for  pid=5467 comm="nft" path="/var/lib/nftables/rules-save" dev="dm-0" ino=647577 scontext=system_u:system_r:iptables_t tcontext=system_u:object_r:var_lib_t tclass=file permissive=1
type=AVC msg=audit(1651277045.116:7): avc:  denied  { read } for  pid=5467 comm="nft" name="rules-save" dev="dm-0" ino=647577 scontext=system_u:system_r:iptables_t tcontext=system_u:object_r:var_lib_t tclass=file permissive=1
----
time->Sat Apr 30 02:04:05 2022
type=PROCTITLE msg=audit(1651277045.116:8): proctitle=6E6674002D63002D66002F7661722F6C69622F6E667461626C65732F72756C65732D73617665
type=SYSCALL msg=audit(1651277045.116:8): arch=c000003e syscall=16 success=no exit=-25 a0=4 a1=5401 a2=7ffc809ca2d0 a3=20000000 items=0 ppid=5466 pid=5467 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="nft" exe="/sbin/nft" subj=system_u:system_r:iptables_t key=(null)
type=AVC msg=audit(1651277045.116:8): avc:  denied  { ioctl } for  pid=5467 comm="nft" path="/var/lib/nftables/rules-save" dev="dm-0" ino=647577 ioctlcmd=0x5401 scontext=system_u:system_r:iptables_t tcontext=system_u:object_r:var_lib_t tclass=file permissive=1
----
time->Sat Apr 30 02:04:05 2022
type=PROCTITLE msg=audit(1651277045.116:9): proctitle=6E6674002D63002D66002F7661722F6C69622F6E667461626C65732F72756C65732D73617665
type=PATH msg=audit(1651277045.116:9): item=0 name="" inode=647577 dev=00:1c mode=0100600 ouid=0 ogid=0 rdev=00:00 obj=system_u:object_r:var_lib_t nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=CWD msg=audit(1651277045.116:9): cwd="/"
type=SYSCALL msg=audit(1651277045.116:9): arch=c000003e syscall=262 success=yes exit=0 a0=4 a1=7fb36d26ff15 a2=7ffc809b39c0 a3=1000 items=1 ppid=5466 pid=5467 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="nft" exe="/sbin/nft" subj=system_u:system_r:iptables_t key=(null)
type=AVC msg=audit(1651277045.116:9): avc:  denied  { getattr } for  pid=5467 comm="nft" path="/var/lib/nftables/rules-save" dev="dm-0" ino=647577 scontext=system_u:system_r:iptables_t tcontext=system_u:object_r:var_lib_t tclass=file permissive=1
```

List file context mapping definitions:

```bash
➤ semanage fcontext -l | grep "/var/lib/.*tables"
/var/lib/ip6?tables(/.*)?                          all files          system_u:object_r:initrc_tmp_t
```

Policies:

```bash
➤ sesearch --allow --source iptables_t --target initrc_tmp_t --class file --perm getattr,ioctl,open,read
allow iptables_t initrc_tmp_t:file { append getattr ioctl lock open read write };
```

Modify:

```bash
semanage fcontext -a -t initrc_tmp_t "/var/lib/nftables(/.*)?"
```

Restore:

```bash
➤ restorecon -R -F -v /var/lib/nftables
Relabeled /var/lib/nftables from system_u:object_r:var_lib_t to system_u:object_r:initrc_tmp_t
Relabeled /var/lib/nftables/.keep_net-firewall_nftables-0 from system_u:object_r:var_lib_t to system_u:object_r:initrc_tmp_t
Relabeled /var/lib/nftables/rules-save from system_u:object_r:var_lib_t to system_u:object_r:initrc_tmp_t
```
