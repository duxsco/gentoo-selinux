# SELinux rules for my custom Gentoo Linux installation (WIP)

Here, SELinux related changes applied to my [custom Gentoo Linux installation](https://github.com/duxsco/gentoo-installation) are documented. This documentation expects for [SELinux already being enabled](https://github.com/duxsco/gentoo-installation#enable-selinux). At this point, the system is in "permissive" mode.

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

## Fixes for early bootup

The policies in the "policy" folder "fix" denials that occur before the `auditd` service starts. As `ausearch` cannot be used in this case, `dmesg` logs need to be checked and suitable policies based on the scarce information created. **I don't like this approach. Suggestions to fix the root cause are welcome.**

I created a script to simplify policy creation for denials printed out by `dmesg`. Reboot after `semodule -i ...` and create the next SELinux policy. The script creates the `.te` file in the current directory!

```bash
➤ bash ../dmesg.sh
"mydmesg_00000-init_t-tmpfs_t.te" has been created!

Please, check the file, create the policy module and install it:
make -f /usr/share/selinux/strict/include/Makefile mydmesg_00000-init_t-tmpfs_t.pp
semodule -i mydmesg_00000-init_t-tmpfs_t.pp
```

In certain cases, a warning is printed and no `.te` file is created:

```bash
➤ bash ../dmesg.sh
audit2allow printed a warning:


#============= systemd_tmpfiles_t ==============

#!!!! This avc can be allowed using the boolean 'systemd_tmpfiles_manage_all'
allow systemd_tmpfiles_t portage_cache_t:dir { getattr open read relabelfrom relabelto };

Aborting...
```

To solve above issue:

```bash
setsebool -P systemd_tmpfiles_manage_all on
```

... and reboot thereafter to execute `dmesg.sh` after bootup.

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
