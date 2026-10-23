# ira module

The flashable half of ira: the daemon and its boot scripts. There is no kernel module.

```
customize.sh        installer: permissions, per-role endpoint names, and device-domain policy
post-fs-data.sh     starts ira-daemon early, before the UDC is bound
service.sh          supervisor; replaces only a daemon that requested a descriptor transition
initrc/ira.rc       creates functions/ffs.ira and links it into configs/b.1 at post-fs-data
ira-daemon          the userspace half (FunctionFS + AOSP adbd)
mksh                the shell a session runs
errno_profile.sh    the acceptance probe: path and errno profile, before and after
```

A bootstrap thread mounts functionfs on `/config/usb_gadget/g1/functions/ffs.ira` in a private
namespace and pins it by directory fd; the daemon and service backends retain the inherited
namespace. It writes the adb descriptors (or the idle ff/00/00 set when the platform's
`functions/ffs.adb` is linked into the same configuration), and serves ADB on the two bulk
endpoints. The link exists before the framework binds the UDC because configfs refuses a link
once the UDC name is set (drivers/usb/gadget/configfs.c, config_usb_cfg_link).

Normal startup takes no user options. Internal service backends use `--ira-services root|shell`;
all service opens use their process-wide platform/minijail identity. Filesystem and SELinux policy
come from the device libraries, and authorization uses the unchanged upstream libadbd_auth core
over a private channel, never the system auth listener. Full revocation resets USB, preserving
the role/controller across an explicitly requested process replacement. TCP forwarding requires an explicit request;
no TCP ADB or wireless discovery is started. Logs are in `state/sync.log`.

`NOTICE`, `LICENSE` and `Apache-2.0.txt` carry project and upstream licensing information.
