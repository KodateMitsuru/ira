#!/system/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
SKIPUNZIP=0

ui_print "- ira"

# No kernel module: the USB function is a FunctionFS instance (functions/ffs.ira) that the
# daemon mounts and describes itself. initrc/ira.rc creates the instance and its configfs link
# at post-fs-data; there is nothing for this installer to select or copy.

set_perm_recursive "$MODPATH" 0 0 0755 0644
for f in "$MODPATH"/*.sh; do chmod 0755 "$f"; done
[ -f "$MODPATH/ira-daemon" ] && chmod 0755 "$MODPATH/ira-daemon"
[ -f "$MODPATH/mksh" ] && chmod 0755 "$MODPATH/mksh"
# The session shell is executed by the daemon before a session assumes its user, and the label it
# carries has to be one a shell-ish domain may execute: a file inside the module keeps the module's
# own context, which is not executable from a session. Only the label changes here - the directory
# stays as private as it was.
[ -f "$MODPATH/mksh" ] && chcon u:object_r:shell_exec:s0 "$MODPATH/mksh" 2>/dev/null


# Which process ZygiskNext injects the hook into.  It must be the init service that owns the
# gadget, and its name is vendor business: AOSP ships "vendor.usb_gadget_default" running
# /vendor/bin/hw/android.hardware.usb.gadget-service.example, this phone runs
# "vendor.usbgadget-hal" running android.hardware.usb.gadget-service.qti.  So the list is not
# written by hand and not matched by name: every init rc on the device is read, and every service
# whose binary or service name says "usb gadget" gets its *path* - the one thing that cannot be
# ambiguous - written out for ZygiskNext.
zn="$MODPATH/zn_modules.txt"
{
	echo "# generated at install time from the device's own init rc files"
	found=0
	for dir in /vendor/etc/init /odm/etc/init /system/etc/init /system_ext/etc/init; do
		[ -d "$dir" ] || continue
		for rc in "$dir"/*.rc; do
			[ -f "$rc" ] || continue
			awk -v rc="$rc" '
				$1 == "service" && NF >= 3 {
					name = $2; path = $3
					if (name ~ /usb[._-]?gadget/ || path ~ /usb[._-]?gadget/) {
						printf "path=%s lib/ira-zn.so\n", path
					}
				}' "$rc"
		done
	done | sort -u | while read -r line; do
		echo "$line"
		found=$((found + 1))
	done
} > "$zn"

# A device that hides its rc files from the installer still gets the names AOSP and the big
# vendors use, as a last resort.
if ! grep -q '^path=' "$zn" 2>/dev/null; then
	cat >> "$zn" <<'EOF'
name=android.hardware.usb.gadget-service lib/ira-zn.so
name=android.hardware.usb.gadget-service.qti lib/ira-zn.so
name=android.hardware.usb.gadget-service.mediatek lib/ira-zn.so
name=android.hardware.usb.gadget-service.exynos lib/ira-zn.so
EOF
fi
chmod 0644 "$zn" 2>/dev/null
ui_print "- gadget hook target: $(grep -c '^path=\|^name=' "$zn") entr(y|ies)"


# The SELinux rule the hook needs, also derived from this device and not written by hand: the
# domain of the running gadget service.  PLT hooking only rewrites the caller's GOT - no memory is
# Our inline hook on ioctl() needs executable memory (the binder read is an internal call, not a
# PLT entry, so it has to be patched in place); the rest is the permission to reach the
# daemon's control socket, which lives in the root manager's domain.
gadget_paths=$(grep '^path=' "$MODPATH/zn_modules.txt" 2>/dev/null | sed 's/^path=//; s/ lib\/ira-zn\.so$//')
gadget_domain=""
for gp in $gadget_paths; do
	for p in /proc/[0-9]*; do
		cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
		case "$cmd" in
		"$gp"*)
			cur=$(cat "$p/attr/current" 2>/dev/null)
			case "$cur" in
			u:r:*)
				gadget_domain=${cur#u:r:}
				gadget_domain=${gadget_domain%%:*}
				;;
			esac
			[ -n "$gadget_domain" ] && break
			;;
		esac
	done
	[ -n "$gadget_domain" ] && break
done

# A device whose init rc could not be read still has the service running. This matches what the
# process is (a usb gadget service), not what a particular ROM calls its domain.
if [ -z "$gadget_domain" ]; then
	for p in /proc/[0-9]*; do
		cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
		case "$cmd" in
		*usb*gadget*)
			cur=$(cat "$p/attr/current" 2>/dev/null)
			case "$cur" in
			u:r:*)
				gadget_domain=${cur#u:r:}
				gadget_domain=${gadget_domain%%:*}
				;;
			esac
			[ -n "$gadget_domain" ] && break
			;;
		esac
	done
fi

# And the domain the daemon will run in: the installer and the daemon are both started by the
# root manager, so this process's own context is that domain - ksu on KernelSU, magisk on Magisk,
# whatever it is here.  Nothing about the manager is assumed.
root_domain=$(cat /proc/self/attr/current 2>/dev/null)
root_domain=${root_domain#u:r:}
root_domain=${root_domain%%:*}
if [ -z "$root_domain" ]; then
	abort "! cannot read this installer's SELinux domain; refusing to guess one"
fi
if [ -z "$gadget_domain" ]; then
	abort "! the USB gadget HAL is not running or has no SELinux domain; ira cannot work on this device"
fi

# Only rules whose source is a restricted domain are written: the root manager's domain is
# unrestricted, so rules from it would be dead weight. Nothing here names a device-specific
# domain - both come from this install's own context and the running gadget service.
{
	echo "# generated at install time: $gadget_domain -> $root_domain"
	echo "allow $gadget_domain $root_domain unix_stream_socket { connectto read write }"
	echo "allow $gadget_domain $gadget_domain process execmem"
	echo "allow system_server $root_domain unix_stream_socket { connectto read write }"
	echo "allow adbd $root_domain unix_stream_socket { read write }"
	# The private shell has shell_exec on /data, whose nosuid mount otherwise suppresses
	# AOSP's adbd -> shell domain transition and leaves logcat inaccessible.
	echo "allow adbd shell process2 nosuid_transition"
} > "$MODPATH/sepolicy.rule"
chmod 0644 "$MODPATH/sepolicy.rule"
# KernelSU consumes policy statements, not .te source. Refuse an unsupported rule
# during installation instead of silently shipping permissions the kernel never receives.
if command -v ksud >/dev/null 2>&1; then
	while IFS= read -r rule; do
		case "$rule" in ''|'#'*) continue ;; esac
		ksud sepolicy check "$rule" || abort "! unsupported generated policy: $rule"
	done < "$MODPATH/sepolicy.rule"
fi
ui_print "- gadget hook domain: $gadget_domain, daemon domain: $root_domain"

# Endpoint names: one random 64-bit base per role, with the role as the suffix. The daemon reads
# them from "names" beside it; each image is given only its own role's name, so no constant survives
# an install and one endpoint does not reveal the others.
random_base() {
	od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n'
}

names="$MODPATH/names"
: > "$names"
for role in ctl auth su; do
	base=$(random_base)
	if [ "${#base}" -ne 16 ]; then
		abort "! secure random source failed; refusing predictable endpoint names"
	fi
	printf '%s=%s.%s\n' "$role" "$base" "$role" >> "$names"
done
chmod 0600 "$names" 2>/dev/null
# Leftovers from older layouts: the name table lived in state/ and offsets were shipped beside it.
rm -f "$MODPATH/state/names" "$MODPATH/state/sockname" "$MODPATH/sockoff" "$MODPATH/sockoff-zn" 2>/dev/null

# Write one role's name over the token its image carries. busybox grep has no -b, so the search is
# byte-oriented: od renders the image as hex, and the offset is half the length of the text before
# the match. The token must occur exactly once, the write is read back, and the token must be gone
# afterwards: an image that was only half written would install looking fine and never connect.
token=IRA-SOCKET-NAME-0000000000000000

inject_name() {
	file=$1
	role=$2
	name=$3
	token=${4:-IRA-SOCKET-NAME-0000000000000000}

	if [ ! -f "$file" ]; then
		abort "! no $file to write the $role endpoint into"
	fi
	if [ -z "$name" ] || [ "${#name}" -gt 31 ]; then
		abort "! the $role endpoint name is not usable for $file"
	fi
	hex=$(od -An -v -tx1 "$file" | tr -d ' \n')
	pat=$(printf '%s' "$token" | od -An -v -tx1 | tr -d ' \n')
	prefix=${hex%"$pat"*}
	if [ "$prefix" = "$hex" ]; then
		abort "! no socket-name token in $file"
	fi
	case ${hex#*"$pat"} in
		*"$pat"*) abort "! more than one socket-name token in $file" ;;
	esac
	offset=$(( ${#prefix} / 2 ))
	{
		printf '%s' "$name"
		dd if=/dev/zero bs=1 count=$((32 - ${#name})) 2>/dev/null
	} | dd of="$file" bs=1 seek="$offset" conv=notrunc 2>/dev/null
	back=$(dd if="$file" bs=1 skip="$offset" count=${#name} 2>/dev/null)
	if [ "$back" != "$name" ]; then
		abort "! the $role endpoint was not written into $file"
	fi
	case $(od -An -v -tx1 "$file" | tr -d ' \n') in
		*"$pat"*) abort "! the socket-name token is still present in $file" ;;
	esac
	ui_print "- $role endpoint in $(basename "$file") at $offset"
}

inject_name "$MODPATH/lib/ira-zn.so" ctl "$(sed -n 's/^ctl=//p' "$names")"
inject_name "$MODPATH/zygisk/arm64-v8a.so" auth "$(sed -n 's/^auth=//p' "$names")"
inject_name "$MODPATH/zygisk/arm64-v8a.so" ctl "$(sed -n 's/^ctl=//p' "$names")" \
	IRA-CONTROL-NAME-00000000000000
ui_print "- Done"
