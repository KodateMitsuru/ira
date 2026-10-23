// IRA-specific changes are licensed AGPL-3.0-or-later.
// Imported portions retain their original copyright and license notices below.
/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG SERVICES

#include "sysdeps.h"

#include "ira_privileges.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

#include <thread>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/parsenetaddress.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#include "adb.h"

#include "ira_bridge.h"

#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "services.h"
#include "socket_spec.h"
#include "sysdeps.h"
#include "transport.h"

#include "daemon/file_sync_service.h"
#include "daemon/logging.h"
#include "daemon/shell_service.h"

void reconnect_service(unique_fd fd, atransport* t) {
    WriteFdExactly(fd.get(), "done");
    kick_transport(t);
}

unique_fd reverse_service(std::string_view command, atransport* transport) {
    // TODO: Switch handle_forward_request to std::string_view.
    std::string str(command);

    int s[2];
    if (adb_socketpair(s)) {
        PLOG(ERROR) << "cannot create service socket pair.";
        return unique_fd{};
    }
    VLOG(SERVICES) << "service socketpair: " << s[0] << ", " << s[1];
    if (!handle_forward_request(str.c_str(), transport, s[1])) {
        SendFail(s[1], "not a reverse forwarding command");
    }
    adb_close(s[1]);
    return unique_fd{s[0]};
}

// Shell service string can look like:
//   shell[,arg1,arg2,...]:[command]
unique_fd ShellService(std::string_view args, const atransport* transport) {
    size_t delimiter_index = args.find(':');
    if (delimiter_index == std::string::npos) {
        LOG(ERROR) << "No ':' found in shell service arguments: " << args;
        return unique_fd{};
    }

    // TODO: android::base::Split(const std::string_view&, ...)
    std::string service_args(args.substr(0, delimiter_index));
    std::string command(args.substr(delimiter_index + 1));

    // Defaults:
    //   PTY for interactive, raw for non-interactive.
    //   No protocol.
    //   $TERM set to "dumb".
    SubprocessType type(command.empty() ? SubprocessType::kPty : SubprocessType::kRaw);
    SubprocessProtocol protocol = SubprocessProtocol::kNone;
    std::string terminal_type = "dumb";

    for (const std::string& arg : android::base::Split(service_args, ",")) {
        if (arg == kShellServiceArgRaw) {
            type = SubprocessType::kRaw;
        } else if (arg == kShellServiceArgPty) {
            type = SubprocessType::kPty;
        } else if (arg == kShellServiceArgShellProtocol) {
            protocol = SubprocessProtocol::kShell;
        } else if (arg.starts_with("TERM=")) {
            terminal_type = arg.substr(strlen("TERM="));
        } else if (!arg.empty()) {
            // This is not an error to allow for future expansion.
            LOG(WARNING) << "Ignoring unknown shell service argument: " << arg;
        }
    }

    return StartSubprocess(command, terminal_type.c_str(), type, protocol);
}

[[maybe_unused]] static unique_fd reboot_device(const std::string& name) {
    std::string cmd = "/system/bin/reboot ";
    cmd += name;
    return StartSubprocess(cmd, nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
}

asocket* daemon_service_to_socket(std::string_view name, atransport* transport) {
    /* Nothing here opens a long-lived socket the host can watch through: the debugger bridge, the
     * app tracker and the wiretap streams are not served by this stack on purpose (docs/design.md).
     * A client that asks for one is told there is no such service. */
    (void)name;
    (void)transport;
    return nullptr;
}

// Switch the default identity for future service backends. The client treats "restarting"
// as a promise of a USB disconnect, so the reply describes the in-process mode change.
static void root_service(unique_fd fd, bool root) {
    ira_root_set(root);
    WriteFdExactly(fd.get(), root ? "adbd is now running as root\n"
                                 : "adbd is now running as non root\n");
}

unique_fd daemon_service_to_fd(std::string_view name, atransport* transport) {
    ADB_LOG(Service) << "transport " << transport->serial_name() << " opening service " << name;

    /* No trade-in mode here: that is a factory/refurbishment path, and this stack does not carry
     * the state it would need to answer for. */
#if defined(__ANDROID__)
    if (name.starts_with("abb:") || name.starts_with("abb_exec:")) {
        return execute_abb_command(name);
    }
#endif

    // Root mode applies to newly started service backends; existing services keep their identity.
    if (name.starts_with("root:"))
        return create_service_thread(
                "root", std::bind(root_service, std::placeholders::_1, true));
    if (name == "reconnect")
        return create_service_thread("reconnect", std::bind(reconnect_service, std::placeholders::_1, transport));
    if (name.starts_with("unroot:"))
        return create_service_thread(
                "unroot", std::bind(root_service, std::placeholders::_1, false));

#if defined(__ANDROID__)
    if (android::base::ConsumePrefix(&name, "remount:")) {
        std::string cmd = "/system/bin/remount ";
        cmd += name;
        return StartSubprocess(cmd, nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
    } else if (android::base::ConsumePrefix(&name, "reboot:")) {
        return reboot_device(std::string(name));
    } else if (android::base::ConsumePrefix(&name, "backup:")) {
        std::string cmd = "/system/bin/bu backup ";
        cmd += name;
        return StartSubprocess(cmd, nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
    } else if (name.starts_with("restore:")) {
        return StartSubprocess("/system/bin/bu restore", nullptr, SubprocessType::kRaw,
                               SubprocessProtocol::kNone);
    } else if (name.starts_with("disable-verity:")) {
        return StartSubprocess("/system/bin/disable-verity", nullptr, SubprocessType::kRaw,
                               SubprocessProtocol::kNone);
    } else if (name.starts_with("enable-verity:")) {
        return StartSubprocess("/system/bin/enable-verity", nullptr, SubprocessType::kRaw,
                               SubprocessProtocol::kNone);
    }
#endif
    /* tcpip:, usb: and spin remain outside this USB-only daemon. Explicit forward/reverse
     * requests still use normal AOSP socket behavior; they do not start a TCP ADB transport. */

    if (android::base::ConsumePrefix(&name, "dev:")) {
        return unique_fd{unix_open(name, O_RDWR | O_CLOEXEC)};
    } else if (android::base::ConsumePrefix(&name, "dev-raw:")) {
        android::base::unique_fd fd(unix_open(name, O_RDWR | O_CLOEXEC));
        termios tattr;

        if (fd == -1) {
            return unique_fd{};
        }

        if (tcgetattr(fd.get(), &tattr) == -1) {
            return unique_fd{};
        }
        cfmakeraw(&tattr);
        if (tcsetattr(fd.get(), TCSADRAIN, &tattr) == -1) {
            return unique_fd{};
        }

        return fd;
    } else if (android::base::ConsumePrefix(&name, "shell")) {
        return ShellService(name, transport);
    } else if (android::base::ConsumePrefix(&name, "exec:")) {
        return StartSubprocess(std::string(name), nullptr, SubprocessType::kRaw,
                               SubprocessProtocol::kNone);
    } else if (name.starts_with("sync:")) {
        return create_service_thread("sync", file_sync_service);
    } else if (android::base::ConsumePrefix(&name, "reverse:")) {
        return reverse_service(name, transport);

    }

    return unique_fd{};
}
