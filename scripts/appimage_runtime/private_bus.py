"""Per-case session bus boundary; never connect to a host or user session bus."""

import os
import re
import stat
import subprocess
from urllib.parse import quote
from xml.sax.saxutils import escape

SERVICE = "com.cmtrace.open.SingleInstance"


def runtime(area, uid):
    directory = area / "runtime"
    info = directory.lstat()
    if (type(uid) is not int or uid <= 0 or uid != os.geteuid()
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("private-bus-unavailable")
    return directory


def address(area):
    return "unix:path=" + quote(str(area / "runtime/bus"), safe="/")


def write_configuration(area, uid):
    directory = runtime(area, uid)
    try:
        (directory / "bus").lstat()
    except FileNotFoundError:
        pass
    else:
        raise ValueError("private-bus-unavailable")
    config = directory / "session.conf"
    # Only a new daemon in this account's private directory reads this file.
    # Standard activation dirs retain the existing AT-SPI service activation.
    content = ('<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" '
               '"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n'
               '<busconfig><type>session</type><auth>EXTERNAL</auth>\n'
               f'<listen>{escape(address(area))}</listen>\n'
               '<standard_session_servicedirs/>\n'
               f'<policy context="default"><allow user="{uid}"/>'
               '<allow own="*"/><allow send_destination="*"/>'
               '<allow receive_sender="*"/></policy></busconfig>\n')
    fd = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(content)
    return config


def verify(area, uid):
    directory = runtime(area, uid)
    actual = os.environ.get("DBUS_SESSION_BUS_ADDRESS", "")
    if (not re.fullmatch(re.escape(address(area)) + r"(?:,guid=[a-f0-9]{32})?", actual)
            or any(name in os.environ for name in ("DBUS_SYSTEM_BUS_ADDRESS", "DBUS_STARTER_ADDRESS"))):
        raise ValueError("private-bus-unavailable")
    info = (directory / "bus").lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != uid:
        raise ValueError("private-bus-unavailable")
    return actual


def query(area, uid, method, argument):
    bus = verify(area, uid)
    try:
        result = subprocess.run(
            ["/usr/bin/dbus-send", "--bus=" + bus, "--print-reply=literal", "--reply-timeout=5000",
             "--dest=org.freedesktop.DBus", "/org/freedesktop/DBus",
             "org.freedesktop.DBus." + method, "string:" + argument],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise ValueError("private-bus-unavailable") from error
    if len(result.stdout.encode()) > 4096:
        raise ValueError("private-bus-unavailable")
    return result.stdout.strip()


def has_owner(area, uid):
    result = query(area, uid, "NameHasOwner", SERVICE)
    if result not in ("boolean true", "boolean false"):
        raise ValueError("private-bus-unavailable")
    return result == "boolean true"


def owner(area, uid):
    if not has_owner(area, uid):
        return None
    name = query(area, uid, "GetNameOwner", SERVICE)
    if not re.fullmatch(r":[0-9]+\.[0-9]+", name):
        raise ValueError("private-bus-unavailable")
    values = []
    for method in ("GetConnectionUnixProcessID", "GetConnectionUnixUser"):
        match = re.fullmatch(r"uint32 ([0-9]+)", query(area, uid, method, name))
        if match is None:
            raise ValueError("private-bus-unavailable")
        values.append(int(match[1]))
    pid, actual_uid = values
    if not 0 < pid < 2**31 or actual_uid != uid or query(area, uid, "GetNameOwner", SERVICE) != name:
        raise ValueError("private-bus-unavailable")
    return name, pid
