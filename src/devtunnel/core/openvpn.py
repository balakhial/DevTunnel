"""Read-only discovery of a locally installed OpenVPN command-line client."""

from __future__ import annotations

import os
from pathlib import Path
import platform
import shutil
from collections.abc import Callable, Mapping


def locate_openvpn_executable(
    *,
    path_lookup: Callable[[str], str | None] | None = None,
    system_name: str | None = None,
    environment: Mapping[str, str] | None = None,
    file_check: Callable[[Path], bool] | None = None,
) -> Path | None:
    """Locate openvpn.exe without launching it or changing system settings.

    PATH is checked first. On Windows, standard OpenVPN Community Edition
    install locations under Program Files are checked as a fallback.
    """
    lookup = path_lookup or shutil.which
    current_system = system_name or platform.system()
    env = environment if environment is not None else os.environ
    exists = file_check or Path.is_file

    for command in ("openvpn.exe", "openvpn"):
        located = lookup(command)
        if located:
            return Path(located)

    if current_system != "Windows":
        return None

    roots = []
    for key in ("ProgramFiles", "PROGRAMFILES", "ProgramW6432", "ProgramFiles(x86)"):
        root = env.get(key)
        if root and root not in roots:
            roots.append(root)

    for root in roots:
        candidate = Path(root) / "OpenVPN" / "bin" / "openvpn.exe"
        if exists(candidate):
            return candidate

    return None
