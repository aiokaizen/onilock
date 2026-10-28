"""
System tools OniLock relies on (gpg, a clipboard tool, vim), and a helper that
offers to install the missing ones with the platform's package manager.
"""

import os
import platform
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import typer

from onilock.core.ui import error, info, success, warning


# Package manager -> command that installs packages without asking again.
_PACKAGE_MANAGERS: Dict[str, List[str]] = {
    "brew": ["brew", "install"],
    "apt-get": ["apt-get", "install", "-y"],
    "dnf": ["dnf", "install", "-y"],
    "pacman": ["pacman", "-S", "--needed", "--noconfirm"],
    "zypper": ["zypper", "--non-interactive", "install"],
}


@dataclass
class Dependency:
    """A system tool, the binaries that provide it, and its package names."""

    name: str
    purpose: str
    binaries: Tuple[str, ...]
    packages: Dict[str, str]

    def is_installed(self) -> bool:
        return any(shutil.which(binary) for binary in self.binaries)


def _same_package(package: str) -> Dict[str, str]:
    return {manager: package for manager in _PACKAGE_MANAGERS}


GNUPG = Dependency(
    name="GnuPG",
    purpose="encrypted files",
    binaries=("gpg",),
    packages={
        "brew": "gnupg",
        "apt-get": "gnupg",
        "dnf": "gnupg2",
        "pacman": "gnupg",
        "zypper": "gpg2",
    },
)

VIM = Dependency(
    name="vim",
    purpose="viewing and editing encrypted files",
    binaries=("vim",),
    packages={
        "brew": "vim",
        "apt-get": "vim",
        "dnf": "vim-enhanced",
        "pacman": "vim",
        "zypper": "vim",
    },
)


def _is_wsl() -> bool:
    try:
        with open("/proc/version") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def clipboard_dependency() -> Optional[Dependency]:
    """
    Return the clipboard tool `onilock copy` needs on this system.

    Returns None when there is nothing to install: macOS, Windows and WSL have a
    built-in clipboard, and without a graphical session there is no clipboard.
    """
    if platform.system() != "Linux" or _is_wsl():
        return None

    x11_tools: Tuple[str, ...] = ()
    if os.environ.get("DISPLAY"):
        x11_tools = ("xclip", "xsel")

    if os.environ.get("WAYLAND_DISPLAY"):
        return Dependency(
            name="wl-clipboard",
            purpose="copying passwords",
            binaries=("wl-copy",) + x11_tools,
            packages=_same_package("wl-clipboard"),
        )
    if x11_tools:
        return Dependency(
            name="xclip",
            purpose="copying passwords",
            binaries=x11_tools,
            packages=_same_package("xclip"),
        )
    return None


def system_dependencies() -> List[Dependency]:
    """All system tools OniLock can use on this platform."""
    clipboard = clipboard_dependency()
    return [GNUPG] + ([clipboard] if clipboard else []) + [VIM]


def missing_dependencies(
    deps: Optional[Iterable[Dependency]] = None,
) -> List[Dependency]:
    if deps is None:
        deps = system_dependencies()
    return [dep for dep in deps if not dep.is_installed()]


def _package_manager() -> Optional[str]:
    if sys.platform == "darwin":
        candidates = ["brew"]
    else:
        candidates = ["apt-get", "dnf", "pacman", "zypper"]
    for manager in candidates:
        if shutil.which(manager):
            return manager
    return None


def install_command(deps: Iterable[Dependency]) -> Optional[List[str]]:
    """
    Return the command that installs `deps`, or None when no supported package
    manager is available.
    """
    manager = _package_manager()
    if manager is None:
        return None

    command = _PACKAGE_MANAGERS[manager] + [dep.packages[manager] for dep in deps]
    if manager != "brew" and os.geteuid() != 0:
        command = ["sudo"] + command
    return command


def install_hint(deps: Iterable[Dependency]) -> str:
    """Tell the user how to install `deps` themselves."""
    deps = list(deps)
    command = install_command(deps)
    if command:
        return f"Install with: {shlex.join(command)}"

    if sys.platform == "darwin":
        packages = " ".join(dep.packages["brew"] for dep in deps)
        return (
            "Install Homebrew from https://brew.sh, "
            f"then run: brew install {packages}"
        )

    names = ", ".join(dep.name for dep in deps)
    return f"Install {names} with your system's package manager."


def ensure_installed(deps: Iterable[Dependency]) -> bool:
    """
    Make sure `deps` are installed, offering to install any that are missing.

    The user is always asked first, and nothing is installed in a
    non-interactive session.

    Returns:
        True if every dependency is installed afterwards.
    """
    missing = missing_dependencies(deps)
    if not missing:
        return True

    for dep in missing:
        warning(f"{dep.name} is not installed. OniLock needs it for {dep.purpose}.")

    command = install_command(missing)
    if command is None or not sys.stdin.isatty():
        info(install_hint(missing))
        return False

    try:
        confirmed = typer.confirm(
            f"Install now with '{shlex.join(command)}'?", default=True
        )
    except typer.Abort:
        confirmed = False
    if not confirmed:
        info(install_hint(missing))
        return False

    try:
        returncode = subprocess.run(command).returncode
    except OSError:
        returncode = 1

    still_missing = missing_dependencies(missing)
    if returncode != 0 or still_missing:
        error("Installation did not finish. " + install_hint(still_missing or missing))
        return False

    success("Installed " + ", ".join(dep.name for dep in missing) + ".")
    return True
