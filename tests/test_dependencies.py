"""Tests for onilock.core.dependencies."""

import os
import unittest
from unittest.mock import MagicMock, patch

import typer

from onilock.core.dependencies import (
    GNUPG,
    VIM,
    Dependency,
    clipboard_dependency,
    ensure_installed,
    install_command,
    install_hint,
    missing_dependencies,
    system_dependencies,
)


def _which(available):
    """shutil.which replacement that only finds the given binaries."""
    return lambda name: f"/usr/bin/{name}" if name in available else None


def _env(**values):
    """os.environ without display variables, plus `values`."""
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("DISPLAY", "WAYLAND_DISPLAY")
    }
    env.update(values)
    return patch.dict(os.environ, env, clear=True)


def _linux():
    system = patch("onilock.core.dependencies.platform.system", return_value="Linux")
    wsl = patch("onilock.core.dependencies._is_wsl", return_value=False)
    return system, wsl


class TestDependency(unittest.TestCase):
    def test_installed_when_any_binary_found(self):
        dep = Dependency("xclip", "copying", ("xclip", "xsel"), {})
        with patch("onilock.core.dependencies.shutil.which", _which({"xsel"})):
            self.assertTrue(dep.is_installed())

    def test_missing_when_no_binary_found(self):
        with patch("onilock.core.dependencies.shutil.which", _which(set())):
            self.assertFalse(GNUPG.is_installed())
            self.assertEqual(missing_dependencies([GNUPG, VIM]), [GNUPG, VIM])


class TestClipboardDependency(unittest.TestCase):
    def test_none_on_macos(self):
        with patch(
            "onilock.core.dependencies.platform.system", return_value="Darwin"
        ):
            self.assertIsNone(clipboard_dependency())

    def test_none_on_wsl(self):
        with patch("onilock.core.dependencies.platform.system", return_value="Linux"):
            with patch("onilock.core.dependencies._is_wsl", return_value=True):
                with _env(DISPLAY=":0"):
                    self.assertIsNone(clipboard_dependency())

    def test_none_without_graphical_session(self):
        system, wsl = _linux()
        with system, wsl, _env():
            self.assertIsNone(clipboard_dependency())

    def test_xclip_on_x11(self):
        system, wsl = _linux()
        with system, wsl, _env(DISPLAY=":0"):
            dep = clipboard_dependency()
        self.assertEqual(dep.name, "xclip")
        self.assertEqual(dep.binaries, ("xclip", "xsel"))
        self.assertEqual(dep.packages["apt-get"], "xclip")

    def test_wl_clipboard_on_wayland(self):
        system, wsl = _linux()
        with system, wsl, _env(WAYLAND_DISPLAY="wayland-0"):
            dep = clipboard_dependency()
        self.assertEqual(dep.name, "wl-clipboard")
        self.assertEqual(dep.binaries, ("wl-copy",))

    def test_wayland_accepts_x11_tools_when_xwayland_is_available(self):
        system, wsl = _linux()
        with system, wsl, _env(WAYLAND_DISPLAY="wayland-0", DISPLAY=":0"):
            dep = clipboard_dependency()
        self.assertEqual(dep.binaries, ("wl-copy", "xclip", "xsel"))

    def test_system_dependencies_include_clipboard_when_needed(self):
        system, wsl = _linux()
        with system, wsl, _env(DISPLAY=":0"):
            names = [dep.name for dep in system_dependencies()]
        self.assertEqual(names, ["GnuPG", "xclip", "vim"])


class TestInstallCommand(unittest.TestCase):
    def test_brew_on_macos(self):
        with patch("onilock.core.dependencies.sys.platform", "darwin"):
            with patch("onilock.core.dependencies.shutil.which", _which({"brew"})):
                self.assertEqual(
                    install_command([GNUPG, VIM]), ["brew", "install", "gnupg", "vim"]
                )

    def test_none_on_macos_without_homebrew(self):
        with patch("onilock.core.dependencies.sys.platform", "darwin"):
            with patch("onilock.core.dependencies.shutil.which", _which(set())):
                self.assertIsNone(install_command([GNUPG]))
                self.assertIn("https://brew.sh", install_hint([GNUPG]))
                self.assertIn("brew install gnupg", install_hint([GNUPG]))

    def test_apt_uses_sudo_for_regular_users(self):
        with patch("onilock.core.dependencies.sys.platform", "linux"):
            with patch("onilock.core.dependencies.shutil.which", _which({"apt-get"})):
                with patch("onilock.core.dependencies.os.geteuid", return_value=1000):
                    self.assertEqual(
                        install_command([GNUPG]),
                        ["sudo", "apt-get", "install", "-y", "gnupg"],
                    )

    def test_no_sudo_for_root(self):
        with patch("onilock.core.dependencies.sys.platform", "linux"):
            with patch("onilock.core.dependencies.shutil.which", _which({"apt-get"})):
                with patch("onilock.core.dependencies.os.geteuid", return_value=0):
                    self.assertEqual(
                        install_command([GNUPG]), ["apt-get", "install", "-y", "gnupg"]
                    )

    def test_dnf_package_names(self):
        with patch("onilock.core.dependencies.sys.platform", "linux"):
            with patch("onilock.core.dependencies.shutil.which", _which({"dnf"})):
                with patch("onilock.core.dependencies.os.geteuid", return_value=0):
                    self.assertEqual(
                        install_command([GNUPG, VIM]),
                        ["dnf", "install", "-y", "gnupg2", "vim-enhanced"],
                    )

    def test_hint_without_package_manager_on_linux(self):
        with patch("onilock.core.dependencies.sys.platform", "linux"):
            with patch("onilock.core.dependencies.shutil.which", _which(set())):
                self.assertEqual(
                    install_hint([GNUPG]),
                    "Install GnuPG with your system's package manager.",
                )


class TestEnsureInstalled(unittest.TestCase):
    def setUp(self):
        self.available = set()
        patches = [
            patch(
                "onilock.core.dependencies.shutil.which",
                side_effect=lambda name: (
                    f"/usr/bin/{name}" if name in self.available else None
                ),
            ),
            patch("onilock.core.dependencies.sys.platform", "darwin"),
            patch("onilock.core.dependencies.sys.stdin"),
            patch("onilock.core.dependencies.typer.confirm", return_value=True),
            patch("onilock.core.dependencies.subprocess.run"),
            patch("onilock.core.dependencies.info"),
            patch("onilock.core.dependencies.warning"),
            patch("onilock.core.dependencies.error"),
            patch("onilock.core.dependencies.success"),
        ]
        mocks = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)
        _, _, self.stdin, self.confirm, self.run, self.info, _, self.error, _ = mocks
        self.stdin.isatty.return_value = True
        self.available.add("brew")

    def _install_succeeds(self, *binaries):
        def run(command):
            self.available.update(binaries)
            return MagicMock(returncode=0)

        self.run.side_effect = run

    def test_nothing_missing_returns_true_without_asking(self):
        self.available.add("gpg")
        self.assertTrue(ensure_installed([GNUPG]))
        self.confirm.assert_not_called()

    def test_accepted_installs_and_returns_true(self):
        self._install_succeeds("gpg")
        self.assertTrue(ensure_installed([GNUPG]))
        self.run.assert_called_once_with(["brew", "install", "gnupg"])

    def test_non_interactive_prints_hint_and_installs_nothing(self):
        self.stdin.isatty.return_value = False
        self.assertFalse(ensure_installed([GNUPG]))
        self.confirm.assert_not_called()
        self.run.assert_not_called()
        self.info.assert_called_once_with("Install with: brew install gnupg")

    def test_declined_installs_nothing(self):
        self.confirm.return_value = False
        self.assertFalse(ensure_installed([GNUPG]))
        self.run.assert_not_called()

    def test_ctrl_c_at_prompt_counts_as_no(self):
        self.confirm.side_effect = typer.Abort()
        self.assertFalse(ensure_installed([GNUPG]))
        self.run.assert_not_called()

    def test_no_package_manager_prints_hint(self):
        self.available.discard("brew")
        self.assertFalse(ensure_installed([GNUPG]))
        self.confirm.assert_not_called()
        self.assertIn("https://brew.sh", self.info.call_args[0][0])

    def test_failed_install_returns_false(self):
        self.run.return_value = MagicMock(returncode=1)
        self.assertFalse(ensure_installed([GNUPG]))
        self.error.assert_called_once()

    def test_install_that_does_not_provide_binary_returns_false(self):
        self.run.return_value = MagicMock(returncode=0)
        self.assertFalse(ensure_installed([GNUPG]))
        self.error.assert_called_once()

    def test_package_manager_that_cannot_run_returns_false(self):
        self.run.side_effect = FileNotFoundError("sudo")
        self.assertFalse(ensure_installed([GNUPG]))
        self.error.assert_called_once()

    def test_only_missing_dependencies_are_installed(self):
        self.available.add("vim")
        self._install_succeeds("gpg")
        self.assertTrue(ensure_installed([GNUPG, VIM]))
        self.run.assert_called_once_with(["brew", "install", "gnupg"])


if __name__ == "__main__":
    unittest.main()
