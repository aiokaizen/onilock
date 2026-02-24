"""Terminal UI helpers for OniLock using rich."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def success(msg: str) -> None:
    console.print(f"[bold green]✓[/bold green] {msg}")


def error(msg: str) -> None:
    error_console.print(f"[bold red]✗[/bold red] {msg}")


def warning(msg: str) -> None:
    console.print(f"[bold yellow]![/bold yellow] {msg}")


def info(msg: str) -> None:
    console.print(f"[dim]ℹ[/dim] {msg}")
