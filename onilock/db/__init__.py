__all__ = ["DatabaseManager"]


def __getattr__(name: str):
    if name == "DatabaseManager":
        from .database_manager import DatabaseManager

        return DatabaseManager
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
