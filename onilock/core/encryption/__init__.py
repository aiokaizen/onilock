__all__ = ["GPGEncryptionBackend"]


def __getattr__(name: str):
    if name == "GPGEncryptionBackend":
        from .encryption import GPGEncryptionBackend

        return GPGEncryptionBackend
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
