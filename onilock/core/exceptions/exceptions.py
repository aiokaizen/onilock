class OniLockError(Exception):
    """Base exception for application-specific errors."""

    def __init__(self, message: str = "OniLock operation failed") -> None:
        super().__init__(message)


class VaultNotInitializedError(OniLockError):
    def __init__(self) -> None:
        super().__init__(
            "This vault is not initialized. Please run `onilock init` first."
        )


class VaultAlreadyInitializedError(OniLockError):
    def __init__(self) -> None:
        super().__init__("This vault is already initialized.")


class VaultAuthenticationError(OniLockError):
    def __init__(self, message: str = "Invalid master password.") -> None:
        super().__init__(message)


class InvalidAccountIdentifierError(OniLockError):
    def __init__(self, message: str = "Invalid account name or index.") -> None:
        super().__init__(message)


class InvalidFileIdentifierError(OniLockError):
    def __init__(self, message: str = "Invalid file id.") -> None:
        super().__init__(message)


class VaultConfigurationError(OniLockError):
    def __init__(self, message: str = "Vault configuration is invalid.") -> None:
        super().__init__(message)


class EncryptionKeyNotFoundError(OniLockError):
    def __init__(self, message: str = "Encryption key not found.") -> None:
        super().__init__(message)


class KeyRingBackendNotAvailable(OniLockError):
    def __init__(self, message: str = "No keyring backend is available.") -> None:
        super().__init__(message)


class DatabaseEngineAlreadyExistsException(OniLockError):
    def __init__(self, id: str = "") -> None:
        if id:
            return super().__init__(f"Engine with id `{id}` already exists.")
        return super().__init__("Engine already exists.")
