class BaseException(Exception):
    pass


class EncryptionKeyNotFoundError(BaseException):
    pass


class DatabaseEngineAlreadyExistsException(BaseException):
    def __init__(self, id: str = "") -> None:
        if id:
            return super().__init__(f"Engine with id `{id}` already exists.")
        return super().__init__("Engine already exists.")
