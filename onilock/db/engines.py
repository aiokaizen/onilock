import os
import json
from typing import Any, Dict

from onilock.core.logging_manager import logger


class Engine:
    """Base Database Engine."""

    def __init__(self, db_url: str):
        self.db_url = db_url

    def write(self, data: Any) -> None:
        raise Exception("Unimplimented")

    def read(self) -> Dict:
        raise Exception("Unimplimented")


class JsonEngine(Engine):
    """Json Database Engine."""

    def __init__(self, db_url: str):
        self.filepath = db_url
        return super().__init__(db_url)

    def write(self, data: Dict) -> None:
        parent_dir = os.path.dirname(self.filepath)
        if not os.path.exists(parent_dir):
            logger.debug(f"Parent dir {parent_dir} does not exist. It will be created.")
            os.makedirs(parent_dir)

        with open(self.filepath, "w") as f:
            json.dump(data, f, indent=4)

    def read(self) -> Dict:
        if not os.path.exists(self.filepath):
            return dict()

        with open(self.filepath, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return dict()
