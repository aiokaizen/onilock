import os
import json
from typing import Dict, Optional


class JsonEngine:
    """Json Database Engine."""

    def __init__(self, filepath: str, data: Optional[Dict] = None):
        self.filepath = filepath
        if data:
            self.write(data)

    def write(self, data: Dict) -> None:
        with open(self.filepath, "w") as f:
            json.dump(data, f)

    def read(self) -> Dict:
        if not os.path.exists(self.filepath):
            open(self.filepath, "w").close()

        with open(self.filepath, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return dict()
