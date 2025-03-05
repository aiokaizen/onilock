from typing import Optional
from pathlib import Path

import typer


class FileEncryptionManager:
    """This class is responsible for all file operations."""

    def encrypt(self, file_id: str, filename: str):
        """Encrypts a file and stors it in the vault."""

        filepath = Path(filename)
        if not filepath.exists():
            typer.echo("File does not exist.")
            exit(1)

        if not filepath.is_file():
            typer.echo(
                "Please make sure `filename` is a normal file. Directories are not supported in this version."
            )
            exit(1)

        file_content = filepath.read_bytes()
        print(f"Content\n{file_content}")

        print(f"File {filename} was successfully incrypted.")

    def read(self, file_id: str):
        pass

    def remove(self, file_id: str):
        pass

    def export(self, file_id: Optional[str], filename: Optional[str]):
        """
        Decrypt and export a file to the specified new location.

        If file_id is not provided, export all files in the vault.
        """

        if not file_id:
            # Ask for confirmation befor exporting all files in the vault
            # to the target directory name (filename).
            pass

    def clear(self):
        """Delete all encrypted files in the vault."""
        pass
