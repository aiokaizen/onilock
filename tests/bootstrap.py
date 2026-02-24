import os
from pathlib import Path


TEST_HOME = Path("/tmp/onilock-tests-home")
TEST_HOME.mkdir(parents=True, exist_ok=True)

os.environ["HOME"] = str(TEST_HOME)
os.environ["ONI_DEFAULT_KEYSTORE_BACKEND"] = "vault"
