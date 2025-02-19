from setuptools import setup, find_packages

setup(
    name="passman",
    version="1.0.0",
    packages=find_packages(),
    py_modules=["passman"],
    install_requires=[
        "typer>=0.15.1,<0.16.0",
        "pydantic-settings>=2.7.1,<3.0.0",
        "colorlog>=6.9.0,<7.0.0",
        "cryptography>=44.0.1,<45.0.0",
        "bcrypt>=4.2.1,<5.0.0",
        "pyperclip>=1.9.0,<2.0.0",
    ],
    entry_points={
        "console_scripts": ["passman=passman:app"],
    },
)
