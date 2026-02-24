# OniLock - Secure Password Manager CLI

OniLock is a command-line password manager that allows you to securely store, retrieve, and manage your passwords with ease. Designed for simplicity and security, OniLock offers encryption and clipboard integration to keep your credentials safe.


## 📖 Introduction
Most password managers focus on graphical interfaces, leaving terminal enthusiasts behind. Onilock changes that by offering a sleek, terminal-based user experience paired with a comprehensive set of command-line options.

It’s designed for those working without a graphical interface, users who need quick password access over SSH, or anyone who simply prefers the command line over traditional GUI tools.

With full support for command-line arguments, Onilock empowers users to create custom aliases and streamline password management to fit their unique workflows.


## 🚀 Features
- **Initialize a secure profile** using `onilock init`
- **Store new accounts** with `onilock new`
- **List stored accounts** using `onilock list`
- **Copy passwords to clipboard** securely with `onilock copy`
- **Remove accounts** using `onilock remove`
- **Generate strong passwords** with `onilock generate`
- **Shell completion support** for faster command-line usage


## 🛠 Installation

OniLock is best installed using `pipx` to keep it isolated:

1. **Install pipx**
```sh
sudo apt install pipx
```

2. **Install OniLock systemwide**

N.B. Make sure you don't have any active virtual environments before executing this command.

```sh
pipx install onilock
```


## ⚠️  Issues

If you encounter any issues with the `init` command, make sure the following dependancies are setup in your system:

1. **Ensure xclip and gpg are installed**. If not, run the following command
```sh
sudo apt install xclip gpg
```


## 📌 Usage
Once installed, you can use `onilock` directly from your terminal:

```sh
onilock --help
```

### 🔹 Initialize OniLock
Before using OniLock, initialize your profile:
```sh
onilock init
```

### 🔹 Add a New Account
```sh
onilock new
```
You will be prompted to enter the account name, username, and password.

Recommended structured workflow:
```sh
onilock secrets create
```

### 🔹 List Stored Accounts
```sh
onilock list
```
Displays all saved accounts.

Structured command:
```sh
onilock secrets list
```

### 🔹 Copy a Password to Clipboard
```sh
onilock copy <account_name>
```
This copies the password to your clipboard securely.

Structured command:
```sh
onilock secrets copy <account_name_or_index>
```

### 🔹 Show Secret Details
```sh
onilock secrets show <account_name_or_index>
onilock secrets show <account_name_or_index> --reveal
```

### 🔹 Update a Secret
```sh
onilock secrets update <account_name_or_index> --username new_user
onilock secrets update <account_name_or_index> --generate-password
```

### 🔹 Rename a Secret
```sh
onilock secrets rename <account_name_or_index> <new_name>
```
Alias:
```sh
onilock rename <account_name_or_index> <new_name>
```

### 🔹 Search Secrets
```sh
onilock secrets search github
onilock secrets search "corp" --field url
```
Alias:
```sh
onilock search github
```

### 🔹 Remove an Account
```sh
onilock remove <account_name>
```
Deletes the stored credentials.

Structured command:
```sh
onilock secrets delete <account_name_or_index>
```

### 🔹 Generate a Secure Password
```sh
onilock generate
```
Creates a strong random password.


## 🔒 Security
- OniLock encrypts stored passwords and prevents direct file access.
- Uses the system keyring for secure storage (if available).
- Passwords copied to the clipboard are automatically cleared after a short period.


## 🖥️ Shell Autocompletion
Enable shell autocompletion for easier usage:
```sh
onilock --install-completion
```


## 📜 License
OniLock is open-source and licensed under the Apache 2.0 License.


## 🤝 Contributing
Contributions are welcome! Feel free to submit issues and pull requests.


## 📝 Changelog

### v1.7.0
- Implement file encryption capabilities.
    - Possibility to encrypt any file in your system and add it to the vault.
    - View, and Edit files directly in the vault without exposing them to external threats.
    - Ability to export a single file or all files in the vault to a zip file.
- Introduce env.py to fix the circular import problem.
- Other bug fixes and improvements

### v1.6.0
- Fix some bugs.
- Implement support for terminal-based distros.
- Implement git-hub actions for auto-deployment when a new release is created.
- Improve project structure, and implement some design patterns

### v1.5.4
- Update `version` command
- Ignore case for `delete` and `copy` commands
- Detect file corruption and manipulation using checksums

### v1.5.0
- Rename shadow to vault
- Clear clipboard after 25 seconds if it still contains the password.
- Encrypt json files using PGP key instead of storing them as raw json file.
- Detect file corruption and manipulation using checksums

View full changelog history on `CHANGELOG.md` file.


## 📧 Contact
Author: Mouad Kommir  
Email: mouadkommir@gmail.com
