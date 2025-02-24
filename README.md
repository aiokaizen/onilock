# OniLock - Secure Password Manager CLI

OniLock is a command-line password manager that allows you to securely store, retrieve, and manage your passwords with ease. Designed for simplicity and security, OniLock offers encryption and clipboard integration to keep your credentials safe.

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

### 🔹 List Stored Accounts
```sh
onilock list
```
Displays all saved accounts.

### 🔹 Copy a Password to Clipboard
```sh
onilock copy <account_name>
```
This copies the password to your clipboard securely.

### 🔹 Remove an Account
```sh
onilock remove <account_name>
```
Deletes the stored credentials.

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
### v1.5.0
- Rename shadow to vault
- Clear clipboard after 25 seconds if it still contains the password.
- Encrypt json files using PGP key instead of storing them as raw json file.
- Detect file corruption and manipulation using checksums

### v1.4.0
- Publish the project under the Apache 2.0 license
- Multiple refactoring
- Big upgrade to README.md file.

### v1.3.2
- Prepare for publishing to PyPi

### v1.3.1
- Renamed Account to Profile
- Renamed Password to Account
- Renamed the `accounts` command to `list`
- Remove exceptions and replace them with meaningful messages.

### v1.3.0
- Removed .env support
- Implement keyring secret storage.
- Introduce prompts to facilitate user input

View more changelog history on `CHANGELOG.md` file.

## 📧 Contact
Author: Mouad Kommir  
Email: mouadkommir@gmail.com

