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

1. Make sure you installed dev dependancies

2. cd into the root directory of the project
```sh
cd path/to/onilock
```

3. Run the following command to create the package:
```sh
python -m build
```

4. Install pipx
```sh
sudo apt install pipx
```

5. Install the package systemwide

Make sure you don't have any active virtual environments before executing this command.

```sh
pipx install dist/onilock-<current-version>-py3-none-any.whl
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
OniLock is open-source and licensed under the MIT License.

## 🤝 Contributing
Contributions are welcome! Feel free to submit issues and pull requests.

## 📧 Contact
Author: Mouad Kommir  
Email: mouad.kommir@payticconnect.com

