LockBox - Secure Image Encryption CLI 🔒
========================================

**LockBox** is a command-line tool written in Go for securely encrypting and decrypting image files using AES-GCM encryption with PBKDF2 key derivation. It's perfect for protecting your photos with a user-friendly interface that makes file and directory selection a breeze! 📸 Whether you're securing a single image on your Desktop or batch-processing a folder, LockBox has you covered with strong encryption and a fun, interactive experience. 😄

Features 🌟
-----------

-   **Secure Encryption**: Uses AES-GCM with PBKDF2 for top-notch security. 🔐
-   **Compression**: Optional gzip compression to shrink files before encryption. 📦
-   **User-Friendly Interface**: Interactive menus for picking files and directories, with:
    -   Wildcards (e.g., *.jpg). 🌍
    -   Directory browsing (navigate, list directories/files, go up). 🗂️
    -   Quick access to Desktop and Pictures folders. 🖥️📷
    -   Drag-and-drop support for paths. 🖱️
-   **Flexible Processing**:
    -   Recursive directory processing. 📂
    -   Include/exclude file extensions. ✅❌
    -   Custom rename patterns for output files. ✍️
    -   Parallel processing for speed. ⚡
-   **Security Options**:
    -   Secure deletion (overwrite with random data). 🗑️
    -   Remove original files after processing. 🧹
    -   Keyfile support as an alternative to passwords. 🔑
-   **Extra Goodies**:
    -   Dry-run mode to simulate operations. 🧪
    -   Verbose output for detailed logging. 📜
    -   Optional logging to a file. 📝
    -   Checksum verification for decrypted files. ✔️

Use Cases 🎯
------------

-   **Secure Personal Photos**: Encrypt sensitive images on your Desktop or Pictures folder to keep them safe. 🛡️
-   **Batch Processing**: Encrypt or decrypt multiple images in a folder (e.g., ~/Desktop/photos/*.jpg) with one command. 🚀
-   **Secure File Sharing**: Encrypt images before sharing, so only those with the password can access them. 📩
-   **Data Protection**: Securely delete originals after encryption to prevent recovery. 🔍

Prerequisites 🛠️
-----------------

-   **Go**: Version 1.16 or higher (grab it from [golang.org](https://golang.org/dl/)). 🐹
-   **Operating System**: Works on Linux, macOS, or Windows. 🌐
-   **Terminal**: Basic comfort with running commands in a terminal or command prompt. 💻

Installation 🚀
---------------

1.  **Clone or Download the Code**:
    -   With Git:
        ```
        bash
        git clone https://github.com/yourusername/lockbox.git
        cd lockbox
        ```

    -   Or download lockbox.go from the repository and save it to a directory. 📥
2.  **Verify Go Installation**:
    -   Check Go is installed:

        ```
        bash
        go version
        ```

    -   Look for output like go version go1.21.0 linux/amd64. ✅
3.  **Build (Optional)**:
    -   Create an executable for convenience:

        ```
        bash
        go build -o lockbox lockbox.go
        ```

    -   This generates a lockbox binary in your directory. 🛠️

Usage 🎉
--------

LockBox is an interactive CLI tool. Run it and follow the prompts to encrypt or decrypt files with ease!

### Running the Program

-   **With Go**:



    ```
    bash
    go run lockbox.go
    ```

-   **With Binary** (if built):

    ```
    bash
    ./lockbox
    ```

    On Windows:

    

    ```
    cmd
    lockbox.exe
    ```

-   You'll see a fun interactive menu:

    ```
    ===================================
     🔐 LockBox - Interactive CLI
     Encrypt/decrypt images securely.
    ===================================
    Choose an option:
     1) Encrypt files
     2) Decrypt files
     3) Settings / Defaults
     4) Help
     5) Exit
    Choice:
    ```

### Example 1: Encrypting Images on Desktop 📸

**Goal**: Encrypt photo.jpg on your Desktop, saving the encrypted file to ~/Desktop/encrypted.

1.  Start the program:

    ```
    bash
    go run lockbox.go
    ```

2.  Select 1 (Encrypt files):


    ```
    Choice: 1
    ```

3.  Choose input files:


    ```
    -- Encrypt Files --
    Select files or directories:
    1) Enter paths manually (comma-separated, e.g., photo.jpg,*.jpg)
    2) Browse directories and select files
    3) Quick select: Desktop
    4) Quick select: Pictures
    Choice: 3
    ```

    -   Pick 3 to select the Desktop directory. 🖥️
4.  Configure options (press Enter for defaults):


    ```
    Compress files before encrypting? (reduces size) (y/n) [y]:
    Process directories recursively? (include subfolders) (y/n) [y]:
    Dry-run? (simulate, no changes made) (y/n) [n]:
    Show progress for each file? (y/n) [n]:
    Verbose output? (more details) (y/n) [n]:
    Allow overwriting existing output files? (y/n) [n]:
    Remove original files after encrypting? (y/n) [n]:
    Securely delete originals? (overwrite with random data) (y/n) [n]:
    ```

5.  Select output directory:


    ```
    Select output directory (current: .):
    1) Keep current directory
    2) Browse directories
    3) Quick select: Desktop
    4) Quick select: Pictures
    5) Enter path manually
    Choice: 5
    Enter output directory path (or drag-and-drop): ~/Desktop/encrypted
    ```

    -   Enter ~/Desktop/encrypted or drag-and-drop the folder. 📂
6.  Set rename pattern (optional):


    ```
    Rename pattern (e.g., {name}_locked{ext}, blank to use default suffix)
    Pattern (current: ):
    ```

    -   Press Enter for the default suffix (.enc). ✍️
7.  Set include/exclude extensions (optional):


    ```
    Include extensions (comma-separated, e.g., jpg,png) - press enter for default image types
    Include:
    Exclude extensions (comma-separated) - press enter for none
    Exclude:
    ```

8.  Set log file (optional):


    ```
    Log file path (press enter to skip)
    Log path:
    ```

9.  Choose password or keyfile:

    ```
    Use a keyfile instead of password? (keyfile contents used as key) (y/n) [n]:
    Password: mypassword123
    Confirm Password: mypassword123
    ```

10. Confirm and proceed:


    ```
    Found 1 files to encrypt. Proceed? (y/n) [y]:
    Encrypted: /home/yourusername/Desktop/photo.jpg -> /home/yourusername/Desktop/encrypted/photo.jpg.enc
    Done in 50ms. Processed 1 files.
    ```

### Example 2: Decrypting an Encrypted Image 🔓

**Goal**: Decrypt photo.jpg.enc from ~/Desktop/encrypted, saving to ~/Desktop/decrypted.

1.  Start the program and select 2 (Decrypt files):


    ```
    Choice: 2
    ```

2.  Choose input files:


    ```
    -- Decrypt Files --
    Select files or directories:
    1) Enter paths manually (comma-separated, e.g., photo.jpg,*.jpg)
    2) Browse directories and select files
    3) Quick select: Desktop
    4) Quick select: Pictures
    Choice: 2
    Current directory: /home/yourusername
    Options: [1] List directories, [2] List files, [3] Enter path, [4] Select this directory, [5] Go up, [6] Home, [7] Desktop, [8] Pictures
    Choice: 7
    Current directory: /home/yourusername/Desktop
    Options: [1] List directories, [2] List files, [3] Enter path, [4] Select this directory, [5] Go up, [6] Home, [7] Desktop, [8] Pictures
    Choice: 1
    Directories:
     1) encrypted
    Select directory number (or enter to go back): 1
    Current directory: /home/yourusername/Desktop/encrypted
    Options: [1] List directories, [2] List files, [3] Enter path, [4] Select this directory, [5] Go up, [6] Home, [7] Desktop, [8] Pictures
    Choice: 2
    Files:
     1) photo.jpg.enc
    Select file number (or enter to go back): 1
    ```

3.  Configure options (press Enter for defaults):


    ```
    Process directories recursively? (include subfolders) (y/n) [y]:
    Dry-run? (simulate, no changes made) (y/n) [n]:
    Show progress for each file? (y/n) [n]:
    Verbose output? (more details) (y/n) [n]:
    Allow overwriting existing output files? (y/n) [n]:
    Remove original encrypted files after decrypting? (y/n) [n]:
    Securely delete originals? (overwrite with random data) (y/n) [n]:
    Keep original name (no _decrypted added)? (y/n) [y]:
    ```

4.  Select output directory:


    ```
    Select output directory (current: .):
    1) Keep current directory
    2) Browse directories
    3) Quick select: Desktop
    4) Quick select: Pictures
    5) Enter path manually
    Choice: 5
    Enter output directory path (or drag-and-drop): ~/Desktop/decrypted
    ```

5.  Set rename pattern, extensions, and log file (optional):


    ```
    Rename pattern (e.g., {name}_unlocked{ext}, blank to use default)
    Pattern (current: ):
    Include extensions (comma-separated) - press enter for all files
    Include:
    Exclude extensions (comma-separated) - press enter for none
    Exclude:
    Log file path (press enter to skip)
    Log path:
    ```

6.  Enter password:


    ```
    Use a keyfile instead of password? (y/n) [n]:
    Password: mypassword123
    Confirm Password: mypassword123
    ```

7.  Confirm and proceed:


    ```
    Found 1 files to decrypt. Proceed? (y/n) [y]:
    Decrypted: /home/yourusername/Desktop/encrypted/photo.jpg.enc -> /home/yourusername/Desktop/decrypted/photo.jpg
    Done in 45ms. Processed 1 files.
    ```

### Example 3: Customizing Settings ⚙️

**Goal**: Set defaults (e.g., always compress, use ~/Desktop as output directory).

1.  Select 3 (Settings / Defaults):


    ```
    Choice: 3
    ```

2.  Configure defaults:


    ```
    -- Settings (current values in brackets) --
    Select output directory (current: .):
    1) Keep current directory
    2) Browse directories
    3) Quick select: Desktop
    4) Quick select: Pictures
    5) Enter path manually
    Choice: 3
    Suffix for encrypted files [.enc]:
    Parallel workers (0 = auto) [0]:
    Use compression by default? (y/n) [n]: y
    Use secure-delete by default? (y/n) [n]:
    Allow overwrite by default? (y/n) [n]:
    Process directories recursively by default? (y/n) [n]: y
    Keep original name for decrypt (no _decrypted added) by default? (y/n) [y]:
    Rename pattern example: {name}_locked{ext} (blank to disable)
    Rename pattern []:
    Include extensions (comma-separated, e.g., jpg,png) - blank for default images
    Include:
    Exclude extensions (comma-separated) - blank for none
    Exclude:
    Logging file path (blank to disable)
    Log path []: /home/yourusername/lockbox.log
    Settings updated.
    ```

Advanced Options 🧙‍♂️
----------------------

-   **Custom Rename Patterns**:
    -   Use {name} for the filename and {ext} for the extension.
    -   Example: {name}_locked{ext} turns photo.jpg into photo_locked.jpg.enc (encrypt) or photo_locked.jpg (decrypt). ✍️
-   **Include/Exclude Extensions**:
    -   Include: jpg,png to process only .jpg and .png files. ✅
    -   Exclude: enc to skip .enc files during encryption. ❌
-   **Keyfile Support**:
    -   Use a file's contents as the encryption key:

        ```
        Use a keyfile instead of password? (y/n) [n]: y
        Path to keyfile: /home/yourusername/key.bin
        ```

-   **Advanced Encryption Settings**:
    -   Customize PBKDF2 iterations, salt, and hash algorithm:


        ```
        Customize advanced settings (PBKDF2 iterations, salt, hash algo)? (y/n) [n]: y
        Iterations (current: 100000, recommended 100000+): 200000
        Salt (hex or text, empty for random):
        Hash algo (sha256 or sha512, current: sha256): sha512
        ```

Security Notes 🔐
-----------------

-   **Password Strength**: Choose strong, unique passwords or keyfiles for maximum security. 💪
-   **Secure Delete**: Enable secure deletion to overwrite originals with random data, preventing recovery. 🗑️
-   **Checksum Verification**: Decrypted files are checked against stored checksums (non-compressed files) to ensure integrity. ✔️
-   **Keyfile Safety**: Store keyfiles securely, as they act as your encryption key. 🔑

Troubleshooting 🛠️
-------------------

-   **"file too small or not a valid lockbox file"**: Ensure the file is a LockBox-encrypted file (starts with IMGENC1). 📄
-   **"decryption/auth failed"**: Double-check the password or keyfile matches the one used for encryption. 🔑
-   **"file exists"**: Enable overwrite or choose a different output directory. 📂
-   **Path Errors**: Use absolute paths, ~ for home, or drag-and-drop to avoid typos. 🖱️
-   **Compilation Errors**: Verify Go is installed (go version). 🐹

Acknowledgments 🌈
------------------

-   Built with Go and standard libraries for cross-platform compatibility. 🐹
-   Inspired by the need for a simple, secure, and fun image encryption tool! 😄
