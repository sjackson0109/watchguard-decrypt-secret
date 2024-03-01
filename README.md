# WatchGuard XTM Config File Encryption/Decryption Tool

## Overview

This tool provides a solution for decrypting sensitive parameters in a WatchGuard XTM configuration export file.
It can also provide a mechanism to encrypt new values for these parameters.

# Contributions
- Version:        1.0.0
- Creation Date:  2023-03-01
- Last Updated:   2024-01-08
- Author:         sjackson0109

## Usage

### Prerequisites

- PowerShell 5.1 or later
- WatchGuard XTM configuration export file (.xml)

### Instructions

1. Download the `Encrypt-WatchguardParameter.ps1` and `Decrypt-WatchguardParameter.ps1` scripts.

2. Place the scripts in a directory accessible from your PowerShell environment.

3. Open PowerShell and navigate to the directory containing the scripts.

4. To encrypt sensitive parameters, use the `Encrypt-WatchguardParameter.ps1` script with the `-PlainText` parameter followed by the value to encrypt. Optionally, use the `-VerboseMode` switch for detailed output.

   Example:
   ```powershell
   Encrypt-WatchguardParameter -PlainText 'YourSensitiveData' -VerboseMode
   ```

5. To decrypt encrypted parameters, use the `Decrypt-WatchguardParameter.ps1` script with the `-EncryptedText` parameter followed by the encrypted value. Optionally, use the `-VerboseMode` switch for detailed output.

   Example:
   ```powershell
   Decrypt-WatchguardParameter -EncryptedText 'YourEncryptedData' -VerboseMode
   ```

6. Ensure that the encrypted values are safely stored and used in the WatchGuard XTM configuration file.

## Considerations

- Ensure that only authorized personnel have access to the encrypted values and decryption scripts.
- Always verify the integrity of the decrypted values after decryption.
- Protect the encryption keys used by the tool to prevent unauthorized access to sensitive information.

## License

This project is licensed under the [MIT License](LICENSE).


## Looking for contributors
I'm looking to expand on this code, with the following:
- Import and Export of XML config files
- Auto-matically index all encrypted parameters
- Ability to decrypt-all parameters
- Ability to replace specific encrypted parameters with new unencrypted value

Am also open to ideas, please feel free to send some over...