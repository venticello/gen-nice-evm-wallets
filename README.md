# EVM Beautiful Wallet Generator & Manager

A secure, multi-threaded CLI tool for generating, storing, and managing beautiful EVM (Ethereum) wallets.

## Features
- Generate beautiful EVM wallets with custom patterns
- Secure encrypted storage with master password
- List, export, and retrieve private keys via CLI
- Support for custom wallet storage files

## Installation
```sh
npm install
```

If you use TypeScript and want type support for yargs:
```sh
npm install --save-dev @types/yargs
```

## Usage
### Generate wallets
```sh
node wallet.js generate 5 --out=mywallets.json --startsWith=000
```

#### Generation options:
```
--workers=N                 - Number of workers (default: CPU cores - 1)
--out=FILENAME              - Output file for wallets (default: encrypted_wallets.json)

# patterns
--startsWith=XXX            - Starts with characters
--endsWith=XXX              - Ends with characters
--contains=XXX              - Contains substring
--repeating=N               - Repeating characters (minimum N in a row)

```

#### Default pattern 
1. Checks for addresses with:
- **Either** 3 consecutive identical characters starting at position 2 **OR** 3 consecutive identical characters starting at position 3
- **AND** 5 consecutive identical characters at the end of the address

    Examples that would match:
    - `0x111abc...22222` (3 at start + 5 at end)
    - `0xd111bc...33333` (3 at start + 5 at end)

2. Checks for addresses with:
- **Exactly** 4 consecutive identical characters starting at position 2 (after "0x")
- **AND** 4 consecutive identical characters at the end

    Examples that would match:
    - `0x1111ab...2222` (4 at start + 4 at end)
    - `0xaaaabd...cccc` (4 at start + 4 at end)


### List wallets
```sh
node wallet-manager.js list --file=mywallets.json
```

### Get private key
```sh
node wallet-manager.js get 1 --file=mywallets.json
```

### Export wallet
```sh
node wallet-manager.js export 2 exported_wallet.json --file=mywallets.json
```

## Wallet Storage File Structure
```json
{
  "wallets": [
    {
      "address": "0x...",
      "encryptedPrivateKey": "...",
      "salt": "...",
      "iv": "...",
      "createdAt": "2024-06-01T12:00:00.000Z",
      "pattern": "starts with 000"
    }
  ],
  "version": "1.0"
}
```

## Security Notes
- **Never share your master password or unencrypted private keys!**
- The exported wallet file contains the private key in plain text.
- Always use a strong, unique master password.

## Contributing
Pull requests and issues are welcome!

If you like the app and want to support
0x000D1f59A429D43Adbdf7fA94Df7470D16cDDDDD

## License
MIT 