# 💎 EVM Beautiful Wallet Generator & Manager

A powerful, fast, and secure CLI tool for generating, storing, and managing "beautiful" EVM (Ethereum, Base, Polygon, etc.) wallet addresses with custom patterns. Built with Node.js and TypeScript, using multi-threading for maximum performance.

## ✨ Features

- **High-Speed Generation**: Utilizes all available CPU cores for parallel wallet generation.
- **Custom Patterns**: Find addresses that start with, end with, or contain specific characters, or have repeating digits.
- **Secure Storage**: All wallets are encrypted with a master password using `AES-256-GCM` and `scrypt`.
- **Wallet Management**: A separate CLI for listing wallets, viewing addresses, and securely exporting private keys.
- **Real-Time Stats**: Live dashboard in your terminal showing generation speed, total attempts, and worker statistics.

## ⚙️ Installation

1.  Clone the repository:
    ```sh
    git clone https://github.com/venticello/gen-nice-evm-wallets.git
    cd gen-nice-evm-wallets
    ```

2.  Install dependencies:
    ```sh
    npm install
    ```

The project uses `ts-node` to run TypeScript files directly, so no manual compilation step is needed for development.

## 🚀 Running in Production (Recommended)

For performance and stability, it is recommended to compile the TypeScript code to JavaScript and run the compiled output directly with Node.js.

1.  **Build the project:**
    This command compiles all `.ts` files into a `dist/` directory.
    ```sh
    npm run build
    ```

2.  **Run the compiled scripts:**
    Use `node` to execute the scripts from the `dist` directory.

    *   **To generate wallets:**
        ```sh
        node dist/wallet.js generate 10 --startsWith "BEEF"
        ```
    *   **To manage wallets:**
        ```sh
        node dist/wallet-manager.js list --file my_wallets.json
        ```

## 💻 Usage (Development)

The tool is split into two main scripts:
1.  `src/wallet.ts`: For generating new wallets.
2.  `src/wallet-manager.ts`: For managing existing wallets in a storage file.

The examples below use `ts-node` which is convenient for development and testing, but not recommended for production use.

### 1. Generating New Wallets

You can run the generator using the `npm run generate` script or by calling `ts-node` directly. When you first run it, you will be prompted to create a secure master password for your wallet file.

**Basic command structure:**
```sh
ts-node src/wallet.ts generate <count> [options]
```

**Example: Generate 5 wallets with the default "beauty" pattern**
This pattern looks for addresses with repeating characters at the start and end (e.g., `0x1111...ffff`).
```sh
ts-node src/wallet.ts generate 5
```

**Example: Find 1 wallet that starts with "BEEF" and save it to a custom file**
```sh
ts-node src/wallet.ts generate 1 --startsWith BEEF --out my_special_wallets.json
```

**Getting Help**
To see all available generation options, use the `--help` flag:
```sh
ts-node src/wallet.ts generate --help
```

### 2. Managing Existing Wallets

The wallet manager is a separate tool for interacting with your `encrypted_wallets.json` file (or any other file you specified with `--out`).

**Basic command structure:**
```sh
ts-node src/wallet-manager.ts <command> [options]
```

**Example: List all wallets in a specific file**
You will be prompted for your master password to decrypt the data for viewing.
```sh
ts-node src/wallet-manager.ts list --file my_special_wallets.json
```

**Example: Get the private key for a specific wallet (by its ID)**
The ID is the number shown in the `list` command.
```sh
ts-node src/wallet-manager.ts get 1 --file my_special_wallets.json
```

**Example: Export a single wallet (unencrypted) to a new file**
```sh
ts-node src/wallet-manager.ts export 1 --outFile exported_beef_wallet.json --file my_special_wallets.json
```

**Getting Help**
To see all available management commands and options, use the `--help` flag:
```sh
ts-node src/wallet-manager.ts --help
```

## 🔒 Security Notice

-   **Master Password is Critical**: Your master password is the only way to decrypt your wallets. If you lose it, your funds are permanently inaccessible. There is no recovery mechanism.
-   **Private Keys**: Never share your private keys or your master password. Anyone with access to them has full control over your funds.
-   **Exported Files are Unencrypted**: The `export` command saves the wallet (including the private key) in plain text. Handle this file with extreme care and delete it securely after use.

## 💖 Support

If you find this tool useful, consider supporting its development:

**EVM Address**: `0x000D1f59A429D43Adbdf7fA94Df7470D16cDDDDD`

## ⚖️ License

[MIT](LICENSE) 