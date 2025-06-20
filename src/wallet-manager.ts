import fs from 'fs/promises';
import { WalletCrypto } from './wallet-crypto';
import { STORAGE_FILE } from './config';
import { getPassword } from './console-tools';
// @ts-expect-error: No type declarations for yargs in this project
import yargs from 'yargs';
// @ts-expect-error: No type declarations for yargs/helpers in this project
import { hideBin } from 'yargs/helpers';

/**
 * Encrypted wallet structure for storage.
 */
interface EncryptedWallet {
    address: string;
    encryptedPrivateKey: string;
    salt: string;
    iv: string;
    createdAt: string;
    pattern?: string;
}

/**
 * Wallet storage file structure.
 */
interface WalletStorage {
    wallets: EncryptedWallet[];
    version: string;
}

interface WalletData {
    index: number
    address: string;
    pattern: string;
    date: string;
    patternCount: number;
    isAfter0x: boolean;
}
/**
 * WalletManager handles encrypted wallet storage, listing, export, and private key retrieval.
 * Supports CLI interface for wallet management.
 */
class WalletManager {
    private storageFile: string;
    private masterPassword: string | null = null;

    /**
     * @param storageFile Optional path to the wallet storage file.
     */
    constructor(storageFile?: string) {
        this.storageFile = storageFile || STORAGE_FILE;
    }

    /**
     * Prompts user to set a master password (with confirmation).
     * @returns The set password.
     * @throws Error if passwords do not match or are too short.
     */
    async setMasterPassword(): Promise<string> {
        const password = await getPassword('🔐 Enter master password: ');
        const confirmPassword = await getPassword('🔐 Confirm master password: ');

        if (password !== confirmPassword) {
            throw new Error('❌ Passwords do not match!');
        }

        if (password.length < 8) {
            throw new Error('❌ Password must be at least 8 characters!');
        }

        this.masterPassword = password;
        console.log('✅ Master password set');
        return password;
    }

    /**
     * Prompts user for master password and authenticates.
     */
    async authenticateUser(): Promise<void> {
        const password = await getPassword('🔐 Enter master password to access: ');
        this.masterPassword = password;
        console.log('✅ Authentication successful');
    }

    /**
     * Lists all wallets in the storage file.
     */
    async listWallets(): Promise<void> {
        try {
            const data = await fs.readFile(this.storageFile, 'utf8');
            const storage: WalletStorage = JSON.parse(data);

            if (storage.wallets.length === 0) {
                console.log('📭 Wallets not found');
                return;
            }

            console.log(`\n📋 Found wallets: ${storage.wallets.length}\n`);
            console.log('№  | Address                                    | Pattern              | Creation Date');
            console.log('---|--------------------------------------------|--------------------- |------------------');

            storage.wallets.forEach((wallet, index) => {
                const date = new Date(wallet.createdAt).toLocaleDateString('ru-RU');
                const pattern = wallet.pattern || 'unknown';
                console.log(`${(index + 1).toString().padStart(2)} | ${wallet.address} | ${pattern.padEnd(20)} | ${date}`);
            });
        } catch (error) {
            console.log('📭 Wallets not found');
        }



    }
    async listSorted(){
        try {
            const data = await fs.readFile(this.storageFile, 'utf8');
            const storage: WalletStorage = JSON.parse(data);

            if (storage.wallets.length === 0) {
                console.log('📭 Wallets not found');
                return;
            }

            console.log(`\n📋 Found wallets: ${storage.wallets.length}\n`);
            console.log('№  | Address                                    | Pattern              | Creation Date');
            console.log('---|--------------------------------------------|--------------------- |------------------');
            const allWallets: WalletData[] = [];
            storage.wallets.forEach((wallet, index) => {
                const { count, addressPattern, isAfter0x } = countMaxRepeatingChars(wallet.address);
                const date = new Date(wallet.createdAt).toLocaleDateString('ru-RU');
                // console.log(`${(index + 1).toString().padStart(2)} | ${wallet.address} | ${addressPattern.padEnd(20)} | ${date}`);
                allWallets.push({
                    index:(index + 1),
                    address: wallet.address,
                    pattern: addressPattern,
                    patternCount: count,
                    date: date,
                    isAfter0x: isAfter0x,
                });
            });

            allWallets.sort((a, b) => {
                if (a.isAfter0x !== b.isAfter0x) {
                    return a.isAfter0x ? -1 : 1; // Адреса с паттерном после '0x' имеют приоритет
                }
                return b.patternCount - a.patternCount;
            });
            allWallets.forEach(wallet => {
                console.log(`${(wallet.index).toString().padStart(2)} | ${wallet.address} | ${wallet.pattern.padEnd(20)} | ${wallet.date}`);
            })
        } catch (error) {
            console.log('📭 Wallets not found');
        }
    }


    /**
     * Prints the private key for the wallet at the given index (1-based).
     * @param walletIndex Index of the wallet (1-based).
     */
    async getPrivateKey(walletIndex: number): Promise<void> {
        if (!this.masterPassword) {
            throw new Error('❌ Authentication required!');
        }

        try {
            const data = await fs.readFile(this.storageFile, 'utf8');
            const storage: WalletStorage = JSON.parse(data);

            if (walletIndex < 1 || walletIndex > storage.wallets.length) {
                throw new Error('❌ Invalid wallet number!');
            }

            const wallet = storage.wallets[walletIndex - 1];
            const [encryptedData, authTag] = wallet.encryptedPrivateKey.split(':');

            const privateKey = await WalletCrypto.decrypt(
                encryptedData,
                this.masterPassword,
                wallet.salt,
                wallet.iv,
                authTag
            );

            console.log(`\n🔑 Private key for ${wallet.address}:`);
            console.log(`${privateKey}\n`);
            console.log('⚠️  WARNING: Do not share this key with anyone!');
            setTimeout(() => {
                console.clear();
                // console.log('\033[2J');
            }, 20000);
            setTimeout(() => {
                console.log('\n🧹 Key automatically removed from memory');
            }, 21000);


        } catch (error) {
            if (error instanceof Error) {
                throw new Error(`❌ Decryption error: ${error.message}`);
            }
            throw error;
        }
    }

    /**
     * Exports the wallet at the given index to a file (unencrypted private key!).
     * @param walletIndex Index of the wallet (1-based).
     * @param outputFile Optional output file name.
     */
    async exportWallet(walletIndex: number, outputFile?: string): Promise<void> {
        if (!this.masterPassword) {
            throw new Error('❌ Authentication required!');
        }

        try {
            const data = await fs.readFile(this.storageFile, 'utf8');
            const storage: WalletStorage = JSON.parse(data);

            if (walletIndex < 1 || walletIndex > storage.wallets.length) {
                throw new Error('❌ Invalid wallet number!');
            }

            const wallet = storage.wallets[walletIndex - 1];
            const [encryptedData, authTag] = wallet.encryptedPrivateKey.split(':');

            const privateKey = await WalletCrypto.decrypt(
                encryptedData,
                this.masterPassword,
                wallet.salt,
                wallet.iv,
                authTag
            );

            const exportData = {
                address: wallet.address,
                privateKey: privateKey,
                pattern: wallet.pattern,
                createdAt: wallet.createdAt
            };

            const fileName = outputFile || `wallet_${wallet.address.slice(2, 8)}.json`;
            await fs.writeFile(fileName, JSON.stringify(exportData, null, 2));

            console.log(`✅ Wallet exported to file: ${fileName}`);
            console.log('⚠️  WARNING: File contains unencrypted private key!');

        } catch (error) {
            if (error instanceof Error) {
                throw new Error(`❌ Export error: ${error.message}`);
            }
            throw error;
        }
    }

    /**
     * CLI: Lists wallets with error handling.
     */
    async listCLI(): Promise<void> {
        try {
            await this.listWallets();
        } catch (error) {
            console.error(error instanceof Error ? error.message : error);
        }
    }

    /**
     * CLI: Authenticates and prints private key for wallet at index.
     * @param index Wallet index (1-based).
     */
    async getCLI(index: number): Promise<void> {
        try {
            await this.authenticateUser();
            await this.getPrivateKey(index);
        } catch (error) {
            console.error(error instanceof Error ? error.message : error);
        }
    }

    /**
     * CLI: Authenticates and exports wallet at index.
     * @param index Wallet index (1-based).
     * @param outputFile Optional output file name.
     */
    async exportCLI(index: number, outputFile?: string): Promise<void> {
        try {
            await this.authenticateUser();
            await this.exportWallet(index, outputFile);
        } catch (error) {
            console.error(error instanceof Error ? error.message : error);
        }
    }

    /**
     * Clears master password from memory.
     */
    cleanup(): void {
        if (this.masterPassword) {
            this.masterPassword = '0'.repeat(this.masterPassword.length);
            this.masterPassword = null;
        }
    }

    /**
     * Runs the WalletManager CLI interface.
     * Supports commands: list, get <index>, export <index> [file].
     * @example
     *   node wallet-manager.js list --file=wallets.json
     *   node wallet-manager.js get 1
     *   node wallet-manager.js export 2 exported.json
     */
    static async runCLI() {
        const argv = yargs(hideBin(process.argv))
            .scriptName('wallet-manager')
            .usage('$0 <cmd> [args]')
            .command('list', 'List all wallets', (y: any) => y.option('file', { type: 'string', describe: 'Wallet storage file' }))
            .command('slist', 'Sorted list all wallets', (y: any) => y.option('file', { type: 'string', describe: 'Wallet storage file' }))
            .command('get <index>', 'Show private key for wallet', (y: any) => y
                .positional('index', { type: 'number', describe: 'Wallet index (1-based)' })
                .option('file', { type: 'string', describe: 'Wallet storage file' })
            )
            .command('export <index> [output]', 'Export wallet to file', (y: any) => y
                .positional('index', { type: 'number', describe: 'Wallet index (1-based)' })
                .positional('output', { type: 'string', describe: 'Output file' })
                .option('file', { type: 'string', describe: 'Wallet storage file' })
            )
            .demandCommand(1, 'You need at least one command before moving on')
            .help()
            .strict()
            .parseSync();

        let storageFile = argv.file as string | undefined;
        const manager = new WalletManager(storageFile);
        const cmd = argv._[0];
        if (cmd === 'list') {
            await manager.listCLI();
        } else if (cmd ==='slist'){
            try {
                await manager.listSorted();
            } catch (error) {
                console.error(error instanceof Error ? error.message : error);
            }
        } else if (cmd === 'get') {
            const index = argv.index as number;
            if (!index || index < 1) {
                console.error('❌ Specify a valid wallet number (integer > 0)');
                process.exit(1);
            }
            await manager.getCLI(index);
        } else if (cmd === 'export') {
            const index = argv.index as number;
            const output = argv.output as string | undefined;
            if (!index || index < 1) {
                console.error('❌ Specify a valid wallet number (integer > 0)');
                process.exit(1);
            }
            await manager.exportCLI(index, output);
        } else {
            console.error('❌ Unknown command. Use --help for usage.');
            process.exit(1);
        }
    }
}

export { WalletManager, EncryptedWallet, WalletStorage };

function countMaxRepeatingChars(address: string): { count: number; addressPattern: string; isAfter0x: boolean } {
    const addr = address.toLowerCase();
    const originalAddr = address; // Сохраняем оригинальный адрес для проверки после '0x'
    let maxCount = 0;
    let maxPattern = '';
    let isAfter0x = false;

    // Проверяем последовательность после '0x'
    if (originalAddr.startsWith('0x')) {
        const after0x = addr.slice(2); // Получаем все символы после '0x'
        let currentChar = after0x[0];
        let currentCount = 1;
        let currentPattern = currentChar;

        // Проверяем последовательность после '0x'
        for (let i = 1; i < after0x.length; i++) {
            if (after0x[i].toLowerCase() === currentChar.toLowerCase()) {
                currentCount++;
                currentPattern += after0x[i];
            } else {
                break;
            }
        }

        if (currentCount >= 3) { // Минимум 3 символа для паттерна после 0x
            maxCount = currentCount;
            maxPattern = currentPattern;
            isAfter0x = true;
        }
    }

    // Проверяем последовательности в конце адреса
    let endChar = addr[addr.length - 1];
    let endCount = 1;
    let endPattern = endChar;

    for (let i = addr.length - 2; i >= 0; i--) {
        if (addr[i].toLowerCase() === endChar.toLowerCase()) {
            endCount++;
            endPattern = addr[i] + endPattern;
        } else {
            break;
        }
    }

    // Если нашли последовательность в конце и она длиннее или равна текущей максимальной
    if (endCount >= 3) {
        maxCount += endCount;
        maxPattern += '...'+endPattern;
        // isAfter0x = false;
    }

    return { count: maxCount, addressPattern: maxPattern, isAfter0x };
}

// CLI entrypoint for direct execution
if (require.main === module) {
    WalletManager.runCLI().catch(err => {
        console.error(err instanceof Error ? err.message : err);
        process.exit(1);
    });
}