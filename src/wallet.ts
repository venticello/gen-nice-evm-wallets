// package.json dependencies needed:
// "viem": "^2.0.0",
// "crypto": "built-in Node.js module"

import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { promises as fs } from 'fs';
import { WalletManager } from './wallet-manager';
import { WalletStorage, EncryptedWallet } from './wallet-manager';

import { WalletCrypto } from './wallet-crypto';

import {
    Worker,
    isMainThread,
    parentPort,
    workerData
} from 'worker_threads';
import { cpus } from 'os';
import { BUFFER_SIZE, STORAGE_FILE } from './config';
// @ts-expect-error: No type declarations for yargs in this project
import yargs from 'yargs';
// @ts-expect-error: No type declarations for yargs/helpers in this project
import { hideBin } from 'yargs/helpers';


/**
 * Defines the pattern for a "beautiful" wallet address.
 */
interface WalletPattern {
    /** The address should start with this string (e.g., "000"). */
    startsWith?: string;
    /** The address should end with this string (e.g., "FFF"). */
    endsWith?: string;
    /** The address should contain this substring. */
    contains?: string;
    /** The address must contain at least this many repeating characters (e.g., 4 for "1111"). */
    repeatingChars?: number;
    /** The address should have a "nice" start/end pattern (e.g., 4+4 or 3+5 identical characters). */
    niceStartEnd?: boolean;
}

/**
 * Defines the structure of a message sent between the main thread and workers.
 */
interface WorkerMessage {
    /** The type of the message. */
    type: 'found' | 'stats' | 'complete' | 'error';
    /** The data payload of the message. */
    data?: any;
}

/**
 * Defines the statistics reported by a single worker.
 */
interface WorkerStats {
    /** The unique ID of the worker. */
    workerId: number;
    /** The number of addresses attempted by the worker. */
    attempts: number;
    /** The number of beautiful addresses found by the worker. */
    found: number;
    /** The current generation speed in keys per second. */
    keysPerSecond: number;
}

/**
 * Defines the aggregated statistics for the entire generation process.
 */
interface GenerationStats {
    /** Total number of addresses attempted by all workers. */
    totalAttempts: number;
    /** Total number of beautiful addresses found by all workers. */
    totalFound: number;
    /** Combined generation speed of all workers in keys per second. */
    totalKeysPerSecond: number;
    /** The total elapsed time in milliseconds. */
    elapsedTime: number;
    /** An array of statistics for each worker. */
    workers: WorkerStats[];
}

/**
 * A utility class to check if an EVM address matches a given beauty pattern.
 */
class BeautifulWalletChecker {
    /**
     * Checks if a given EVM address is "beautiful" based on a pattern.
     * @param address The EVM address string to check.
     * @param pattern The pattern to match against.
     * @returns True if the address matches the pattern, false otherwise.
     */
    static isBeautifulAddress(address: string, pattern?: WalletPattern): boolean {
        const addr = address.toLowerCase();
        if (!pattern || pattern?.niceStartEnd) {
            const len = addr.length;
            // 3 + 5 
            const isEndPattern =(((addr[2] === addr[3] && addr[3] === addr[4]) || (addr[3] === addr[4] && addr[4] === addr[5])) && addr[len-1] === addr[len-2] && addr[len-2] === addr[len-3] &&
                addr[len-3] === addr[len-4] && addr[len-4] === addr[len-5])

            // Fast 4+4 check
            const isStartEndPattern = (addr[2] === addr[3] && addr[3] === addr[4] && addr[4] === addr[5] &&
                addr[len-1] === addr[len-2] && addr[len-2] === addr[len-3] && addr[len-3] === addr[len-4])
            // Basic beauty criteria
            return (isEndPattern || isStartEndPattern);
        }

        // Custom pattern check
        if (pattern.startsWith && !addr.startsWith('0x' + pattern.startsWith.toLowerCase())) {
            return false;
        }
        if (pattern.endsWith && !addr.endsWith(pattern.endsWith.toLowerCase())) {
            return false;
        }
        if (pattern.contains && !addr.includes(pattern.contains.toLowerCase())) {
            return false;
        }
        if (pattern.repeatingChars) {
            const regex = new RegExp(`(.)\\1{${pattern.repeatingChars - 1},}`);
            if (!regex.test(addr.replace('0x', ''))) {
                return false;
            }
        }

        return true;
    }

    /**
     * Generates a human-readable description of a wallet pattern.
     * @param pattern The pattern to describe.
     * @returns A string describing the pattern.
     */
    static getPatternDescription(pattern: WalletPattern): string {
        const descriptions: string[] = [];
        if (pattern.startsWith) {
            descriptions.push(`starts with "${pattern.startsWith}"`);
        }
        if (pattern.endsWith) {
            descriptions.push(`ends with "${pattern.endsWith}"`);
        }
        if (pattern.contains) {
            descriptions.push(`contains "${pattern.contains}"`);
        }
        if (pattern.repeatingChars) {
            descriptions.push(`repeating chars >= ${pattern.repeatingChars}`);
        }

        if (descriptions.length > 0) {
            return descriptions.join(', ');
        }
        
        if (pattern.niceStartEnd) {
            return 'nice start/end (e.g. 4+4 or 3+5 equal chars)';
        }

        return 'default pattern';
    }

}

/**
 * The function executed by each worker thread to generate and check wallets.
 */
function workerFunction() {
    if (!parentPort || !workerData) return;

    const { workerId, pattern } = workerData;
    let attempts = 0;
    let found = 0;
    let lastStatsTime = Date.now();
    let lastStatsAttempts = 0;

    // Send statistics every 1000 attempts
    const sendStats = () => {
        const now = Date.now();
        const timeDiff = (now - lastStatsTime) / BUFFER_SIZE;
        const attemptsDiff = attempts - lastStatsAttempts;
        const keysPerSecond = attemptsDiff / timeDiff;

        parentPort!.postMessage({
            type: 'stats',
            data: {
                workerId,
                attempts,
                found,
                keysPerSecond: Math.round(keysPerSecond)
            }
        } as WorkerMessage);

        lastStatsTime = now;
        lastStatsAttempts = attempts;
    };

    // Main generation loop
    const generateLoop = () => {
        for (let i = 0; i < BUFFER_SIZE; i++) {
            try {
                const privateKey = generatePrivateKey();
                const account = privateKeyToAccount(privateKey);
                attempts++;

                if (BeautifulWalletChecker.isBeautifulAddress(account.address, pattern)) {
                    found++;

                    parentPort!.postMessage({
                        type: 'found',
                        data: {
                            address: account.address,
                            privateKey,
                            pattern:  BeautifulWalletChecker.getPatternDescription(pattern),
                            workerId
                        }
                    } as WorkerMessage);
                }
            } catch (error) {
                parentPort!.postMessage({
                    type: 'error',
                    data: { workerId, error: error instanceof Error ? error.message : 'Unknown error' }
                } as WorkerMessage);
            }
        }

        sendStats();
        setImmediate(generateLoop); // Non-blocking continuation
    };

    generateLoop();
}

/**
 * Orchestrates the multi-threaded generation of beautiful EVM wallets.
 */
class BeautifulWalletGenerator {
    private workers: Worker[] = [];
    private stats: GenerationStats = {
        totalAttempts: 0,
        totalFound: 0,
        totalKeysPerSecond: 0,
        elapsedTime: 0,
        workers: []
    };
    private startTime: number = 0;
    private statsInterval?: NodeJS.Timeout;
    private masterPassword: string = '';
    private storageFile: string = STORAGE_FILE;
    private searchPattern?: WalletPattern;

    /**
     * Starts the wallet generation process.
     * @param count The target number of wallets to find.
     * @param pattern The pattern to match.
     * @param numWorkers The number of worker threads to use. Defaults to CPU cores - 1.
     * @param storageFile The file to save the found wallets to.
     */
    async generate(
        count: number = 1,
        pattern?: WalletPattern,
        numWorkers?: number,
        storageFile?: string
    ): Promise<void> {
        this.searchPattern = pattern;
        if (storageFile) {
            this.storageFile = storageFile;
        }
        const workerCount = numWorkers || Math.max(1, cpus().length - 1);
        console.log(`🚀 Starting ${workerCount} workers for finding ${count} beautiful addresses...`);

        if (pattern) {
            console.log(`📋 Pattern:`, JSON.stringify(pattern, null, 2));
        }

        this.startTime = Date.now();
        this.stats = {
            totalAttempts: 0,
            totalFound: 0,
            totalKeysPerSecond: 0,
            elapsedTime: 0,
            workers: Array(workerCount).fill(0).map((_, i) => ({
                workerId: i,
                attempts: 0,
                found: 0,
                keysPerSecond: 0
            }))
        };

        // Creating workers
        for (let i = 0; i < workerCount; i++) {
            const worker = new Worker(__filename, {
                workerData: { workerId: i, pattern }
            });

            worker.on('message', async (message: WorkerMessage) => {
                try {
                    await this.handleWorkerMessage(message, count);
                } catch (error) {
                    console.error(`❌ Error processing message from worker:`, error);
                }
            });

            worker.on('error', (error) => {
                console.error(`❌ Worker ${i} error:`, error);
            });

            this.workers.push(worker);
        }

        // Starting statistics display
        this.startStatsDisplay();

        // Waiting for completion
        return new Promise((resolve) => {
            const checkCompletion = () => {
                if (this.stats.totalFound >= count) {
                    this.cleanup();
                    console.log(`\n🎉 Generation completed! Found ${count} addresses in ${this.formatTime(this.stats.elapsedTime)}`);
                    console.log(`📊 Total statistics: ${this.stats.totalAttempts.toLocaleString()} attempts, ${this.stats.totalKeysPerSecond.toLocaleString()} keys/sec`);
                    resolve();
                } else {
                    setTimeout(checkCompletion, 100);
                }
            };
            checkCompletion();
        });
    }

    /**
     * Handles messages received from worker threads.
     * @param message The message from the worker.
     * @param targetCount The total number of wallets to find.
     */
    private async handleWorkerMessage(message: WorkerMessage, targetCount: number): Promise<void> {
        switch (message.type) {
            case 'found':
                const wallet = message.data;
                await this.saveWalletImmediately(wallet);
                this.stats.totalFound++;
                console.log(`\n✅ Found address ${this.stats.totalFound}/${targetCount}: ${wallet.address} (${wallet.pattern}) [Worker ${wallet.workerId}]`);
                break;

            case 'stats':
                const workerStats = message.data as WorkerStats;
                this.stats.workers[workerStats.workerId] = workerStats;
                this.updateTotalStats();
                break;

            case 'error':
                console.error(`❌ Worker ${message.data.workerId} error:`, message.data.error);
                break;
        }
    }

    /**
     * Encrypts and saves a found wallet to the storage file immediately.
     * @param wallet The wallet data to save, including address, private key, and pattern.
     */
    private async saveWalletImmediately(wallet: { address: string; privateKey: string; pattern: string }): Promise<void> {
        try {
            // Loading existing storage
            let storage: WalletStorage;
            try {
                const data = await fs.readFile(this.storageFile, 'utf8');
                storage = JSON.parse(data);
            } catch {
                storage = { wallets: [], version: '1.0' };
            }

            // Encrypting private key
            const encrypted = await WalletCrypto.encrypt(wallet.privateKey, this.masterPassword);

            const encryptedWallet: EncryptedWallet = {
                address: wallet.address,
                encryptedPrivateKey: encrypted.encrypted + ':' + encrypted.authTag,
                salt: encrypted.salt,
                iv: encrypted.iv,
                createdAt: new Date().toISOString(),
                pattern: wallet.pattern
            };

            // Adding new wallet
            storage.wallets.push(encryptedWallet);

            // Saving updated storage
            await fs.writeFile(this.storageFile,
                JSON.stringify(storage, null, 2)
            );
        } catch (error) {
            console.error('❌ Wallet saving error:', error);
        }
    }

    /**
     * Updates the total generation statistics based on worker reports.
     */
    private updateTotalStats(): void {
        this.stats.totalAttempts = this.stats.workers.reduce((sum, w) => sum + w.attempts, 0);
        this.stats.totalKeysPerSecond = this.stats.workers.reduce((sum, w) => sum + w.keysPerSecond, 0);
        this.stats.elapsedTime = Date.now() - this.startTime;
    }

    /**
     * Starts the interval for displaying real-time statistics to the console.
     */
    private startStatsDisplay(): void {
        this.statsInterval = setInterval(() => {
            this.updateTotalStats();
            this.displayStats();
        }, 2000);
    }

    /**
     * Renders and displays the real-time statistics table in the console.
     */
    private displayStats(): void {
        // Clearing screen and displaying statistics
        process.stdout.write('\x1B[2J\x1B[0f');
        console.log('🔍 SEARCHING FOR BEAUTIFUL ADDRESSES - REAL-TIME STATISTICS\n');
        if (this.searchPattern) {
            console.log(`🔎 Pattern: ${BeautifulWalletChecker.getPatternDescription(this.searchPattern)}`);
        }
        console.log(`⏱️ Working time: ${this.formatTime(this.stats.elapsedTime)}`);
        console.log(`🎯 Found: ${this.stats.totalFound} addresses`);
        console.log(`🔢 Total attempts: ${this.stats.totalAttempts.toLocaleString()}`);
        console.log(`⚡ Speed: ${this.stats.totalKeysPerSecond.toLocaleString()} keys/sec`);
        console.log(`📈 Efficiency: ${this.stats.totalAttempts > 0 ? ((this.stats.totalFound / this.stats.totalAttempts) * 100).toFixed(6) : '0.000000'}%\n`);

        console.log('👷 WORKER STATISTICS:');

        const colWidths = {
            id: 4,
            attempts: 13,
            found: 7,
            keysPerSec: 10,
        };

        const header = [
            'ID'.padStart(colWidths.id),
            'Attempts'.padStart(colWidths.attempts),
            'Found'.padStart(colWidths.found),
            'Keys/sec'.padStart(colWidths.keysPerSec),
        ].join(' | ');

        const separator = Object.values(colWidths)
            .map(w => '-'.repeat(w))
            .join('-|-');
        
        console.log(header);
        console.log(separator);

        this.stats.workers.forEach(worker => {
            const row = [
                worker.workerId.toString().padStart(colWidths.id),
                worker.attempts.toLocaleString().padStart(colWidths.attempts),
                worker.found.toString().padStart(colWidths.found),
                worker.keysPerSecond.toLocaleString().padStart(colWidths.keysPerSec),
            ].join(' | ');
            console.log(row);
        });
    }

    /**
     * Formats a duration in milliseconds into a human-readable string (e.g., "1h 5m 10s").
     * @param ms The duration in milliseconds.
     * @returns The formatted time string.
     */
    private formatTime(ms: number): string {
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);

        if (hours > 0) {
            return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds % 60}s`;
        } else {
            return `${seconds}s`;
        }
    }

    /**
     * Sets the master password for encrypting wallets.
     * @param password The master password.
     */
    setMasterPassword(password: string): void {
        this.masterPassword = password;
    }

    /**
     * Terminates all worker threads and cleans up resources.
     */
    private cleanup(): void {
        if (this.statsInterval) {
            clearInterval(this.statsInterval);
        }

        this.workers.forEach(worker => {
            worker.terminate();
        });

        this.workers = [];
    }
}



/**
 * The main entry point for the CLI application.
 * Parses arguments and initiates wallet generation.
 */
async function main() {
    // Check if code is running as a worker
    if (!isMainThread) {
        workerFunction();
        return;
    }

    // Using yargs for powerful CLI argument parsing
    const argv = yargs(hideBin(process.argv))
        .scriptName("wallet")
        .usage('Usage: $0 generate <count> [options]')
        .command('generate <count>', 'Generate beautiful wallets', (y: any) => {
            return y
                .positional('count', {
                    describe: 'Number of wallets to generate',
                    type: 'number',
                    demandOption: true,
                })
                .option('workers', {
                    type: 'number',
                    describe: 'Number of workers (default: CPU cores - 1)',
                })
                .option('out', {
                    type: 'string',
                    describe: 'Output file for wallets',
                    default: STORAGE_FILE,
                })
                .option('startsWith', {
                    type: 'string',
                    describe: 'Address must start with these characters (e.g., "000")',
                })
                .option('endsWith', {
                    type: 'string',
                    describe: 'Address must end with these characters (e.g., "FFF")',
                })
                .option('contains', {
                    type: 'string',
                    describe: 'Address must contain this substring',
                })
                .option('repeating', {
                    type: 'number',
                    describe: 'Address must contain N repeating characters (e.g., 4 for "1111")',
                });
        })
        .demandCommand(1, 'The "generate" command is required.')
        .help()
        .alias('h', 'help')
        .strict()
        .parseSync();

    const manager = new WalletManager();

    try {
        const { count, workers, out, startsWith, endsWith, contains, repeating } = argv;

        const pattern: WalletPattern = {};
        if (startsWith) pattern.startsWith = startsWith as string;
        if (endsWith) pattern.endsWith = endsWith as string;
        if (contains) pattern.contains = contains as string;
        if (repeating) pattern.repeatingChars = repeating as number;

        if (Object.keys(pattern).length === 0) {
            pattern.niceStartEnd = true;
        }

        console.log('PATTERN', pattern);
        const masterPassword = await manager.setMasterPassword();
        const generator = new BeautifulWalletGenerator();
        generator.setMasterPassword(masterPassword);

        await generator.generate(count as number, pattern, workers, out);

    } catch (error) {
        console.error(error instanceof Error ? error.message : 'Unknown error');
        process.exit(1);
    } finally {
        manager.cleanup();
    }
}

// Run only if file is executed directly
if (require.main === module) {
    main().catch(console.error);
}

export {
    BeautifulWalletGenerator,
    WalletManager,
    WalletCrypto,
    WalletPattern,
    EncryptedWallet
};
