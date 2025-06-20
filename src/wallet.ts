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
    workerData,
    MessageChannel
} from 'worker_threads';
import { cpus } from 'os';
import { BUFFER_SIZE, STORAGE_FILE } from './config';





interface WalletPattern {
    startsWith?: string;
    endsWith?: string;
    contains?: string;
    repeatingChars?: number;
    niceStartEnd?: boolean;
}

interface WorkerMessage {
    type: 'found' | 'stats' | 'complete' | 'error';
    data?: any;
}

interface WorkerStats {
    workerId: number;
    attempts: number;
    found: number;
    keysPerSecond: number;
}

interface GenerationStats {
    totalAttempts: number;
    totalFound: number;
    totalKeysPerSecond: number;
    elapsedTime: number;
    workers: WorkerStats[];
}

class BeautifulWalletChecker {
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

    static getPatternDescription(pattern: WalletPattern): string {
        let text_pattern = '';
        if (pattern.startsWith) {
            text_pattern = `starts with ${pattern.startsWith}`;
        }
        if (pattern.endsWith) {
            text_pattern += `ends with ${pattern.endsWith}`;
        }
        if (pattern.contains) {
            text_pattern += `contains ${pattern.contains}`;
        }
        if (text_pattern === '')
            return 'nice start...end pattern';
        else return text_pattern;
    }

}

// Worker code for wallet generation
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

    async generate(
        count: number = 1,
        pattern?: WalletPattern,
        numWorkers?: number,
        storageFile?: string
    ): Promise<void> {
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

    private updateTotalStats(): void {
        this.stats.totalAttempts = this.stats.workers.reduce((sum, w) => sum + w.attempts, 0);
        this.stats.totalKeysPerSecond = this.stats.workers.reduce((sum, w) => sum + w.keysPerSecond, 0);
        this.stats.elapsedTime = Date.now() - this.startTime;
    }

    private startStatsDisplay(): void {
        this.statsInterval = setInterval(() => {
            this.updateTotalStats();
            this.displayStats();
        }, 2000);
    }

    private displayStats(): void {
        // Clearing screen and displaying statistics
        process.stdout.write('\x1B[2J\x1B[0f');
        console.log('🔍 SEARCHING FOR BEAUTIFUL ADDRESSES - REAL-TIME STATISTICS\n');
        console.log(`⏱️ Working time: ${this.formatTime(this.stats.elapsedTime)}`);
        console.log(`🎯 Found: ${this.stats.totalFound} addresses`);
        console.log(`🔢 Total attempts: ${this.stats.totalAttempts.toLocaleString()}`);
        console.log(`⚡ Speed: ${this.stats.totalKeysPerSecond.toLocaleString()} keys/sec`);
        console.log(`📈 Efficiency: ${this.stats.totalAttempts > 0 ? ((this.stats.totalFound / this.stats.totalAttempts) * 100).toFixed(6) : '0.000000'}%\n`);

        console.log('👷 WORKER STATISTICS:');
        console.log('ID  | Attempts    | Found | Keys/sec');
        console.log('----|-------------|-------|----------');

        this.stats.workers.forEach(worker => {
            console.log(
                `${worker.workerId.toString().padStart(2)}  ` +
                `| ${worker.attempts.toLocaleString().padStart(10)} ` +
                `| ${worker.found.toString().padStart(7)} ` +
                `| ${worker.keysPerSecond.toLocaleString().padStart(8)}`
            );
        });
    }

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

    setMasterPassword(password: string): void {
        this.masterPassword = password;
    }

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



// CLI interface
async function main() {
    // Check if code is running as a worker
    if (!isMainThread) {
        workerFunction();
        return;
    }

    const manager = new WalletManager();

    try {
        const args = process.argv.slice(2);

        if (args.length === 0) {
            console.log(`
🌟 EVM Beautiful Wallet Generator & Manager (Multithreaded version)

Commands:
  generate <count> [options]    - Generate beautiful wallets
  list                         - List saved wallets  
  get <index>                  - Get private key
  export <index> [file]        - Export wallet
  
Generation options:
  --workers=N                  - Number of workers (default: CPU cores - 1)
  --startsWith=XXX            - Starts with characters
  --endsWith=XXX              - Ends with characters
  --contains=XXX              - Contains substring
  --repeating=N               - Repeating characters (minimum N in a row)
  --out=FILENAME              - Output file for wallets (default: encrypted_wallets.json)
  
Examples:
  node wallet.js generate 5
  node wallet.js generate 10 --workers=8 --startsWith=000
  node wallet.js generate 3 --endsWith=999 --contains=1234
  node wallet.js list
  node wallet.js get 1
      `);
            return;
        }

        const command = args[0];

        switch (command) {
            case 'generate': {
                const count = parseInt(args[1]) || 1;
                let numWorkers: number | undefined;
                let outFile: string | undefined;
    
                // Parsing pattern and options
                let pattern: WalletPattern = {};
                for (let i = 2; i < args.length; i++) {
                    const arg = args[i];
                    
                    if (arg.startsWith('--workers=')){
                        numWorkers = parseInt(arg.split('=')[1]);
                    }
                    if (arg.startsWith('--out=')) {
                        outFile = arg.split('=')[1];
                    }
                        if (arg.startsWith('--startsWith=')) {
                            pattern.startsWith = arg.split('=')[1];
                        }
                        if (arg.startsWith('--endsWith=')) {
                            pattern.endsWith = arg.split('=')[1];
                        }
                        if (arg.startsWith('--contains=')) {
                            pattern.contains = arg.split('=')[1];
                        }
                        if (arg.startsWith('--repeating=')) {
                            pattern.repeatingChars = parseInt(arg.split('=')[1]);
                        }
                    
                }
                if (!(pattern.contains || pattern.startsWith || pattern.endsWith || pattern.repeatingChars)){
                    pattern.niceStartEnd = true;
                }
                console.log('PATTERN', pattern);
                const masterPassword = await manager.setMasterPassword();
                const generator = new BeautifulWalletGenerator();
                generator.setMasterPassword(masterPassword);

                await generator.generate(count, pattern, numWorkers, outFile);
                break;
            }

            case 'list': {
                await manager.listCLI();
                break;
            }
            case 'get': {
                const index = parseInt(args[1]);
                if (!index) {
                    throw new Error('❌ Specify wallet number');
                }
                await manager.getCLI(index);
                break;
            }
            case 'export': {
                const index = parseInt(args[1]);
                if (!index) {
                    throw new Error('❌ Specify wallet number');
                }
                const outputFile = args[2];
                await manager.exportCLI(index, outputFile);
                break;
            }


            default:
                console.log('❌ Unknown command. Use without parameters for help.');
        }

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
