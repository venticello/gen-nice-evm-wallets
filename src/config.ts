/**
 * The default filename for storing encrypted wallets.
 */
export const STORAGE_FILE = 'encrypted_wallets.json';

/**
 * The number of wallet generation attempts to buffer in memory within each worker
 * before sending stats to the main thread. A larger buffer can improve performance
 * by reducing message passing overhead but increases memory usage.
 */
export const BUFFER_SIZE = 20000;