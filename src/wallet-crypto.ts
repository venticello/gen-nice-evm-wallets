import {createHash, randomBytes, createCipheriv, createDecipheriv, scrypt} from 'crypto';
import { promisify } from 'util';
const scryptAsync = promisify(scrypt);

/**
 * Defines the options for the scrypt key derivation function.
 * @see https://nodejs.org/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback
 */
interface ScryptOptions {
    /** CPU/memory cost factor. */
    cost?: number;
    /** Block size parameter. */
    blockSize?: number;
    /** Parallelization factor. */
    parallelization?: number;
    /** Alias for `cost`. */
    N?: number;
    /** Alias for `blockSize`. */
    r?: number;
    /** Alias for `parallelization`. */
    p?: number;
}

/**
 * Handles encryption and decryption of wallet data using AES-256-GCM and scrypt.
 */
class WalletCrypto {
    private static readonly ALGORITHM = 'aes-256-gcm';
    private static readonly KEY_LENGTH = 32;
    private static readonly IV_LENGTH = 16;
    private static readonly SALT_LENGTH = 32;
    private static readonly SCRYPT_N = 16384;
    private static readonly SCRYPT_R = 8;
    private static readonly SCRYPT_P = 1;

    /**
     * Derives a cryptographic key from a password and salt using scrypt.
     * @param password The user's password.
     * @param salt A random salt.
     * @returns A promise that resolves to the derived key as a Buffer.
     */
    static async deriveKey(password: string, salt: Buffer): Promise<Buffer> {
        const options: ScryptOptions = {
            N: this.SCRYPT_N,
            r: this.SCRYPT_R,
            p: this.SCRYPT_P,
        };
        // without as any, expect error: Node.js does support 4 arguments
        return await (scryptAsync as any)(
            password,
            salt,
            this.KEY_LENGTH,
            options
        ) as Buffer;
    }

    /**
     * Encrypts a string using AES-256-GCM.
     * @param data The string to encrypt (e.g., a private key).
     * @param password The password to use for key derivation.
     * @returns A promise that resolves to an object containing the encrypted data and necessary metadata (salt, iv, authTag).
     */
    static async encrypt(data: string, password: string): Promise<{
        encrypted: string;
        salt: string;
        iv: string;
        authTag: string;
    }> {
        const salt = randomBytes(this.SALT_LENGTH);
        const iv = randomBytes(this.IV_LENGTH);
        const key = await this.deriveKey(password, salt);

        const cipher = createCipheriv(this.ALGORITHM, key, iv);
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const authTag = cipher.getAuthTag();

        return {
            encrypted,
            salt: salt.toString('hex'),
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex')
        };
    }

    /**
     * Decrypts an AES-256-GCM encrypted string.
     * @param encryptedData The hex-encoded encrypted data.
     * @param password The password used for encryption.
     * @param salt The hex-encoded salt used during key derivation.
     * @param iv The hex-encoded initialization vector.
     * @param authTag The hex-encoded GCM authentication tag.
     * @returns A promise that resolves to the decrypted string.
     */
    static async decrypt(
        encryptedData: string,
        password: string,
        salt: string,
        iv: string,
        authTag: string
    ): Promise<string> {
        const saltBuffer = Buffer.from(salt, 'hex');
        const ivBuffer = Buffer.from(iv, 'hex');
        const authTagBuffer = Buffer.from(authTag, 'hex');
        const key = await this.deriveKey(password, saltBuffer);

        const decipher = createDecipheriv(this.ALGORITHM, key, ivBuffer);
        decipher.setAuthTag(authTagBuffer);

        let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }
}

export {
    WalletCrypto,
};