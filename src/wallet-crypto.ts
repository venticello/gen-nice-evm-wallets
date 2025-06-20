import {createHash, randomBytes, createCipheriv, createDecipheriv, scrypt} from 'crypto';
import { promisify } from 'util';
const scryptAsync = promisify(scrypt);

interface ScryptOptions {
    cost?: number;
    blockSize?: number;
    parallelization?: number;
    N?: number; // alias for cost
    r?: number; // alias for blockSize
    p?: number; // alias for parallelization
}

class WalletCrypto {
    private static readonly ALGORITHM = 'aes-256-gcm';
    private static readonly KEY_LENGTH = 32;
    private static readonly IV_LENGTH = 16;
    private static readonly SALT_LENGTH = 32;
    private static readonly SCRYPT_N = 16384;
    private static readonly SCRYPT_R = 8;
    private static readonly SCRYPT_P = 1;

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