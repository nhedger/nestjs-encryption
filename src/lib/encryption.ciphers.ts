/**
 * The list of supported ciphers.
 */
export enum Cipher {
	AES_128_CBC = "aes-128-cbc",
	AES_256_CBC = "aes-256-cbc",
	AES_128_GCM = "aes-128-gcm",
	AES_256_GCM = "aes-256-gcm",
}

/**
 * A map of the supported ciphers to their characteristics.
 */
export const ciphers: Record<
	Cipher,
	{
		ivLength: number;
		keyLength: number;
		blockLength: number;
	}
> = {
	[Cipher.AES_128_CBC]: { keyLength: 16, ivLength: 16, blockLength: 16 },
	[Cipher.AES_256_CBC]: { keyLength: 32, ivLength: 16, blockLength: 16 },
	[Cipher.AES_128_GCM]: { keyLength: 16, ivLength: 12, blockLength: 16 },
	[Cipher.AES_256_GCM]: { keyLength: 32, ivLength: 12, blockLength: 16 },
};
