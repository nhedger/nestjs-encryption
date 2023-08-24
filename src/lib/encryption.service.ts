import { Cipher, ciphers } from "./encryption.ciphers";
import { Inject, Injectable } from "@nestjs/common";
import {
	createCipheriv,
	createDecipheriv,
	createHmac,
	randomBytes,
	timingSafeEqual,
} from "node:crypto";
import { UnableToDecrypt, UnableToInitialize } from "./encryption.errors";
import {
	MODULE_OPTIONS_TOKEN,
	type EncryptionModuleOptions,
} from "./encryption.module";

/**
 * Authenticated Encryption with Associated Data Payload
 */
export interface AEADPayload<TFormat = string | Buffer> {
	iv: TFormat;
	hmac: TFormat;
	cipherText: TFormat;
}

@Injectable()
export class EncryptionService {
	/**
	 * The secret key used for encrypting and decrypting data.
	 */
	private readonly key: Buffer;

	/**
	 * The cipher used for encrypting and decrypting data.
	 */
	private readonly cipher: Cipher;

	/**
	 * Initializes the encryption service.
	 *
	 * The secret key must be provided as a base64-encoded string that represents a set of N bytes.
	 * The number of bytes required depends on the cipher being used. A random key can be generated
	 * using the static {@link generateKey} method.
	 *
	 * @param {string} key The secret key to use for encrypting and decrypting data.
	 * @param {Cipher} cipher The cipher to use for encrypting and decrypting data.
	 *
	 * @throws {UnableToInitialize} If the encryption service cannot be initialized.
	 */
	constructor(
		@Inject(MODULE_OPTIONS_TOKEN)
		options: EncryptionModuleOptions,
	) {
		try {
			this.cipher = options.cipher ?? Cipher.AES_256_CBC;
			this.key = this.decodeKey(options.key);
		} catch (e) {
			throw new UnableToInitialize((e as Error).message);
		}
	}

	/**
	 * Encrypts the given plaintext.
	 *
	 * This method encrypts the given plaintext using the cipher and secret key provided to the
	 * constructor. The encrypted data is returned as a base64-encoded AEAD payload, which is the
	 * format expected by the {@link decrypt} method.
	 *
	 * @param {string} plaintext The plaintext to encrypt.
	 *
	 * @returns {string} The encrypted value, AKA the base64-encoded AEAD payload.
	 */
	public encrypt(plaintext: string): string {
		// Create a random initialization vector.
		const iv = this.generateIV();

		// Create the cipher and encrypt the plaintext.
		const cipher = createCipheriv(this.cipher, this.key, iv);
		const cipherText = Buffer.concat([
			cipher.update(plaintext),
			cipher.final(),
		]);

		// Compute the HMAC based on the ciphertext and initialization vector.
		const hmac = this.computeHmac(cipherText, iv);

		// Build the encrypted package.
		const aead: AEADPayload<string> = {
			iv: iv.toString("base64"),
			hmac: hmac.toString("base64"),
			cipherText: cipherText.toString("base64"),
		};

		// Serialize and encode the encrypted package.
		return Buffer.from(JSON.stringify(aead)).toString("base64");
	}

	/**
	 * Decrypts a value
	 *
	 * This method decrypts the ciphertext contained in the given base64-encoded AEAD payload.
	 *
	 * @param {string} encrypted The encrypted value, AKA the base64-encoded AEAD payload.
	 *
	 * @returns {string} The decrypted plaintext.
	 *
	 * @throws {UnableToDecrypt} Thrown when the given ciphertext cannot be decrypted.
	 */
	public decrypt(encrypted: string): string {
		try {
			const { iv, cipherText, hmac } = this.decodeAEADPayload(encrypted);
			this.verifyHmac(cipherText, iv, hmac);
			const decipher = createDecipheriv(this.cipher, this.key, iv);
			const decrypted = Buffer.concat([
				decipher.update(cipherText),
				decipher.final(),
			]);
			return decrypted.toString();
		} catch (e: unknown) {
			throw new UnableToDecrypt((e as Error).message);
		}
	}

	/**
	 * Decodes the AEAD payload
	 *
	 * This method decodes the given base64-encoded AEAD payload into an {@link AEADPayload}
	 * object and validates that it contains all the required fields.
	 *
	 * @param {string} encodedPayload The base64-encoded encrypted payload.
	 *
	 * @returns {AEADPayload<Buffer>} The decoded encrypted payload.
	 *
	 * @throws {Error} Thrown when the AEAD payload cannot be decoded.
	 * @throws {Error} Thrown when the decoded AEAD payload is not a valid JSON string.
	 * @throws {Error} Thrown when the AEAD payload is missing a required field.
	 */
	private decodeAEADPayload(encodedPayload: string): AEADPayload<Buffer> {
		const payload = Buffer.from(encodedPayload, "base64");

		if (payload.toString("base64") !== encodedPayload) {
			throw new Error(
				"The encoded AEAD payload is not a valid base64-encoded string.",
			);
		}

		let deserializedPkg;
		try {
			deserializedPkg = JSON.parse(payload.toString());
		} catch (e) {
			throw new Error("The decoded AEAD payload is not a valid JSON string.");
		}

		for (const field of ["iv", "cipherText", "hmac"]) {
			if (!Object.hasOwn(deserializedPkg, field)) {
				throw new Error(`The AEAD payload is missing the ${field} field.`);
			}
		}

		return {
			iv: this.decodeIV(deserializedPkg.iv),
			hmac: this.decodeHmac(deserializedPkg.hmac),
			cipherText: this.decodeCipherText(deserializedPkg.cipherText),
		};
	}

	/**
	 * Decodes the initialization vector.
	 *
	 * This method decodes the given base64-encoded initialization vector into a Buffer and
	 * validates that it is the correct length for the cipher being used.
	 *
	 * @param {string} encodedIV The base64-encoded initialization vector.
	 *
	 * @returns {Buffer} The decoded initialization vector.
	 *
	 * @throws {Error} Thrown when the initialization vector is not a valid base64-encoded string.
	 * @throws {Error} Thrown when the initialization vector does not have the correct length.
	 */
	private decodeIV(encodedIV: string): Buffer {
		const iv = Buffer.from(encodedIV, "base64");

		if (iv.toString("base64") !== encodedIV) {
			throw new Error("The IV is not a valid base64-encoded string.");
		}

		if (iv.length !== ciphers[this.cipher].ivLength) {
			throw new Error(
				`The decoded IV is not the correct length. Expected ${
					ciphers[this.cipher].ivLength
				} bytes, got ${iv.length} bytes.`,
			);
		}

		return iv;
	}

	/**
	 * Decodes the HMAC.
	 *
	 * This method decodes the given base64-encoded HMAC into a Buffer.
	 *
	 * @param {string} encodedHmac The base64-encoded HMAC.
	 *
	 * @returns {Buffer} The decoded HMAC.
	 *
	 * @throws {Error} Thrown when the HMAC is not a valid base64-encoded string.
	 */
	private decodeHmac(encodedHmac: string): Buffer {
		const hmac = Buffer.from(encodedHmac, "base64");

		if (hmac.toString("base64") !== encodedHmac) {
			throw new Error("The HMAC is not a valid base64-encoded string.");
		}

		return hmac;
	}

	/**
	 * Decodes the given base64-encoded ciphertext into a Buffer.
	 *
	 * This method decodes the given base64-encoded ciphertext into a Buffer and validates that the
	 * decoded length is a multiple of the cipher's block length.
	 *
	 * @param {string} encodedCipherText The base64-encoded ciphertext.
	 *
	 * @throws {Error} Thrown when the ciphertext is not a valid base64-encoded string.
	 * @throws {Error} Thrown when the ciphertext is not a multiple of the cipher's block length.
	 *
	 * @returns {Buffer} The decoded ciphertext.
	 */
	private decodeCipherText(encodedCipherText: string): Buffer {
		const cipherText = Buffer.from(encodedCipherText, "base64");

		if (cipherText.toString("base64") !== encodedCipherText) {
			throw new Error(
				"The encoded ciphertext is not a valid base64-encoded string.",
			);
		}

		if (cipherText.length % ciphers[this.cipher].blockLength !== 0) {
			throw new Error(
				"The length of the decoded ciphertext is not a multiple of the cipher's block length.",
			);
		}

		return cipherText;
	}

	/**
	 * Generates a random key for the given cipher.
	 *
	 * This method generates a random secret key for the given cipher and returns it as a
	 * base64-encoded string.
	 *
	 * @param {Cipher} cipher The cipher for which to generate a key.
	 *
	 * @returns {string} The generated secret key.
	 */
	public static generateKey(cipher: Cipher): string {
		return randomBytes(ciphers[cipher].keyLength).toString("base64");
	}

	/**
	 * Decodes the given base64-encoded secret key into a Buffer.
	 *
	 * This method decodes the given base64-encoded key into a Buffer and validates that it is the
	 * correct length for the cipher being used.
	 *
	 * @param {string} key The base64-encoded secret key.
	 *
	 * @returns {Buffer} The decoded secret key.
	 *
	 * @throws {Error} Thrown when the key is not a valid base64-encoded string.
	 * @throws {Error} Thrown when the key does not have the correct length.
	 */
	private decodeKey(key: string): Buffer {
		const decodedKey = Buffer.from(key, "base64");

		if (decodedKey.toString("base64") !== key) {
			throw new Error("The key must be a valid base64-encoded string.");
		}

		if (decodedKey.length !== ciphers[this.cipher].keyLength) {
			throw new Error(
				`The decoded key must be ${ciphers[this.cipher].keyLength} bytes long.`,
			);
		}

		return decodedKey;
	}

	/**
	 * Generates a random initialization vector.
	 *
	 * This method generates a random initialization vector tailored for the cipher being used.
	 *
	 * @returns {Buffer} The generated initialization vector.
	 */
	private generateIV(): Buffer {
		return randomBytes(ciphers[this.cipher].ivLength);
	}

	/**
	 * Computes an HMAC.
	 *
	 * This method computes an HMAC for the given ciphertext and initialization vector.
	 *
	 * @param {Buffer} cipherText The ciphertext.
	 * @param {Buffer} iv The initialization vector.
	 *
	 * @returns {Buffer} The computed HMAC.
	 */
	private computeHmac(cipherText: Buffer, iv: Buffer): Buffer {
		return createHmac("sha256", this.key)
			.update(cipherText)
			.update(iv)
			.digest();
	}

	/**
	 * Verifies an HMAC.
	 *
	 * This method verifies that the given HMAC matches the HMAC computed for
	 * the given ciphertext and initialization vector.
	 *
	 * @param {Buffer} cipherText The ciphertext.
	 * @param {Buffer} iv The initialization vector.
	 * @param {string} hmac The base64-encoded HMAC to compare against.
	 *
	 * @throws {Error} Thrown when the HMAC does not match.
	 */
	private verifyHmac(cipherText: Buffer, iv: Buffer, hmac: Buffer): void {
		if (!timingSafeEqual(this.computeHmac(cipherText, iv), hmac)) {
			throw new Error("The signature does not match the encrypted payload.");
		}
	}
}
