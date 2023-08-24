import { describe, expect, it, test } from "vitest";
import { Cipher, ciphers } from "@/lib/encryption.ciphers";
import { type AEADPayload, EncryptionService } from "@/lib/encryption.service";

describe("Encryption Service", () => {
	it("encrypts and decrypts strings.", () => {
		const encryptionService = new EncryptionService({
			key: EncryptionService.generateKey(Cipher.AES_256_CBC),
			cipher: Cipher.AES_256_CBC,
		});

		const plaintext = "Hello, world!";
		const encrypted = encryptionService.encrypt(plaintext);
		const decrypted = encryptionService.decrypt(encrypted);

		expect(decrypted).toBe(plaintext);
	});

	it("fails to initialize if the key is not a valid base64-encoded string.", () => {
		expect(() => {
			new EncryptionService({ key: "invalid key", cipher: Cipher.AES_256_CBC });
		}).toThrowError(/The key must be a valid base64-encoded string/);
	});

	it("fails to initialize if the key is not of the correct length for the cipher.", () => {
		expect(() => {
			new EncryptionService({
				key: Buffer.from("invalid key").toString("base64"),
				cipher: Cipher.AES_256_CBC,
			});
		}).toThrowError(/The decoded key must be \d+ bytes long./);
	});

	it("fails to decrypt a payload if it is not a valid base64-encoded string", () => {
		const encryptionService = new EncryptionService({
			key: EncryptionService.generateKey(Cipher.AES_256_CBC),
			cipher: Cipher.AES_256_CBC,
		});

		expect(() => {
			encryptionService.decrypt("invalid payload");
		}).toThrowError(
			/The encoded AEAD payload is not a valid base64-encoded string./,
		);
	});

	it("fails to decrypt a payload if its decoded value is not a valid JSON string", () => {
		const encryptionService = new EncryptionService({
			key: EncryptionService.generateKey(Cipher.AES_256_CBC),
			cipher: Cipher.AES_256_CBC,
		});

		expect(() => {
			encryptionService.decrypt("bm90IHZhbGlkIGpzb24="); // not valid json
		}).toThrowError(/The decoded AEAD payload is not a valid JSON string./);
	});

	it("fails to decrypt a payload if the hmac does not match.", () => {
		const encryptionService = new EncryptionService({
			key: "M/Cn64TCeBOqzmriwFpX3H0QP1RcF7eel7KkSWtpx5g=",
			cipher: Cipher.AES_256_CBC,
		});

		expect(() => {
			encryptionService.decrypt(
				"eyJpdiI6InlRN3VmMEg5VFdjdFc5dEJiT0FKRWc9PSIsImhtYWMiOiJQTWVDbnB2WEJUWXZ3MTh6cDIyMmxnTzJCTjAyN2xUZC9sUFdNSUhndEhnPSIsImNpcGhlclRleHQiOiJxTWY0Q2Q2b1ZxMmZsL2dRaFpCR3FRPT0ifQ==",
			);
		}).toThrowError(/The signature does not match the encrypted payload/);
	});

	it("fails to decrypt if the IV is not a valid base64-encoded string.", () => {
		const encryptionService = new EncryptionService({
			key: EncryptionService.generateKey(Cipher.AES_256_CBC),
			cipher: Cipher.AES_256_CBC,
		});

		const encrypted = encryptionService.encrypt("Hello, world!");

		// Decode the payload and break the iv
		const payload = JSON.parse(
			Buffer.from(encrypted, "base64").toString("utf-8"),
		) as AEADPayload;

		payload.iv = "invalid iv";

		expect(() => {
			encryptionService.decrypt(
				Buffer.from(JSON.stringify(payload)).toString("base64"),
			);
		}).toThrowError(/The IV is not a valid base64-encoded string./);
	});

	it("fails to decrypt if the IV length is not correct for the cipher", () => {
		const encryptionService = new EncryptionService({
			key: EncryptionService.generateKey(Cipher.AES_256_CBC),
			cipher: Cipher.AES_256_CBC,
		});

		const encrypted = encryptionService.encrypt("Hello, world!");

		// Decode the payload and change the IV length
		const payload = JSON.parse(
			Buffer.from(encrypted, "base64").toString("utf-8"),
		) as AEADPayload;

		payload.iv = payload.iv = Buffer.from("invalid iv").toString("base64");

		expect(() => {
			encryptionService.decrypt(
				Buffer.from(JSON.stringify(payload)).toString("base64"),
			);
		}).toThrowError(
			/The decoded IV is not the correct length. Expected \d+ bytes, got \d+ bytes./,
		);
	});

	it("fails to decrypt if the HMAC is not a valid base64-encoded string.", () => {
		const encryptionService = new EncryptionService({
			key: EncryptionService.generateKey(Cipher.AES_256_CBC),
			cipher: Cipher.AES_256_CBC,
		});

		const encrypted = encryptionService.encrypt("Hello, world!");

		// Decode the payload and break the hmac
		const payload = JSON.parse(
			Buffer.from(encrypted, "base64").toString("utf-8"),
		) as AEADPayload;

		payload.hmac = "invalid hmac";

		expect(() => {
			encryptionService.decrypt(
				Buffer.from(JSON.stringify(payload)).toString("base64"),
			);
		}).toThrowError(/The HMAC is not a valid base64-encoded string/);
	});

	it("fails to decrypt if the the length of the ciphertext is not a multiple of the cipher's block length", () => {
		const encryptionService = new EncryptionService({
			key: EncryptionService.generateKey(Cipher.AES_256_CBC),
			cipher: Cipher.AES_256_CBC,
		});

		const encrypted = encryptionService.encrypt("Hello, world!");

		// Decode the payload and break the ciphertext
		const payload = JSON.parse(
			Buffer.from(encrypted, "base64").toString("utf-8"),
		) as AEADPayload;

		payload.cipherText = Buffer.from("invalid ciphertext").toString("base64");

		expect(() => {
			encryptionService.decrypt(
				Buffer.from(JSON.stringify(payload)).toString("base64"),
			);
		}).toThrowError(
			/The length of the decoded ciphertext is not a multiple of the cipher's block length/,
		);
	});

	it("fails to decrypt if the cipherText is not a valid base64-encoded string.", () => {
		const encryptionService = new EncryptionService({
			key: EncryptionService.generateKey(Cipher.AES_256_CBC),
			cipher: Cipher.AES_256_CBC,
		});

		const encrypted = encryptionService.encrypt("Hello, world!");

		// Decode the payload and break the ciphertext
		const payload = JSON.parse(
			Buffer.from(encrypted, "base64").toString("utf-8"),
		) as AEADPayload;

		payload.cipherText = "invalid ciphertext";

		expect(() => {
			encryptionService.decrypt(
				Buffer.from(JSON.stringify(payload)).toString("base64"),
			);
		}).toThrowError(
			/The encoded ciphertext is not a valid base64-encoded string/,
		);
	});

	test.each(["iv", "cipherText", "hmac"])(
		"fails to decrypt a payload if the %s is missing.",
		(missing) => {
			const encryptionService = new EncryptionService({
				key: EncryptionService.generateKey(Cipher.AES_256_CBC),
				cipher: Cipher.AES_256_CBC,
			});

			const payload: AEADPayload = {
				iv: "iv",
				cipherText: "cipherText",
				hmac: "hmac",
			};

			delete payload[missing as keyof AEADPayload];

			expect(() => {
				encryptionService.decrypt(
					Buffer.from(JSON.stringify(payload)).toString("base64"),
				);
			}).toThrowError(/The AEAD payload is missing the (.+) field./);
		},
	);

	test.each(Object.entries(ciphers).map(([k, v]) => [v.keyLength, k]))(
		"generates a key of %i bytes for the %s cipher.",
		(keyLength, cipher) => {
			const key = EncryptionService.generateKey(cipher as Cipher);
			expect(Buffer.from(key, "base64")).toHaveLength(keyLength);
		},
	);
});
