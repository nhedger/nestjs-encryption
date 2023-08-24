import { parseArgs } from "node:util";
import { EncryptionService, Cipher, ciphers } from "../lib";

const {
	values: { cipher },
} = parseArgs({
	options: {
		cipher: {
			type: "string",
			short: "c",
			default: Cipher.AES_256_CBC,
		},
	},
});

// If the provided cipher is not in the list of supported ciphers, print a warning.
if (!ciphers[cipher as Cipher]) {
	const supportedCiphers = Object.keys(ciphers).join(", ");
	console.error(
		`The provided cipher "${cipher}" is not supported. Supported ciphers are: ${supportedCiphers}`,
	);
}

console.log(EncryptionService.generateKey(cipher as Cipher));
