import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";
import { Cipher, ciphers } from "../lib/encryption.ciphers";

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
	process.exit(1);
}

console.log(
	randomBytes(ciphers[cipher as Cipher].keyLength).toString("base64"),
);
