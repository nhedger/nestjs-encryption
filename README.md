# NestJS Encryption Module

**NestJS Encrytion** is NestJS 9+ module that provides _plug-and-play_ encryption
and decryption functionality to your NestJS application.

-   Uses `AES-256-CBC` by default, but supports [other ciphers](#supported-ciphers) as well.
-   Provides a keygen (API and CLI) for generating random and secure encryption keys.
-   Thoroughly tested.

## Installation

**NestJS Encryption** can be installed with your favorite package manager.

```bash
# NPM
npm install @hedger/nestjs-encryption

# Yarn
yarn add @hedger/nestjs-encryption

# PNPM
pnpm add @hedger/nestjs-encryption
```

## Setup

Setting up the module inside your NestJS application is a matter of registering
the module within your `AppModule`.

You may use either the `register` or `registerAsync` method to register the module in your `AppModule`.

### Using `register`

The `register` method is the simplest way to register the module.

```typescript
import { EncryptionModule, Cipher } from "@hedger/nestjs-encryption";

@Module({
	imports: [
		EncryptionModule.register({
			key: process.env.APP_KEY,
			cipher: Cipher.AES_256_CBC,
		}),
	],
})
export class AppModule {}
```

### Using `registerAsync`

The `registerAsync` method allows you to register the module asynchronously,
optionally resolving the encryption key from a configuration service. Here's
an example that uses the `ConfigService` from `@nestjs/config` to resolve the
encryption key from the `APP_KEY` environment variable.

```typescript
import { ConfigModule, ConfigService } from "@nestjs/config";
import { EncryptionModule, Cipher } from "@hedger/nestjs-encryption";

@Module({
	imports: [
		ConfigModule.forRoot(),
		EncryptionModule.registerAsync({
			useFactory: (config: ConfigService) => ({
				key: config.get("APP_KEY"),
				cipher: Cipher.AES_256_CBC,
			}),
			inject: [ConfigService],
		}),
	],
	controllers: [AppController],
	providers: [AppService],
})
export class AppModule {}
```

## Usage

Inject the EncryptionService in your service or controller.

```typescript
import { EncryptionService } from "@hedger/nestjs-encryption";

@Injectable()
export class FooService {
	constructor(private readonly crypto: EncryptionService) {}

	someMethod() {
		const encrypted = this.crypto.encrypt("some value");
		const decrypted = this.crypto.decrypt(encrypted);
	}
}
```

## Encryption key

This package expects the encryption key to be a base64-encoded string of N random
bytes, where N is the key length of the cipher you're using. For example, the
`aes-256-cbc` cipher has a key length of 32 bytes, so the encryption key must
be a base64-encoded string of 32 random bytes.

### Generating a key

This package provides CLI utility for generating random and secure encryption
keys.

```bash
# Generates a random key for the aes-256-cbc cipher (default)
npm exec nestjs-encryption-keygen
```

By default, the keygen generates keys for the `aes-256-cbc` cipher. You may
specify a different cipher by passing the `--cipher` option.

```bash
# Generates a random key for the aes-128-cbc cipher
npm exec nestjs-encryption-keygen --cipher aes-128-cbc
```

See the [Supported ciphers](#supported-ciphers) section for a list of supported
ciphers.

### Generating a key programmatically

Random and secure encryption keys may also be generated programmatically by
calling the `generateKey` method on the `EncryptionService` class.

```typescript
import { Cipher, EncryptionService } from "@hedger/nestjs-encryption";

// Pass the desired cipher as the first argument.
const key = EncryptionService.generateKey(Cipher.AES_256_CBC);
```

## Supported ciphers

The following ciphers are supported by this package.

-   `aes-256-cbc` (default)
-   `aes-256-gcm`
-   `aes-128-cbc`
-   `aes-128-gcm`

## License

Copyright © 2023, [Nicolas Hedger](https://github.com/nhedger). Released under the [MIT License](LICENSE.md).
