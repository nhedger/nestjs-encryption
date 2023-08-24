import { Module } from "@nestjs/common";
import type { Cipher } from "./encryption.ciphers";
import { EncryptionService } from "./encryption.service";
import { ConfigurableModuleClass } from "./encryption.module-definition";

export interface EncryptionModuleOptions {
	key: string;
	cipher?: Cipher;
}

@Module({
	providers: [EncryptionService],
	exports: [EncryptionService],
})
export class EncryptionModule extends ConfigurableModuleClass {}
