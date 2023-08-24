import type { Cipher } from "./encryption.ciphers";
import { EncryptionService } from "./encryption.service";
import { ConfigurableModuleBuilder, Global, Module } from "@nestjs/common";

export interface EncryptionModuleOptions {
	key: string;
	cipher?: Cipher;
}

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } =
	new ConfigurableModuleBuilder<EncryptionModuleOptions>()
		.setExtras(
			{
				global: true,
			},
			(definition, extras) => ({
				...definition,
				global: extras.global,
			}),
		)
		.build();

@Global()
@Module({
	providers: [EncryptionService],
	exports: [EncryptionService],
})
export class EncryptionModule extends ConfigurableModuleClass {}
