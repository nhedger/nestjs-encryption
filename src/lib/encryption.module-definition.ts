import { ConfigurableModuleBuilder } from "@nestjs/common";
import type { EncryptionModuleOptions } from "./encryption.module";

export const { ConfigurableModuleClass, MODULE_OPTIONS_TOKEN } =
	new ConfigurableModuleBuilder<EncryptionModuleOptions>()
		.setClassMethodName("forRoot")
		.setExtras(
			{
				isGlobal: true,
			},
			(definition, extras) => ({
				...definition,
				global: extras.isGlobal,
			}),
		)
		.build();
