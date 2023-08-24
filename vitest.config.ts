import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		passWithNoTests: true,
		coverage: {
			reporter: ["text", "html"],
		},
	},
	resolve: {
		alias: {
			"@/": "src/",
		},
	},
});
