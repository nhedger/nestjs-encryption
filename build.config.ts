import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
	entries: ["src/lib/index", "src/cli/keygen"],
	declaration: true,
	clean: true,
	rollup: {
		emitCJS: true,
		esbuild: {
			tsconfigRaw: {
				compilerOptions: {
					target: "es2021",
					experimentalDecorators: true,
				},
			},
		},
	},
	alias: {
		"@/": "src/",
	},
});
