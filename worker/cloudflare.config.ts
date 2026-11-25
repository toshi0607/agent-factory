import { bindings, defineConfig, defineContainer, exports } from "cf/config";

const WORKER_NAME = "agent-factory-p0";

// Deployment values are not committed. They come from the environment of the `cf deploy` process.
function required(name: string): string {
	const value = process.env[name];
	if (value === undefined || value.trim() === "") {
		throw new Error(`${name} must be set to deploy ${WORKER_NAME}`);
	}
	return value;
}

const sandbox = defineContainer({
	name: `${WORKER_NAME}-run`,
	schedulingPolicy: "durable-object",
	images: {
		sandbox: { dockerfile: "./Dockerfile" },
	},
});

export default defineConfig(() => ({
	worker: {
		name: WORKER_NAME,
		compatibilityDate: "2026-09-15",
		compatibilityFlags: ["nodejs_compat"],
		entrypoint: "src/index.ts",
		workersDev: true,
		observability: { enabled: true },
		env: {
			OIDC_AUDIENCE: bindings.text(required("FACTORY_OIDC_AUDIENCE")),
			ALLOWED_REPOSITORY_ID: bindings.text(required("FACTORY_ALLOWED_REPOSITORY_ID")),
			ALLOWED_REPOSITORY_OWNER_ID: bindings.text(required("FACTORY_ALLOWED_REPOSITORY_OWNER_ID")),
			ALLOWED_JOB_WORKFLOWS: bindings.text(required("FACTORY_ALLOWED_JOB_WORKFLOWS")),
			ALLOWED_REFS: bindings.text(required("FACTORY_ALLOWED_REFS")),
			FACTORY_COMMIT: bindings.text(required("FACTORY_COMMIT")),
			INSTANCE_TYPE: bindings.text("standard-3"),
			RUN: bindings.durableObject({ worker: WORKER_NAME, exportName: "Run" }),
			LEDGER: bindings.durableObject({ worker: WORKER_NAME, exportName: "Ledger" }),
			CF_VERSION_METADATA: bindings.versionMetadata(),
		},
		exports: {
			Run: exports.durableObject({ storage: "sqlite", container: sandbox }),
			Ledger: exports.durableObject({ storage: "sqlite" }),
		},
	},
	containers: [sandbox],
}));
