import { parseArgs } from "node:util";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { platform } from "process";

import { parse } from "yaml";

import { sleep } from "./script_utils.mjs";

const BLUE = "\x1b[34m";
const GREEN = "\x1b[32m";
const RESET = "\x1b[0m";

// Metric value that will be used for new default routes (greater than Viridian Reef metric value).
const REASONABLY_LOW_METRIC_VALUE = 10;
// Timeout for Docker compose to initialize (and stop completely in case of an error).
const DOCKER_COMPOSE_INITIALIZATION_TIMEOUT = 15;
// Gateway network for VPN access.
const DOCKER_COMPOSE_GATEWAY_NETWORK = "sea-cli-int";
// Gateway router for VPN access.
const DOCKER_COMPOSE_GATEWAY_CONTAINER = "int-router";
// Path to `viridian/algae` directory.
const PYTHON_LIB_ALGAE_PATH = join(dirname(import.meta.dirname), "..", "viridian", "algae");
// Path to the default Docker compose configuration file in `viridian/algae` directory.
const DOCKER_COMPOSE_ALGAE_PATH = join(PYTHON_LIB_ALGAE_PATH, "docker", "compose.default.yml");
// Path to `viridian/reef` directory.
const PYTHON_LIB_REEF_PATH = join(dirname(import.meta.dirname), "..", "viridian", "reef");
// Path to the Docker compose configuration file in `viridian/reef` directory.
const DOCKER_COMPOSE_REEF_PATH = join(PYTHON_LIB_REEF_PATH, "docker", "compose.yml");
// Host configuration cache file name.
const DOCKER_COMPOSE_CACHE_FILE_NAME = ".setup_test_cache";
// VPN client test environment file name.
const DOCKER_COMPOSE_SOURCE_ENV_FILE_NAME = ".env";

/**
 * Print usage help message and exit with code 0.
 */
function printHelpMessage() {
	console.log(`${BOLD}Host preparation for testing script usage${RESET}:`);
	console.log(`\t${BLUE}-r --reset${RESET}: Revert all the changes, stop processes and restore system routes.`);
	console.log(`\t${BLUE}-h --help${RESET}: Print this message again and exit.`);
	console.log(`${BOLD}Optional environment variables${RESET}:`);
	console.log(`\t${GREEN}DOCKER_COMPOSE_CACHE_FILE_NAME${RESET}: Cache file where changes will be saved (default: ${DOCKER_COMPOSE_CACHE_FILE_NAME}).`);
	console.log(`\t${GREEN}DOCKER_COMPOSE_SOURCE_ENV_FILE_NAME${RESET}: Environment file where test environment variables will be stored (default: ${DOCKER_COMPOSE_SOURCE_ENV_FILE_NAME}).`);
	process.exit(0);
}

/**
 * Execute different console commands for different operation systems.
 * Throw an error if no command is provided for current OS.
 * The OS supported: Linux, Windows, MacOS.
 * @param {string | undefined} linuxCommand command for Linux OS.
 * @param {string | undefined} windowsCommand command for Windows OS.
 * @param {string | undefined} macosCommand command for MacOS.
 * @returns {string} command STDOUT output as a string.
 */
function runCommandForSystem(linuxCommand = undefined, windowsCommand = undefined, macosCommand = undefined) {
	switch (platform) {
		case "darwin":
			if (macosCommand !== undefined) return spawnSync(macosCommand, { shell: true }).stdout.toString();
		case "linux":
			if (linuxCommand !== undefined) return spawnSync(linuxCommand, { shell: true }).stdout.toString();
		case "win32":
			if (windowsCommand !== undefined) return spawnSync(windowsCommand, { shell: true }).stdout.toString();
		default:
			throw Error(`Command for platform ${platform} is not defined!`);
	}
}

/**
 * Parse CLI and environment flags and arguments.
 * @returns {object} object, containing all the arguments parsed
 */
function parseArguments() {
	const options = {
		reset: {
			type: "boolean",
			short: "r",
			default: false
		},
		help: {
			type: "boolean",
			short: "h",
			default: false
		}
	};
	const { values } = parseArgs({ options });
	if (values.help) printHelpMessage();
	if (process.env.DOCKER_COMPOSE_CACHE_FILE_NAME === undefined) values["cacheFile"] = DOCKER_COMPOSE_CACHE_FILE_NAME;
	else values["cacheFile"] = process.env.DOCKER_COMPOSE_CACHE_FILE_NAME;
	values["cacheFile"] = join(dirname(import.meta.filename), values["cacheFile"]);
	if (process.env.DOCKER_COMPOSE_SOURCE_ENV_FILE_NAME === undefined) values["envFile"] = DOCKER_COMPOSE_SOURCE_ENV_FILE_NAME;
	else values["envFile"] = process.env.DOCKER_COMPOSE_SOURCE_ENV_FILE_NAME;
	values["envFile"] = join(dirname(import.meta.filename), values["envFile"]);
	return values;
}

/**
 * Parse Viridian Reef Docker compose file.
 * Extract Seaside IP and gateway container IP.
 * Also get network addresses of all the networks that should become unreachable.
 * Write Viridian Reef container environment to `.env` file.
 * @param {string} envFileName path where environment file will be saved.
 * @returns {object} containing keys: `seasideIP`, `gatewayIP`, `dockerNetworks`.
 */
function parseDockerComposeFile(envFileName) {
	console.log("Reading Docker compose file...");
	const composeDict = parse(readFileSync(DOCKER_COMPOSE_REEF_PATH).toString());
	const seasideIP = composeDict["services"]["whirlpool"]["environment"]["SEASIDE_ADDRESS"];
	const gatewayIP = composeDict["services"][DOCKER_COMPOSE_GATEWAY_CONTAINER]["networks"][DOCKER_COMPOSE_GATEWAY_NETWORK]["ipv4_address"];
	const gatewayNetwork = composeDict["networks"][DOCKER_COMPOSE_GATEWAY_NETWORK]["ipam"]["config"][0]["subnet"];
	console.log(`Extracted compose parameters: Seaside IP (${seasideIP}), gateway IP (${gatewayIP})`);
	const dockerNetworks = Object.values(composeDict["networks"])
		.map((v) => v["ipam"]["config"][0]["subnet"])
		.filter((v) => v !== gatewayNetwork);
	console.log(`Extracted networks that will be disconnected: ${dockerNetworks}`);
	writeFileSync(
		envFileName,
		Object.entries(composeDict["services"]["reef"]["environment"])
			.map(([k, v]) => `${k}=${v}`)
			.join("\n")
	);
	console.log(`Default environment variables written to: ${envFileName}`);
	return { seasideIP, gatewayIP, dockerNetworks };
}

/**
 * Extract and remove system default route and add new default route via Docker gateway container.
 * After that, remove routes to all the other Docker containers (that should not be directly reachable during testing).
 * @param {string} gatewayContainerIP Docker gateway container IP address.
 * @param {Array<string>} dockerNetworks Docker networks that should become unreachable.
 * @returns {string} the old system default route that should be saved and restored afterwards.
 */
function setupRouting(gatewayContainerIP, dockerNetworks) {
	console.log("Looking for the default route...");
	const defaultRoute = runCommandForSystem("ip route show default", "route print 0.0.0.0").trim();
	console.log("Deleting current default route...");
	runCommandForSystem(`ip route delete ${defaultRoute}`, `route delete ${defaultRoute}`);
	console.log("Adding new default route via specified Docker container router...");
	runCommandForSystem(`ip route add default via ${gatewayContainerIP} metric ${REASONABLY_LOW_METRIC_VALUE}`, `route add 0.0.0.0 ${gatewayContainerIP} metric ${REASONABLY_LOW_METRIC_VALUE}`);
	console.log("Deleting Docker routes to the networks that should become unreachable...");
	dockerNetworks.forEach((v) => runCommandForSystem(`ip route delete ${v}`, `route delete ${v}`));
	console.log(`Routing set up, saved default route: ${defaultRoute}`);
	return defaultRoute;
}

/**
 * Generate certificates and launch Docker compose project in the background.
 * Wait for some time to check if it started successfully and throw an error if it did.
 * @param {string} seasideIP Seaside Caerulean IP address for client to connect to.
 * @returns {number} Docker compose process PID.
 */
async function launchDockerCompose(seasideIP) {
	console.log("Generating certificates...");
	spawnSync(`poetry -C ${PYTHON_LIB_ALGAE_PATH} run python3 -m setup --just-certs ${seasideIP} -v ERROR`, { shell: true });
	console.log("Moving certificates...");
	spawnSync(`mv ${join(PYTHON_LIB_ALGAE_PATH, "certificates")}, ${join(PYTHON_LIB_REEF_PATH, "certificates")}`);
	console.log("Building 'whirlpool' and 'echo' images...");
	spawnSync(`docker compose -f ${DOCKER_COMPOSE_ALGAE_PATH} build whirlpool echo`, { shell: true });
	console.log("Spawning Docker compose process...");
	const child = spawn(`docker compose -f ${DOCKER_COMPOSE_REEF_PATH} up --build --abort-on-container-exit --exit-code-from whirlpool`, { detached: true, shell: true, stdio: "ignore" });
	console.log("Reading Docker compose process PID...");
	if (child.pid === undefined) throw Error("Docker compose command didn't start successfully!");
	console.log("Waiting for Docker compose process to initiate...");
	await sleep(DOCKER_COMPOSE_INITIALIZATION_TIMEOUT);
	if (child.exitCode !== null) throw Error(`Docker compose command failed, with exit code: ${child.exitCode}`);
	console.log("Disconnecting from Docker compose process...");
	child.unref();
	return child.pid;
}

/**
 * Store Docker compose process PID and old route in a cache file.
 * @param {string} cacheFile file to store cache.
 * @param {object} cacheObject cache object that will be stored (as JSON).
 */
function storeCache(cacheFile, cacheObject) {
	console.log("Writing cache file...");
	writeFileSync(cacheFile, JSON.stringify(cacheObject));
	console.log(`Cache written: ${JSON.stringify(cacheObject)}`);
}

/**
 * Load Docker compose process PID and old route from a cache file.
 * @param {string} cacheFile file to store cache.
 * @returns {object} cache object that will be loaded.
 */
function loadCache(cacheFile) {
	console.log("Reading cache file...");
	const cache = JSON.parse(readFileSync(cacheFile).toString());
	console.log(`Cache read: default route (${cache.route}), PID (${cache.pid})`);
	return cache;
}

/**
 * Kill Docker compose process (by PID) running in the background.
 * @param {number} pid process PID.
 */
function killDockerCompose(pid) {
	console.log("Killing Docker compose process...");
	runCommandForSystem(`kill -2 ${pid}`, `taskkill /pid ${pid}`);
	console.log("Docker compose process killed!");
}

/**
 * Restore system default route (remove current and add previous).
 * @param {string} defaultRoute previous default route to restore.
 */
function resetRouting(defaultRoute) {
	console.log("Deleting current default route...");
	runCommandForSystem("ip route delete default", "route delete 0.0.0.0");
	console.log("Restoring previous default route...");
	runCommandForSystem(`ip route add ${defaultRoute}`, `route add ${defaultRoute}`);
	console.log("Default route reset!");
}

// Script body:

const args = parseArguments();
if (!args.reset) {
	const { seasideIP, gatewayIP, dockerNetworks } = parseDockerComposeFile(args.envFile);
	const pid = await launchDockerCompose(seasideIP);
	const route = setupRouting(gatewayIP, dockerNetworks);
	storeCache(args.cacheFile, { route, pid });
} else {
	const { route, pid } = loadCache(args.cacheFile);
	resetRouting(route);
	killDockerCompose(pid);
}
