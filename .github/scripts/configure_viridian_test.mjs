import { parseArgs } from "node:util";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawn, execSync } from "node:child_process";
import { platform } from "process";

import { parse } from "yaml";

import { sleep } from "./script_utils.mjs";

const BLUE = "\x1b[34m";
const GREEN = "\x1b[32m";
const RED = "\x1b[31m";
const RESET = "\x1b[0m";

const DOCKER_COMPOSE_INITIALIZATION_TIMEOUT = 10;
const DOCKER_COMPOSE_GATEWAY_NETWORK = "sea-cli-int";
const DOCKER_COMPOSE_GATEWAY_CONTAINER = "int-router";
const DOCKER_COMPOSE_BLOCK_NETWORKS_REGEX = platform === "linux" ? "10\\.\\d+\\.\\d+\\.\\d+\\/24" : "10.*";
const PYTHON_LIB_ALGAE_PATH = join(dirname(import.meta.dirname), "..", "viridian", "algae");
const DOCKER_COMPOSE_ALGAE_PATH = join(PYTHON_LIB_ALGAE_PATH, "docker", "compose.default.yml");
const DOCKER_COMPOSE_REEF_PATH = join(dirname(import.meta.dirname), "..", "viridian", "reef", "docker", "compose.yml");
const DOCKER_COMPOSE_CACHE_FILE_NAME = ".setup_test_cache";

/**
 * Print usage help message and exit with code 0.
 */
function printHelpMessage() {
	console.log(`${BOLD}Beget deployment script usage${RESET}:`);
	console.log(`\t${BLUE}-c --certs${RESET}: Load user CA self-signed certificates to this location (if needed, default: ${DEFAULT_CERTS}).`);
	console.log(`\t${BLUE}-h --help${RESET}: Print this message again and exit.`);
	console.log(`\t${BLUE}-v --verbose${RESET}: Print viridian connection link in the end.`);
	console.log(`${BOLD}Required environment variables${RESET}:`);
	console.log(`\t${GREEN}BEGET_API_LOGIN${RESET}: Beget account owner login.`);
	console.log(`\t${GREEN}BEGET_API_PASSWORD${RESET}: Beget account owner password.`);
	console.log(`\t${GREEN}BEGET_SERVER_KEY${RESET}: Password of the deployment server root user (also admin payload).`);
	console.log(`${BOLD}Optional environment variables${RESET}:`);
	console.log(`\t${GREEN}WHIRLPOOL_PAYLOAD${RESET}: Whirlpool viridian poyload (default: will be generated).`);
	console.log(`\t${GREEN}WHIRLPOOL_CTRLPORT${RESET}: Whirlpool control port (default: ${DEFAULT_CTRLPORT}).`);
	process.exit(0);
}

function runCommandForSystem(linuxCommand = undefined, windowsCommand = undefined) {
	switch (platform) {
		case "linux":
			if (linuxCommand !== undefined) return execSync(linuxCommand).toString();
		case "win32":
			if (windowsCommand !== undefined) return execSync(windowsCommand).toString();
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
	return values;
}

function parseGatewayContainerIP() {
	console.log("Reading Docker compose file...");
	const composeDict = parse(readFileSync(DOCKER_COMPOSE_REEF_PATH).toString());
    const seasideIP = composeDict["services"]["whirlpool"]["environment"]["SEASIDE_ADDRESS"];
	const gatewayIP = composeDict["services"][DOCKER_COMPOSE_GATEWAY_CONTAINER]["networks"][DOCKER_COMPOSE_GATEWAY_NETWORK]["ipv4_address"];
	const gatewayNetwork = composeDict["networks"][DOCKER_COMPOSE_GATEWAY_NETWORK]["ipam"]["config"][0]["subnet"];
	console.log(`Extracted compose parameters: Seaside IP (${seasideIP}), Gateway IP (${gatewayIP}) and Gateway network (${gatewayNetwork})`);
	return { seasideIP, gatewayIP, gatewayNetwork };
}

function setupRouting(gatewayContainerIP, gatewayNetwork) {
	console.log("Looking for the default route...");
	const defaultRoute = runCommandForSystem("ip route show default", "route print 0.0.0.0");
	if (platform === "linux") {
		const routes = execSync("ip route show").toString();
		console.log("Replacing default route...");
		execSync(`sudo ip route replace default via ${gatewayContainerIP}`);
		console.log("Deleting Docker routes...");
		for (let line of routes.split("\n")) {
			const match = line.match(DOCKER_COMPOSE_BLOCK_NETWORKS_REGEX);
			if (match !== null && match[0] !== gatewayNetwork) {
				console.log(`\tDeleting route: ${line}`);
				execSync(`sudo ip route delete ${line.trim()}`);
			}
		}
	} else if (platform === "windows") {
		console.log("Deleting Docker routes and the default route...");
		execSync(`route delete ${DOCKER_COMPOSE_BLOCK_NETWORKS_REGEX} && route delete ${defaultRoute}`);
		console.log("Adding new default route...");
		execSync(`route add 0.0.0.0 ${gatewayContainerIP}`);
	} else throw Error(`Command for platform ${platform} is not defined!`);
	console.log(`Routing set up, default route: ${defaultRoute}`);
	return defaultRoute;
}

async function launchDockerCompose(seasideIP) {
	console.log("Generating certificates...");
    execSync(`python3 -m setup --just-certs ${seasideIP}`, { env: { "PYTHONPATH": PYTHON_LIB_ALGAE_PATH } });
	console.log("Building 'whirlpool' and 'echo' images...");
    execSync(`docker compose -f ${DOCKER_COMPOSE_ALGAE_PATH} build whirlpool echo`);
	console.log("Spawning Docker compose process...");
	const process = spawn(`docker compose -f ${DOCKER_COMPOSE_REEF_PATH} up --build`, { detached: true, shell: true, stdio: "ignore" });
	console.log("Reading Docker compose process PID...");
	const pid = process.pid;
	console.log(`Docker compose process spawned, PID: ${pid}`);
	if (pid === undefined) {
		console.log("Killing Docker compose process...");
		process.kill();
		throw Error("Docker compose command failed!");
	} else {
		console.log("Waiting for Docker compose process to initiate...");
        await sleep(DOCKER_COMPOSE_INITIALIZATION_TIMEOUT);
		console.log("Disconnecting from Docker compose process...");
		process.unref();
		return pid;
	}
}

function storeCache(cacheFile, { route, pid }) {
	console.log("Writing cache file...");
	writeFileSync(cacheFile, JSON.stringify({ route, pid }));
	console.log(`Cache written: default route (${route}), PID (${pid})`);
}

function loadCache(cacheFile) {
	console.log("Reading cache file...");
	const cache = JSON.parse(readFileSync(cacheFile).toString());
	console.log(`Cache read: default route (${cache.route}), PID (${cache.pid})`);
	return cache;
}

function killDockerCompose(pid) {
	console.log("Killing Docker compose process...");
	runCommandForSystem(`kill -2 ${pid}`, `taskkill /pid ${pid}`);
	console.log("Docker compose process killed!");
}

function resetRouting(defaultRoute) {
	console.log("Resetting default route...");
	runCommandForSystem(`sudo ip route replace ${defaultRoute}`, `route delete 0.0.0.0 && route add ${defaultRoute}`);
	console.log("Default route reset!");
}

// Script body:

const args = parseArguments();
if (!args.reset) {
    const { seasideIP, gatewayIP, gatewayNetwork } = parseGatewayContainerIP();
	const pid = await launchDockerCompose(seasideIP);
	const route = setupRouting(gatewayIP, gatewayNetwork);
	storeCache(args.cacheFile, { route, pid });
} else {
	const { route, pid } = loadCache(args.cacheFile);
	resetRouting(route);
	killDockerCompose(pid);
}
