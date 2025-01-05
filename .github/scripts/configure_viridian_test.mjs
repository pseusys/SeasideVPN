import { parseArgs } from "node:util";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { exec, execSync } from "node:child_process";
import { platform } from "process";

import { parse } from "yaml";

const BLUE = "\x1b[34m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RESET = "\x1b[0m";

const DOCKER_COMPOSE_GATEWAY_NETWORK = "sea-cli-int";
const DOCKER_COMPOSE_GATEWAY_CONTAINER = "int-router";
const DOCKER_COMPOSE_BLOCK_NETWORKS_REGEX = platform === "linux" ? "10\\.\\d+\\.\\d+\\.\\d+\\/24" : "10.*";
const DOCKER_COMPOSE_PATH = join(dirname(import.meta.dirname), "..", "viridian", "reef", "docker", "compose.yml");
const DOCKER_COMPOSE_PROCESS_FILE_NAME = ".reef_test_cache";

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
	if (process.env.DOCKER_COMPOSE_GATEWAY_NETWORK === undefined) values["gatewayNetwork"] = DOCKER_COMPOSE_GATEWAY_NETWORK;
	else values["gatewayNetwork"] = process.env.DOCKER_COMPOSE_GATEWAY_NETWORK;
	if (process.env.DOCKER_COMPOSE_BLOCK_NETWORKS_REGEX === undefined) values["networkRegex"] = DOCKER_COMPOSE_BLOCK_NETWORKS_REGEX;
	else values["networkRegex"] = process.env.DOCKER_COMPOSE_BLOCK_NETWORKS_REGEX;
	if (process.env.DOCKER_COMPOSE_GATEWAY_CONTAINER === undefined) values["gatewayContainer"] = DOCKER_COMPOSE_GATEWAY_CONTAINER;
	else values["gatewayContainer"] = process.env.DOCKER_COMPOSE_GATEWAY_CONTAINER;
	if (process.env.DOCKER_COMPOSE_PATH === undefined) values["composePath"] = DOCKER_COMPOSE_PATH;
	else values["composePath"] = process.env.DOCKER_COMPOSE_PATH;
	if (process.env.DOCKER_COMPOSE_PROCESS_FILE_NAME === undefined) values["composePID"] = DOCKER_COMPOSE_PROCESS_FILE_NAME;
	else values["composePID"] = process.env.DOCKER_COMPOSE_PROCESS_FILE_NAME;
	values["composePID"] = join(dirname(import.meta.dirname), values["composePID"]);
	return values;
}

function parseGatewayContainerIP(composePath, gatewayName, gatewayNetworkName) {
	const composeDict = parse(readFileSync(composePath).toString());
	const gatewayIP = composeDict["services"][gatewayName]["networks"][gatewayNetworkName]["ipv4_address"];
	const gatewayNetwork = composeDict["networks"][gatewayNetworkName]["ipam"]["config"][0]["subnet"];
	return { gatewayIP, gatewayNetwork };
}

function setupRouting(gatewayContainerIP, networkRegex, gatewayNetwork) {
	const defaultRoute = runCommandForSystem("ip route show default", "route print 0.0.0.0");
	if (platform === "linux") {
		const routes = execSync("ip route show").toString();
        console.log(routes);
		execSync(`sudo ip route replace default via ${gatewayContainerIP}`);
		for (let line of routes.split("\n")) {
			const match = line.match(networkRegex);
			if (match !== null && match[0] !== gatewayNetwork) execSync(`sudo ip route delete ${line.trim()}`);
		}
	} else if (platform === "windows") {
		execSync(`route delete ${networkRegex} && route delete ${defaultRoute}`);
		execSync(`route add 0.0.0.0 ${gatewayContainerIP}`);
	} else throw Error(`Command for platform ${platform} is not defined!`);
	return defaultRoute;
}

function dockerErrorCallback(error, stdout, stderr) {
	if (error) {
		console.log(`${RED}Docker compose command error: ${error}\n\n${stderr}\n\n${stdout}${RESET}`);
	} else {
		console.log(`${GREEN}Docker compose command terminated correctly!${RESET}`);
	}
}

function launchDockerCompose(composePath) {
	const process = exec(`docker compose -f ${composePath} up --build`, dockerErrorCallback);
	const pid = process.pid;
	if (pid === undefined) {
		process.kill();
		throw Error("Docker compose command failed!");
	} else {
		process.unref();
		return pid;
	}
}

function storeCache(cachePID, { route, pid }) {
	writeFileSync(cachePID, JSON.stringify({ route, pid }));
}

function loadCache(cachePID) {
	return JSON.parse(readFileSync(cachePID).toString());
}

function killDockerCompose(pid) {
	runCommandForSystem(`kill -2 ${pid}`, `taskkill /pid ${pid}`);
}

function resetRouting(defaultRoute) {
	runCommandForSystem(`sudo ip route replace ${defaultRoute}`, `route delete 0.0.0.0 && route add ${defaultRoute}`);
}

// Script body:

const args = parseArguments();
if (!args.reset) {
    const { gatewayIP, gatewayNetwork } = parseGatewayContainerIP(args.composePath, args.gatewayContainer, args.gatewayNetwork);
	const pid = launchDockerCompose(args.composePath);
	const route = setupRouting(gatewayIP, args.networkRegex, gatewayNetwork);
	storeCache(args.composePID, { route, pid });
} else {
	const { route, pid } = loadCache(args.composePID);
	resetRouting(route);
	killDockerCompose(pid);
}
