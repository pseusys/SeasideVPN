import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync, ChildProcess } from "node:child_process";
import { platform } from "process";

import { parse } from "yaml";

import { sleep } from "./script_utils.mjs";

const BLUE = "\x1b[34m";
const GREEN = "\x1b[32m";
const RESET = "\x1b[0m";

// Timeout for Docker compose to initialize (and stop completely in case of an error).
const DOCKER_COMPOSE_TIMEOUT = 15;
// Echo server network for VPN access.
const DOCKER_COMPOSE_ECHO_NETWORK = "sea-serv-ext";
// Gateway network for VPN access.
const DOCKER_COMPOSE_GATEWAY_NETWORK = "sea-cli-int";
// Seaside network for VPN access.
const DOCKER_COMPOSE_WHIRLPOOL_NETWORK = "sea-rout-int";
// Gateway router for VPN access.
const DOCKER_COMPOSE_GATEWAY_CONTAINER = "int-router";
// Seaside container for VPN access.
const DOCKER_COMPOSE_WHIRLPOOL_CONTAINER = "whirlpool";
// Echo server for VPN access.
const DOCKER_COMPOSE_ECHO_CONTAINER = "echo";
// Path to the Docker compose configuration file in `viridian/algae` directory.
const DOCKER_COMPOSE_ALGAE_PATH = join(dirname(import.meta.dirname), "..", "viridian", "algae", "docker", "compose.standalone.yml");

/**
 * Print usage help message and exit with code 0.
 */
function printHelpMessage() {
	console.log(`${BOLD}Host preparation for testing script usage${RESET}:`);
	console.log(`\t${BLUE}-r --reset${RESET}: Revert all the changes, stop processes and restore system routes.`);
	console.log(`\t${BLUE}-h --help${RESET}: Print this message again and exit.`);
	process.exit(0);
}

/**
 * Execute a console command.
 * Throw an error if command failed to start or returned non-zero code.
 * @param {string} command the command to execute.
 * @returns {ChildProcess} child process spawned by the command.
 */
function runCommand(command) {
	const child = spawnSync(command, { shell: true, encoding: "utf-8" });
	if (child.error) throw Error(`Command execution error: ${child.error.message}`);
	else if (child.status !== 0) throw Error(`Command failed with error code: ${child.status}\n${child.stderr.toString()}`);
	else return child;
}

/**
 * Execute a console command.
 * Throw an error if command failed to start or returned non-zero code.
 * @param {string} command the command to execute.
 * @returns {string} command STDOUT output as a string.
 */
function getOutput(command) {
	return runCommand(command).stdout.toString().trim();
}

/**
 * Execute different console commands for different operation systems.
 * Transform all paths so that separators are consistent with the selected platform.
 * Throw an error if no command is provided for current OS.
 * Throw an error if command failed to start or returned non-zero code.
 * The OS supported: Linux, Windows, MacOS.
 * @param {string | undefined} linuxCommand command for Linux OS.
 * @param {string | undefined} windowsCommand command for Windows OS.
 * @param {string | undefined} macosCommand command for MacOS.
 * @returns {ChildProcess} child process spawned by the command.
 */
function runCommandForSystem(linuxCommand = undefined, windowsCommand = undefined, macosCommand = undefined) {
	switch (platform) {
		case "darwin":
			if (macosCommand !== undefined) return runCommand(macosCommand);
		case "linux":
			if (linuxCommand !== undefined) return runCommand(linuxCommand);
		case "win32":
			if (windowsCommand !== undefined) return runCommand(windowsCommand);
		default:
			throw Error(`Command for platform ${platform} is not defined!`);
	}
}

/**
 * Execute different console commands for different operation systems.
 * Transform all paths so that separators are consistent with the selected platform.
 * Throw an error if no command is provided for current OS.
 * Throw an error if command failed to start or returned non-zero code.
 * The OS supported: Linux, Windows, MacOS.
 * @param {string | undefined} linuxCommand command for Linux OS.
 * @param {string | undefined} windowsCommand command for Windows OS.
 * @param {string | undefined} macosCommand command for MacOS.
 * @returns {string} command STDOUT output as a string.
 */
function getOutputForSystem(linuxCommand = undefined, windowsCommand = undefined, macosCommand = undefined) {
	return runCommandForSystem(linuxCommand, windowsCommand, macosCommand).stdout.toString().trim();
}

/**
 * Convert given path to WSL-compatible format (using `wslpath` tool) if running on Windows.
 * Return path as it is otherwise.
 * @param {string} path path ro convert.
 * @returns {string} converted path.
 */
function optionallyConvertPathToWSL(path) {
	switch (platform) {
		case "win32":
			return runCommand(`wsl wslpath -a ${path.replaceAll("\\", "\\\\")}`).stdout.toString().trim();
		default:
			return path;
	}
}

/**
 * Convert network address such as IP/CIDR to IP address and netmask.
 * @param {string} network address, should be a valid IP address and a CIDR, separated by '/'.
 * @returns {object} containing string keys "network" and "netmask".
 */
function convertNetworkAddress(network) {
	const [ip, prefixLength] = cidr.split("/");
	const maskBinary = "1".repeat(parseInt(prefixLength)).padEnd(32, "0");
	const mask = [
	  	parseInt(maskBinary.slice(0, 8), 2),
	  	parseInt(maskBinary.slice(8, 16), 2),
	  	parseInt(maskBinary.slice(16, 24), 2),
	  	parseInt(maskBinary.slice(24, 32), 2),
	].join(".");
	return { network: ip, netmask: mask };
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
	return values;
}

/**
 * Parse Viridian Algae Docker compose file.
 * Extract gateway container IP, whirlpool container IP, whirlpool container network, echo container IP and echo container network.
 * @returns {object} containing keys: `gatewayIP`, `whirlpoolNetwork`, `whirlpoolIP`, `echoIP`, `echoNetwork`.
 */
function parseDockerComposeFile() {
	console.log("Reading Docker compose file...");
	const composeDict = parse(readFileSync(DOCKER_COMPOSE_ALGAE_PATH).toString());
	const whirlpoolIP = composeDict["services"][DOCKER_COMPOSE_WHIRLPOOL_CONTAINER]["networks"][DOCKER_COMPOSE_WHIRLPOOL_NETWORK]["ipv4_address"];
	const gatewayIP = composeDict["services"][DOCKER_COMPOSE_GATEWAY_CONTAINER]["networks"][DOCKER_COMPOSE_GATEWAY_NETWORK]["ipv4_address"];
	const echoIP = composeDict["services"][DOCKER_COMPOSE_ECHO_CONTAINER]["networks"][DOCKER_COMPOSE_ECHO_NETWORK]["ipv4_address"];
	const whirlpoolNetwork = composeDict["networks"][DOCKER_COMPOSE_WHIRLPOOL_NETWORK]["ipam"]["config"][0]["subnet"];
	const echoNetwork = composeDict["networks"][DOCKER_COMPOSE_ECHO_NETWORK]["ipam"]["config"][0]["subnet"];
	console.log(`Extracted compose parameters: gateway IP (${gatewayIP}), echo IP (${echoIP}), echo network (${echoNetwork})`);
	return { gatewayIP, whirlpoolIP, whirlpoolNetwork, echoIP, echoNetwork };
}

/**
 * Extract and remove system route to the given network and replace it with a route via given gateway.
 * After that, print the resulting routes.
 * NB! Since the default route is not changed, this *should* work on GitHub Actions.
 * @param {string} gatewayContainerIP gateway IP address.
 * @param {string} unreachableIP IP address that will become unreachable (directly).
 * @param {string} unreachableNetwork network that will become unreachable (directly).
 * @param {string | null} name the given name for the unreachable IP and network.
 */
function setupRouting(gatewayContainerIP, unreachableIP, unreachableNetwork, name=null) {
	console.log(`Removing a route to the ${name} network...`);
	runCommandForSystem(`ip route delete ${unreachableNetwork}`, `wsl -u root ip route delete ${unreachableNetwork}`);
	console.log(`Setting a new route to the ${name} network...`);
	runCommandForSystem(`ip route add ${unreachableNetwork} via ${gatewayContainerIP}`, `wsl -u root ip route add ${unreachableNetwork} via ${gatewayContainerIP}`);
	console.log(`Looking for the new route to the ${name} IP...`);
	const route = getOutputForSystem(`ip route get ${unreachableIP}`, `wsl -u root ip route get ${unreachableIP}`);
	console.log(`Route to the ${name} IP found:\n${route}`);
	if (platform == "win32") {
		const WSLIP = getOutput(`wsl -u root sh -c "ip route | grep '^default' | awk '{print \\$3}'"`);
		console.log(`Preparing route to the ${name} via WSL host IP: ${WSLIP}...`);
		const { unreachableNetworkIP, unreachableNetworkMask } = convertNetworkAddress(unreachableNetwork);
		console.log(`Setting route to the ${name}, specifically: network ${unreachableNetworkIP} netmask ${unreachableNetworkMask}...`);
		runCommand(`route add ${unreachableNetworkIP} mask ${unreachableNetworkMask} ${WSLIP}`);
		console.log(`Looking for the route to the ${name} via WSL...`);
		const WSLroute = getOutput(`route print ${unreachableIP}`);
		console.log(`Route to the ${name} via WSL configured:\n${WSLroute}`);
	}
}

/**
 * Launch Docker compose project in the background.
 * Wait for some time to check if it started successfully and throw an error if it did.
 * @param {string} path Docker Compose standalone project file path.
 */
async function launchDockerCompose(path) {
	console.log("Spawning Docker compose process...");
	runCommandForSystem(`docker compose -f ${path} up --build --detach`, `wsl -u root docker compose -f ${path} up --build --detach`);
	console.log("Waiting for Docker compose process to initiate...");
	await sleep(DOCKER_COMPOSE_TIMEOUT);
	console.log("Docker compose process started!");
}

/**
 * Kill Docker compose process (with docker compose) running in the background.
 * @param {string} path Docker Compose standalone project file path.
 */
async function killDockerCompose(path) {
	console.log("Killing Docker compose process...");
	runCommandForSystem(`docker compose -f ${path} down`, `wsl -u root docker compose -f ${path} down`);
	console.log("Docker compose process killed!");
}

// Script body:

// NB! Since the default route can not be changed in GitHub Actions, a different approach is taken here:
// Since, in fact, the only meaningful targets are whirlpool and echo docker containers, routes to them are changed instead of the default one.
// Viridian client determines the default route as the route to the caerulean address, so the router address is considered to be the default one.
const args = parseArguments();
if (!args.reset) {
	const { gatewayIP, whirlpoolIP, whirlpoolNetwork, echoIP, echoNetwork } = parseDockerComposeFile();
	await launchDockerCompose(optionallyConvertPathToWSL(DOCKER_COMPOSE_ALGAE_PATH));
	setupRouting(gatewayIP, echoIP, echoNetwork, "echo");
	setupRouting(gatewayIP, whirlpoolIP, whirlpoolNetwork, "whirlpool");
} else {
	await killDockerCompose(optionallyConvertPathToWSL(DOCKER_COMPOSE_ALGAE_PATH));
}
