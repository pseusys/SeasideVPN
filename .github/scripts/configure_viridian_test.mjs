import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync, ChildProcess } from "node:child_process";
import { platform } from "process";

import { parse } from "yaml";

import { sleep } from "./script_utils.mjs";

const BLUE = "\x1b[34m";
const RESET = "\x1b[0m";

// Timeout for Docker compose to initialize (and stop completely in case of an error).
const DOCKER_COMPOSE_TIMEOUT = 15;
// Echo server network for VPN access.
const DOCKER_COMPOSE_NETWORK = "sea-net";
// Seaside container for VPN access.
const DOCKER_COMPOSE_CONTAINER = "whirlpool";
// Seaside container and image name for server container in hosted network.
const DOCKER_COMPOSE_HOST_CONTAINER = "whirlpool-host";
// Seaside container and image name for server container in bridged network.
const DOCKER_COMPOSE_BRIDGE_CONTAINER = "whirlpool-bridge";
// Path to the Docker compose configuration file in `viridian/algae` directory.
const DOCKER_COMPOSE_PATH = join(dirname(import.meta.dirname), "..", "viridian", "algae", "docker", "compose.standalone.yml");


function print(message, silent = false) {
	if (!silent) console.log(message);
}

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
function runCommand(command, environment) {
	const child = spawnSync(command, { shell: true, encoding: "utf-8", env: environment });
	if (child.error) throw Error(`Command execution error: ${child.error.message}`);
	else if (child.status !== 0) throw Error(`Command failed with error code: ${child.status}\n${child.stderr.toString()}`);
	else return child;
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
function runCommandForSystem(linuxCommand = undefined, windowsCommand = undefined, macosCommand = undefined, environment = Object()) {
	switch (platform) {
		case "darwin":
			if (macosCommand !== undefined) return runCommand(macosCommand, environment);
		case "linux":
			if (linuxCommand !== undefined) return runCommand(linuxCommand, environment);
		case "win32":
			if (windowsCommand !== undefined) return runCommand(windowsCommand, environment);
		default:
			throw Error(`Command for platform ${platform} is not defined!`);
	}
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
		silent: {
			type: "boolean",
			short: "s",
			default: false
		},
		target: {
			type: "string",
			short: "t"
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
function parseDockerComposeFile(silent) {
	if (platform == "win32") {
		print("Reading system configurations...", silent);
		const WSLIP = runCommand("hostname -I").stdout.toString().trim().split(" ")[0].trim();
		print(`Extracted whirlpool IP from WSL configuration: ${WSLIP}`, silent);
		return WSLIP;
	} else {
		print("Reading Docker compose file...", silent);
		const composeDict = parse(readFileSync(DOCKER_COMPOSE_PATH).toString());
		const whirlpoolIP = composeDict["services"][DOCKER_COMPOSE_CONTAINER]["networks"][DOCKER_COMPOSE_NETWORK]["ipv4_address"].trim();+
		print(`Extracted whirlpool IP from compose file: ${whirlpoolIP}`, silent);
		return whirlpoolIP;
	}
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
function setupRouting(unreachable, silent) {
	print(`Disabling access to ${unreachable} address...`, silent);
	runCommandForSystem(
		`iptables -A OUTPUT --dst ${unreachable}/32 -j DROP`,
		`New-NetFirewallRule -DisplayName "seaside-test-block-unreachable" -Direction Outbound -RemoteAddress ${unreachable} -Action Block -Profile Any -Enabled True`
	);
	print(`Accessing ${unreachable} is no longer possible!`, silent);
}

function resetRouting(unreachable, silent) {
	print(`Enabling access to ${unreachable} address...`, silent);
	runCommandForSystem(
		`sudo iptables -D OUTPUT -d ${unreachable}/32 -j DROP`,
		`Remove-NetFirewallRule -DisplayName "seaside-test-block-unreachable"`
	);
	print(`Accessing ${unreachable} is possible again!`, silent);
}

/**
 * Launch Docker compose project in the background.
 * Wait for some time to check if it started successfully and throw an error if it did.
 * @param {string} path Docker Compose standalone project file path.
 */
async function launchWhirlpool(whirlpool, silent) {
	print("Spawning whirlpool process...", silent);
	runCommandForSystem(
		`docker compose -f ${DOCKER_COMPOSE_PATH} up --build --detach ${DOCKER_COMPOSE_BRIDGE_CONTAINER}`,
		`wsl -u root docker compose -f ${optionallyConvertPathToWSL(DOCKER_COMPOSE_PATH)} up --build --detach ${DOCKER_COMPOSE_HOST_CONTAINER}`,
		environment = {"SEASIDE_ADDRESS_ARG": whirlpool}
	);
	print("Waiting whirlpool to initiate...", silent);
	await sleep(DOCKER_COMPOSE_TIMEOUT);
	print("Whirlpool started!", silent);
}

/**
 * Kill Docker compose process (with docker compose) running in the background.
 * @param {string} path Docker Compose standalone project file path.
 */
async function killWhirlpool(silent) {
	print("Killing whirlpool process...", silent);
	runCommandForSystem(
		`docker compose -f ${DOCKER_COMPOSE_PATH} down`,
		`wsl -u root docker compose -f ${optionallyConvertPathToWSL(DOCKER_COMPOSE_PATH)} down`
	);
	print("Whirlpool process killed!", silent);
}

// Script body:

// NB! Since the default route can not be changed in GitHub Actions, a different approach is taken here:
// Since, in fact, the only meaningful targets are whirlpool and echo docker containers, routes to them are changed instead of the default one.
// Viridian client determines the default route as the route to the caerulean address, so the router address is considered to be the default one.
const args = parseArguments();
const whirlpoolIP = parseDockerComposeFile(args.silent);
if (!args.reset) {
	await launchWhirlpool(whirlpoolIP, args.silent);
	setupRouting(args.target, args.silent);
	print(whirlpoolIP, !args.silent)
} else {
	resetRouting(args.target, args.silent);
	await killWhirlpool(args.silent);
}
