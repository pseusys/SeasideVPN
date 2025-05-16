import { parseArgs } from "node:util";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync, ChildProcess } from "node:child_process";
import { platform } from "process";

import { parse } from "yaml";

import { sleep } from "./script_utils.mjs";

const BLUE = "\x1b[34m";
const GREEN = "\x1b[32m";
const RESET = "\x1b[0m";

// Metric value that will be used for new default routes (greater than Viridian Algae metric value).
const REASONABLY_LOW_METRIC_VALUE = 10;
// Timeout for Docker compose to initialize (and stop completely in case of an error).
const DOCKER_COMPOSE_INITIALIZATION_TIMEOUT = 15;
// Gateway network for VPN access.
const DOCKER_COMPOSE_GATEWAY_NETWORK = "sea-cli-int";
// Gateway router for VPN access.
const DOCKER_COMPOSE_GATEWAY_CONTAINER = "int-router";
// Echo server for VPN access.
const DOCKER_COMPOSE_ECHO_CONTAINER = "echo";
// Echo server network for VPN access.
const DOCKER_COMPOSE_ECHO_NETWORK = "sea-serv-ext";
// Path to `viridian/algae` directory.
const PYTHON_LIB_ALGAE_PATH = join(dirname(import.meta.dirname), "..", "viridian", "algae");
// Path to the Docker compose configuration file in `viridian/algae` directory.
const DOCKER_COMPOSE_ALGAE_PATH = join(PYTHON_LIB_ALGAE_PATH, "docker", "compose.standalone.yml");
// Host configuration cache file name.
const DOCKER_COMPOSE_CACHE_FILE_NAME = ".setup_test_cache";

/**
 * Print usage help message and exit with code 0.
 */
function printHelpMessage() {
	console.log(`${BOLD}Host preparation for testing script usage${RESET}:`);
	console.log(`\t${BLUE}-r --reset${RESET}: Revert all the changes, stop processes and restore system routes.`);
	console.log(`\t${BLUE}-h --help${RESET}: Print this message again and exit.`);
	console.log(`${BOLD}Optional environment variables${RESET}:`);
	console.log(`\t${GREEN}DOCKER_COMPOSE_CACHE_FILE_NAME${RESET}: Cache file where changes will be saved (default: ${DOCKER_COMPOSE_CACHE_FILE_NAME}).`);
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
 * Execute different console commands for different operation systems.
 * Throw an error if no command is provided for current OS.
 * Throw an error if command failed to start or returned non-zero code.
 * The OS supported: Linux, Windows, MacOS.
 * @param {string | undefined} linuxCommand command for Linux OS.
 * @param {string | undefined} windowsCommand command for Windows OS.
 * @param {string | undefined} macosCommand command for MacOS.
 * @returns {string} command STDOUT output as a string.
 */
function runCommandForSystem(linuxCommand = undefined, windowsCommand = undefined, macosCommand = undefined) {
	switch (platform) {
		case "darwin":
			if (macosCommand !== undefined) return runCommand(macosCommand).stdout.toString().trim();
		case "linux":
			if (linuxCommand !== undefined) return runCommand(linuxCommand).stdout.toString().trim();
		case "win32":
			if (windowsCommand !== undefined) return runCommand(windowsCommand).stdout.toString().trim();
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

/**
 * Parse Viridian Algae Docker compose file.
 * Extract host gateway IP, echo container IP and echo container network.
 * @returns {object} containing keys: `hostIP`, `echoIP`, `echoNetwork`.
 */
function parseDockerComposeFile() {
	console.log("Reading Docker compose file...");
	const composeDict = parse(readFileSync(DOCKER_COMPOSE_ALGAE_PATH).toString());
	const hostIP = composeDict["networks"][DOCKER_COMPOSE_GATEWAY_NETWORK]["ipam"]["config"][0]["gateway"];
	const echoIP = composeDict["services"][DOCKER_COMPOSE_ECHO_CONTAINER]["networks"][DOCKER_COMPOSE_ECHO_NETWORK]["ipv4_address"];
	const echoNetwork = composeDict["networks"][DOCKER_COMPOSE_ECHO_NETWORK]["ipam"]["config"][0]["subnet"];
	console.log(`Extracted compose parameters: host gateway IP (${hostIP}), echo IP (${echoIP}), echo network (${echoNetwork})`);
	return { hostIP, echoIP, echoNetwork };
}

/**
 * TODO: change.
 * Extract and remove system default route and add new default route via Docker gateway container.
 * After that, remove routes to all the other Docker containers (that should not be directly reachable during testing).
 * @param {string} gatewayHostIP Docker gateway container IP address.
 * @param {string} echoContainerIP Docker gateway container IP address.
 * @param {string} echoNetwork Docker gateway container IP address.
 */
function setupRouting(gatewayHostIP, echoContainerIP, echoNetwork) {
	console.log("Removing a route to the echo container...");
	runCommandForSystem(`ip route delete ${echoNetwork}`, `route delete ${echoNetwork}`);
	console.log("Setting a new to the echo container...");
	runCommandForSystem(`ip route add ${echoNetwork} via ${gatewayHostIP} metric ${REASONABLY_LOW_METRIC_VALUE}`, `route add ${echoNetwork} ${gatewayHostIP} metric ${REASONABLY_LOW_METRIC_VALUE}`);
	console.log("Looking for the new route to the echo container...");
	const route = runCommandForSystem(`ip route get ${echoContainerIP}`, `route print ${echoContainerIP}`);
	console.log(`Route to the echo container found:\n${route}`);
}

/**
 * Launch Docker compose project in the background.
 * Wait for some time to check if it started successfully and throw an error if it did.
 */
async function launchDockerCompose() {
	console.log("Spawning Docker compose process...");
	const child = runCommand(`docker compose -f ${DOCKER_COMPOSE_ALGAE_PATH} up --detach --build whirlpool`);
	console.log("Waiting for Docker compose process to initiate...");
	await sleep(DOCKER_COMPOSE_INITIALIZATION_TIMEOUT);
	if (child.status !== 0) throw Error(`Docker compose command failed, with exit code: ${child.status}`);
	console.log("Docker compose process started!");
}

/**
 * Kill Docker compose process (with docker compose) running in the background.
 */
async function killDockerCompose() {
	console.log("Killing Docker compose process...");
	const child = runCommand(`docker compose -f ${DOCKER_COMPOSE_ALGAE_PATH} down`);
	console.log("Waiting for Docker compose process to terminate...");
	await sleep(DOCKER_COMPOSE_INITIALIZATION_TIMEOUT);
	if (child.status !== null) throw Error(`Docker compose command failed, with exit code: ${child.status}`);
	console.log("Docker compose process killed!");
}

// Script body:

const args = parseArguments();
if (!args.reset) {
	const { hostIP, echoIP, echoNetwork } = parseDockerComposeFile();
	await launchDockerCompose();
	setupRouting(hostIP, echoIP, echoNetwork);
} else {
	await killDockerCompose();
}
