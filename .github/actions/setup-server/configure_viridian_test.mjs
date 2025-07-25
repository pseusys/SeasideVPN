import { parseArgs } from "node:util";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync, ChildProcess } from "node:child_process";
import { platform } from "process";

import { parse } from "yaml";

import { sleep } from "../../scripts/script_utils.mjs";

const BLUE = "\x1b[34m";
const RESET = "\x1b[0m";

// Timeout for Docker compose to initialize (and stop completely in case of an error).
const DOCKER_COMPOSE_TIMEOUT = 45;
// Echo server network for VPN access.
const DOCKER_COMPOSE_NETWORK = "sea-net";
// Seaside container and image name for server container in bridged network.
const DOCKER_COMPOSE_CONTAINER = "whirlpool";
// Path to the Docker compose configuration file.
const DOCKER_COMPOSE_PATH = join(import.meta.dirname, "compose.yml");

const CAERULEAN_WHIRLPOOL_ROOT = join(import.meta.dirname, "..", "..", "..", "caerulean", "whirlpool");

const VIRIDIAN_ALGAE_ROOT = join(import.meta.dirname, "..", "..", "..", "viridian", "algae");

const INSTALLER_PATH = join(VIRIDIAN_ALGAE_ROOT, "install.pyz");

function print(message, silent = false) {
	if (!silent) console.log(message);
}

/**
 * Print usage help message and exit with code 0.
 */
function printHelpMessage() {
	console.log(`${BOLD}Host preparation for testing script usage${RESET}:`);
	console.log(`\t${BLUE}-h --help${RESET}: Print this message again and exit.`);
	process.exit(0);
}

/**
 * Execute a console command.
 * Throw an error if command failed to start or returned non-zero code.
 * @param {string | Array<string>} command the command to execute.
 * @returns {ChildProcess | undefined} child process spawned by the command.
 */
function runCommand(command, environment = {}, stdio = undefined) {
	const shell = platform == "win32" ? "powershell" : true;
	const child = spawnSync(command, { shell, encoding: "utf-8", env: { ...process.env, ...environment }, stdio });
	if (child.error) throw Error(`Command execution error: ${child.error.message}`);
	else if (child.status !== 0) throw Error(`Command failed: "${command}" (env: ${JSON.stringify(environment)})\nCommand failed with error code: ${child.status}\n\nSTDOUT:\n${child.stdout.toString()}\n\nSTDERR:\n${child.stderr.toString()}`);
	else return child;
}

function getOutput(command, environment = {}, stdio = undefined) {
	return runCommand(command, environment, stdio).stdout.toString().trim();
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
function runCommandForSystem(linuxCommand = undefined, windowsCommand = undefined, macosCommand = undefined, environment = {}, stdio = undefined) {
	switch (platform) {
		case "darwin":
			if (macosCommand !== undefined) return runCommand(macosCommand, environment, stdio);
		case "linux":
			if (linuxCommand !== undefined) return runCommand(linuxCommand, environment, stdio);
		case "win32":
			if (windowsCommand !== undefined) return runCommand(windowsCommand, environment, stdio);
		default:
			throw Error(`Command for platform ${platform} is not defined!`);
	}
}

function convertPathToWindows(path) {
	if (platform == "win32") {
		return path.replaceAll("\\", "\\\\");
	} else {
		return path;
	}
}

/**
 * Convert given path to WSL-compatible format (using `wslpath` tool) if running on Windows.
 * Return path as it is otherwise.
 * @param {string} path path to convert.
 * @returns {string} converted path.
 */
function convertPathToWSL(path) {
	if (platform == "win32") {
		return runCommand(`wsl wslpath -a ${convertPathToWindows(path)}`)
			.stdout.toString()
			.trim();
	} else {
		return path;
	}
}

/**
 * Parse CLI and environment flags and arguments.
 * @returns {object} object, containing all the arguments parsed
 */
function parseArguments() {
	const options = {
		silent: {
			type: "boolean",
			short: "s",
			default: false
		},
		target: {
			type: "string",
			short: "t"
		},
		lower_port: {
			type: "string",
			short: "l"
		},
		higher_port: {
			type: "string",
			short: "h"
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
function getWhirlpoolIP(silent) {
	if (platform == "win32") {
		print("Reading system configurations...", silent);
		const WSLIP = getOutput("wsl hostname -I").split(" ")[0].trim();
		print(`Extracted whirlpool IP from WSL configuration: ${WSLIP}`, silent);
		return WSLIP;
	} else {
		print("Reading Docker compose file...", silent);
		const composeDict = parse(readFileSync(DOCKER_COMPOSE_PATH).toString());
		const whirlpoolIP = composeDict["services"][DOCKER_COMPOSE_CONTAINER]["networks"][DOCKER_COMPOSE_NETWORK]["ipv4_address"].trim();
		print(`Extracted whirlpool IP from compose file: ${whirlpoolIP}`, silent);
		return whirlpoolIP;
	}
}

function getOutputConnection(unreachable) {
	if (platform == "win32") {
		const route = getOutput(`Find-NetRoute -RemoteIPAddress ${unreachable} | Select-Object -First 1 | ForEach-Object { "$($_.IPAddress) $($_.InterfaceIndex)" }`);
		const match = route.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+(.+)$/);
		return { iface: match[2], address: match[1] };
	} else {
		const route = getOutput(`ip route get ${unreachable}`);
		const iface = route.match(/\bdev\s+(\S+)/)[1];
		const address = route.match(/\bsrc\s+([0-9.]+)/)[1];
		return { iface, address };
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
function setupRouting(unreachable, lower_port, higher_port, iface, address, silent) {
	print(`Disabling access to ${unreachable} address...`, silent);
	runCommandForSystem(
		`iptables -t mangle -A OUTPUT -o ${iface} -s ${address} -d ${unreachable} -p tcp --sport ${lower_port}:${higher_port} -j DROP`,
		`Start-Process -FilePath "${convertPathToWindows(process.env.WINDIVERT_PATH)}\\\\netfilter" -ArgumentList '"ip and outbound and (ifIdx == ${iface}) and ((tcp.SrcPort >= ${lower_port}) and (tcp.SrcPort <= ${higher_port})) and (ip.SrcAddr == ${address}) and (ip.DstAddr == ${unreachable})" 16' -NoNewWindow`,
		undefined,
		{},
		"ignore"
	);
	print(`Accessing ${unreachable} is no longer possible!`, silent);
}

/**
 * Launch Docker compose project in the background.
 * Wait for some time to check if it started successfully and throw an error if it did.
 * @param {string} path Docker Compose standalone project file path.
 */
async function launchWhirlpool(whirlpool, silent) {
	print("Preparing whirlpool executable...", silent);
	runCommandForSystem(`docker compose -f ${DOCKER_COMPOSE_PATH} build ${DOCKER_COMPOSE_CONTAINER}`, `poetry poe -C ${VIRIDIAN_ALGAE_ROOT} bundle`, undefined, {
		SEASIDE_HOST_ADDRESS: whirlpool
	});
	print("Spawning whirlpool process...", silent);
	runCommandForSystem(
		`docker compose -f ${DOCKER_COMPOSE_PATH} up --detach ${DOCKER_COMPOSE_CONTAINER}`,
		`wsl -u root python3 ${convertPathToWSL(INSTALLER_PATH)} -g -o -a back whirlpool -l "${convertPathToWSL(CAERULEAN_WHIRLPOOL_ROOT)}" -r compile -v "${process.env.SEASIDE_API_KEY_ADMIN}" -a ${whirlpool} -e ${whirlpool} -i ${process.env.SEASIDE_API_PORT} --log-level DEBUG`,
		undefined,
		{
			SEASIDE_HOST_ADDRESS: whirlpool
		}
	);
	print("Waiting whirlpool to initiate...", silent);
	await sleep(DOCKER_COMPOSE_TIMEOUT);
	print("Whirlpool started!", silent);
}

// Script body:

// NB! Since the default route can not be changed in GitHub Actions, a different approach is taken here:
// Since, in fact, the only meaningful targets are whirlpool and echo docker containers, routes to them are changed instead of the default one.
// Viridian client determines the default route as the route to the caerulean address, so the router address is considered to be the default one.
const args = parseArguments();
const whirlpoolIP = getWhirlpoolIP(args.silent);
const { iface, address } = getOutputConnection(args.target);
await launchWhirlpool(whirlpoolIP, args.silent);
setupRouting(args.target, args.lower_port, args.higher_port, iface, address, args.silent);
print(whirlpoolIP, !args.silent);
