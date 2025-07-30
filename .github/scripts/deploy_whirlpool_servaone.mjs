import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { execSync } from "node:child_process";

import fetch from "node-fetch";
import { NodeSSH } from "node-ssh";

import { sleep } from "./script_utils.mjs";

const BOLD = "\x1b[1m";
const UNDER = "\x1b[4m";
const BLUE = "\x1b[34m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RESET = "\x1b[0m";

// Number of SSH connection attempts to the newly recreated server
const WAIT_TIMES = 25;
// Time to sleep between SSH connection attempts to the newly recreated server
const SLEEP_TIME = 15;
// Ubuntu version to reinstall on the server
const UBUNTU_VERISON = "22.04";
// Default root user name.
const DEFAULT_USER = "root";
// Local path to the viridian algae project root
const ALGAE_PATH = join(import.meta.dirname, "..", "..", "viridian", "algae");
// Local path to the 'install.pyz' whirlpool node installation script
const INSTALL_SCRIPT = join(ALGAE_PATH, "install.pyz");
// Local certificates path
const LOCAL_CERTS_PATH = join(ALGAE_PATH, "certificates");
// Remote certificates path
const REMOTE_CERTS_PATH = "./certificates/caerulean";
// Default API port for whirlpool
const DEFAULT_APIPORT = 8587;
// Host name
const HOST_NAME = "SeasideVPN";

/**
 * Make HTTP request and return results parsed as JSON.
 * @param {string} url HTTP request address
 * @param {string} method HTTP request method (GET, POST, etc.)
 * @param {object | null} data data to send in the request body (only use this with appropriate methods!)
 * @param {string | null} token authorization token ("bearer" header will be sent)
 * @returns {Promise<object>} JSON response object
 */
async function request(url, method, data = null, token = null) {
	const options = { method: method, headers: { "User-Agent": "SeasideVPN Autodeployer" } };
	if (data != null) {
		options["body"] = JSON.stringify(data);
		options.headers["Content-Type"] = "application/json";
	}
	if (token != null) options.headers["x-xsrf-token"] = token;
	const response = await fetch(url, options);
	return await response.json();
}

/**
 * Make HTTP POST request and return results parsed as JSON.
 * @param {string} url HTTP POST request address
 * @param {object | null} data data to send in the request body
 * @param {string | null} token authorization token ("bearer" header will be sent)
 * @returns {Promise<object>} JSON response object
 */
async function post(url, data = {}, token = null) {
	return await request(url, "POST", data, token);
}

/**
 * Make HTTP GET request and return results parsed as JSON.
 * @param {string} url HTTP GET request address
 * @param {string | null} token authorization token ("bearer" header will be sent)
 * @returns {Promise<object>} JSON response object
 */
async function get(url, token = null) {
	return await request(url, "GET", null, token);
}

/**
 * Print usage help message and exit with code 0.
 */
function printHelpMessage() {
	console.log(`${BOLD}ServaOne deployment script usage${RESET}:`);
	console.log(`\t${BLUE}-h --help${RESET}: Print this message again and exit.`);
	console.log(`\t${BLUE}-v --verbose${RESET}: Print viridian connection link in the end.`);
	console.log(`${BOLD}Required environment variables${RESET}:`);
	console.log(`\t${GREEN}SERVAONE_API_EMAIL${RESET}: ServaOne account owner email.`);
	console.log(`\t${GREEN}SERVAONE_API_TOKEN${RESET}: ServaOne account owner password.`);
	console.log(`\t${GREEN}SERVAONE_SERVER_USER${RESET}: ServaOne server root user (default: "root").`);
	console.log(`\t${GREEN}SERVAONE_SERVER_PASSWORD${RESET}: ServaOne server root user password.`);
	console.log(`\t${GREEN}SERVAONE_SERVER_KEY${RESET}: Seaside whirlpool node owner API key.`);
	console.log(`${BOLD}Optional environment variables${RESET}:`);
	console.log(`\t${GREEN}WHIRLPOOL_PAYLOAD${RESET}: Seaside whirlpool node admin API keys (default: will be generated).`);
	console.log(`\t${GREEN}WHIRLPOOL_APIPORT${RESET}: Whirlpool API port (default: ${DEFAULT_APIPORT}).`);
	process.exit(0);
}

/**
 * Generate python installation script (just compress the installation module with 'zipapp') if it does not exist.
 * The installation script '.pyz' will be uploaded to the server.
 */
function ensureInstallationScript() {
	if (!existsSync(INSTALL_SCRIPT)) {
		console.log("Installation script not found, generating...");
		try {
			execSync("poetry poe bundle", { cwd: ALGAE_PATH });
		} catch (error) {
			throw Error(`Error generating installation script, try reinstalling poetry in ${ALGAE_PATH}!\nError: ${error}`);
		}
	} else console.log("Installation script found!");
}

function ensureCertificatesExist(ip) {
	if (!existsSync(LOCAL_CERTS_PATH)) {
		console.log("Certificates not found, generating...");
		try {
			execSync(`poetry poe setup --just-certs ${ip}`, { cwd: ALGAE_PATH });
		} catch (error) {
			throw Error(`Error generating certificates, try reinstalling poetry in ${ALGAE_PATH}!\nError: ${error}`);
		}
	} else console.log("Certificates found!");
}

/**
 * Parse CLI and environment flags and arguments.
 * Throw an error if one of the required arguments is missing.
 * The required arguments are: email, password, key.
 * @returns {object} object, containing all the arguments parsed
 */
function parseArguments() {
	const options = {
		help: {
			type: "boolean",
			short: "h",
			default: false
		},
		verbose: {
			type: "boolean",
			short: "v",
			default: true
		}
	};
	const { values } = parseArgs({ options });
	if (values.help) printHelpMessage();
	if (process.env.SERVAONE_API_EMAIL === undefined) throw new Error("Parameter 'email' is missing!");
	else values["email"] = process.env.SERVAONE_API_EMAIL;
	if (process.env.SERVAONE_API_TOKEN === undefined) throw new Error("Parameter 'token' is missing!");
	else values["token"] = process.env.SERVAONE_API_TOKEN;
	if (process.env.SERVAONE_SERVER_PASSWORD === undefined) throw new Error("Parameter 'password' is missing!");
	else values["password"] = process.env.SERVAONE_SERVER_PASSWORD;
	if (process.env.SERVAONE_SERVER_KEY === undefined) throw new Error("Parameter 'key' is missing!");
	else values["key"] = process.env.SERVAONE_SERVER_KEY;
	if (process.env.SERVAONE_SERVER_USER === undefined) values["user"] = DEFAULT_USER;
	else values["user"] = process.env.SERVAONE_SERVER_USER;
	if (process.env.WHIRLPOOL_PAYLOAD === undefined) values["payload"] = randomBytes(16).toString("hex");
	else values["payload"] = process.env.WHIRLPOOL_PAYLOAD;
	if (process.env.WHIRLPOOL_APIPORT === undefined) values["apiport"] = DEFAULT_APIPORT;
	else values["apiport"] = parseInt(process.env.WHIRLPOOL_APIPORT);
	return values;
}

/**
 * Receive ServaOne authentication token.
 * @param {string} email ServaOne user email
 * @param {string} password ServaOne user password
 * @returns {Promise<string>} authentication token string
 */
async function getToken(email, password) {
	console.log("Receiving ServaOne authentication token...");
	const credentials = { email: email, password: password };
	const { token } = await post("https://vm.serva.one/auth/v4/public/token", credentials);
	return token;
}

/**
 * Get the first VPS ID.
 * Throw an error if no VPS found.
 * @param {string} token authentication token
 * @returns {Promise<string>} host ID
 */
async function getHostID(token) {
	console.log("Receiving ServaOne test host ID...");
	const list = await get(`https://vm.serva.one/vm/v3/host?where=(name+EQ+'${HOST_NAME}')`, token);
	if (list.size < 1) throw new Error("No VPS found on account!");
	const vps = list.list[0];
	return { serverID: vps.id, serverDisk: vps.disk.id, serverAddress: vps.ip4[0].ip };
}

/**
 * Get the required Ubuntu version application ID.
 * Throw an error if no such version found.
 * @param {string} version required Ubuntu version
 * @param {string} token authentication token
 * @returns {Promise<string>} Ubuntu application ID
 */
async function getUbuntuOsID(version, token) {
	console.log("Receiving ServaOne Ubuntu app ID...");
	const list = await get(`https://vm.serva.one/vm/v3/os?where=(name+EQ+'Ubuntu ${version}')`, token);
	if (list.size < 1) throw new Error("No OS found available!");
	return list.list[0].id;
}

/**
 * Reinstall ServaOne VPS.
 * Performs server reset, removes all the user files and reinstalls the OS.
 * @param {string} server VPS ID
 * @param {string} ssh ID of the SSH key that will be added to the VPS
 * @param {string} key new VPS root user password
 * @param {string} osID new VPS OS ID
 * @param {string} token authentication token
 * @returns {Promise<object>} new VPS configuration object
 */
async function reinstallServer(server, password, disk, osID, token) {
	console.log("Reinstalling ServaOne test server...");
	const reinstallParams = { os: osID, send_email_mode: "default", password: password, disk: disk };
	const task = await post(`https://vm.serva.one/vm/v3/host/${server}/reinstall`, reinstallParams, token);
	if (task.id === undefined) throw Error(`Error reinstalling server: ${JSON.stringify(task)}`);
}

/**
 * Wait until VPS server comes online and becomes available for SSH connection.
 * Perform several connection attempts, sleep between 'sleepTime' them.
 * Throw an error if the connection will not be established after 'waitTimes' attempts.
 * @param {string} ip VPS IP (or host name) to connect to
 * @param {string} key root user password
 * @param {string} user root user name
 * @param {int} waitTimes number of SSH connection attempts
 * @param {int} sleepTime time to sleep between connection attempts
 * @returns {Promise<NodeSSH>} established SSH connection
 */
async function waitForServer(id, ip, password, user, waitTimes, sleepTime, token) {
	console.log("Waiting for ServaOne test server to come online...");
	const sshConn = new NodeSSH();
	for (let step = 0; step < waitTimes; step++) {
		try {
			const vps = await get(`https://vm.serva.one/vm/v3/host/${id}`, token);
			if (vps.state !== "active") throw Error("Server is still restarting...");
			return await sshConn.connect({ host: ip, username: user, password: password, timeout: sleepTime });
		} catch {
			await sleep(sleepTime);
		}
	}
	throw new Error(`Connection wasn't established after ${waitTimes * sleepTime} seconds!`);
}

/**
 * Deploy Whirlpool node to VPS.
 * Copy whirlpool installation script from the local source.
 * Run the script and prepare environment (generate 'conf.env' file, create certificates if needed).
 * Run the node in the background and close SSH connection.
 * @param {NodeSSH} sshConn SSH connection to use
 * @param {string} certsPath local path to store generated self-signed CA certificates
 * @param {string} whirlpoolIP server IP address for external VPN connections
 * @param {string} ownerPayload deployment server owner payload
 * @param {string} viridianPayload deployment server viridian payload
 * @param {string} apiport whirlpool API port
 */
async function runDeployCommand(sshConn, whirlpoolIP, ownerPayload, viridianPayload, apiport) {
	console.log("Ensuring installation script exists...");
	ensureInstallationScript();
	console.log("Ensuring certificates exist...");
	ensureCertificatesExist(whirlpoolIP);
	console.log("Ensuring python and pip are installed and available on server...");
	const pipRes = await sshConn.execCommand("sudo apt-get update && sudo apt-get install -y --no-install-recommends python3-dev python3-pip");
	if (pipRes.code != 0) throw new Error(`Python and pip installation failed, error code: ${pipRes.code}`);
	console.log("Determining current git branch...");
	const gitBranch = execSync("git rev-parse --abbrev-ref HEAD").toString().trim();
	console.log("Copying whirlpool installation script to ServaOne test server...");
	await sshConn.putFile(INSTALL_SCRIPT, "install.pyz");
	console.log("Copying whirlpool certificates to ServaOne test server...");
	await sshConn.putDirectory(LOCAL_CERTS_PATH, "certificates", { recursive: true });
	console.log("Running whirlpool installation script on ServaOne test server...");
	const installArgs = `-s ${gitBranch} -a ${whirlpoolIP} -e ${whirlpoolIP} -o ${ownerPayload} -v ${viridianPayload} -p ${apiport}`;
	const installRes = await sshConn.execCommand(`python3 install.pyz -o -a back whirlpool ${installArgs} --certificates-path ${REMOTE_CERTS_PATH}`);
	if (installRes.code != 0) throw new Error(`Installation script failed, error code: ${installRes.code}\n\nSTDOUT:\n${installRes.stdout}\nSTDERR:\n${installRes.stderr}`);
	console.log("Closing connection to ServaOne test server...");
	sshConn.dispose();
}

// Script body:

const args = parseArguments();
const token = await getToken(args.email, args.token);

const { serverID, serverDisk, serverAddress } = await getHostID(token);
const osID = await getUbuntuOsID(UBUNTU_VERISON, token);
await reinstallServer(serverID, args.password, serverDisk, osID, token);

const conn = await waitForServer(serverID, serverAddress, args.password, args.user, WAIT_TIMES, SLEEP_TIME, token);
await runDeployCommand(conn, serverAddress, args.key, args.payload, args.apiport);

if (args.verbose) console.log(`Node is available at: ${YELLOW}${UNDER}${serverAddress}:${args.apiport}${RESET}`);
