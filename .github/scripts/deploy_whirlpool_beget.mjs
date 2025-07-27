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
// Local path to the 'install.pyz' Whirlpool node installation script
const INSTALL_SCRIPT = join(import.meta.dirname, "..", "..", "viridian", "algae", "install.pyz");
// Default API port for whirlpool.
const DEFAULT_APIPORT = 8587;
// Certificates path.
const CERTS_PATH = "./certificates";

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
	if (token != null) options.headers["Authorization"] = `Bearer ${token}`;
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
	console.log(`${BOLD}Beget deployment script usage${RESET}:`);
	console.log(`\t${BLUE}-h --help${RESET}: Print this message again and exit.`);
	console.log(`\t${BLUE}-v --verbose${RESET}: Print viridian connection link in the end.`);
	console.log(`${BOLD}Required environment variables${RESET}:`);
	console.log(`\t${GREEN}BEGET_API_LOGIN${RESET}: Beget account owner login.`);
	console.log(`\t${GREEN}BEGET_API_PASSWORD${RESET}: Beget account owner password.`);
	console.log(`\t${GREEN}BEGET_SERVER_USER${RESET}: User name of the deployment server root user (default: "root").`);
	console.log(`\t${GREEN}BEGET_SERVER_KEY${RESET}: Password of the deployment server root user (also admin payload).`);
	console.log(`${BOLD}Optional environment variables${RESET}:`);
	console.log(`\t${GREEN}WHIRLPOOL_PAYLOAD${RESET}: Whirlpool viridian poyload (default: will be generated).`);
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
		execSync("poetry poe bundle", { cwd: dirname(INSTALL_SCRIPT) });
	} else console.log("Installation script found!");
}

function ensureCertificatesExist(ip) {
	if (!existsSync(CERTS_PATH)) {
		const scriptDir = dirname(INSTALL_SCRIPT);
		console.log("Certificates not found, generating...");
		try {
			execSync(`poetry run python3 -m setup.main --just-certs ${ip}`, { cwd: scriptDir });
		} catch (error) {
			throw Error(`Error generating certificates, try reinstalling poetry in ${scriptDir}!\nError: ${error}`);
		}
	} else console.log("Certificates found!");
}

/**
 * Parse CLI and environment flags and arguments.
 * Throw an error if one of the required arguments is missing.
 * The required arguments are: login, password, key.
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
	if (process.env.BEGET_API_LOGIN === undefined) throw new Error("Parameter 'login' is missing!");
	else values["login"] = process.env.BEGET_API_LOGIN;
	if (process.env.BEGET_API_PASSWORD === undefined) throw new Error("Parameter 'password' is missing!");
	else values["password"] = process.env.BEGET_API_PASSWORD;
	if (process.env.BEGET_SERVER_KEY === undefined) throw new Error("Parameter 'key' is missing!");
	else values["key"] = process.env.BEGET_SERVER_KEY;
	if (process.env.BEGET_SERVER_USER === undefined) values["user"] = DEFAULT_USER;
	else values["user"] = process.env.BEGET_SERVER_USER;
	if (process.env.WHIRLPOOL_PAYLOAD === undefined) values["payload"] = randomBytes(16).toString("hex");
	else values["payload"] = process.env.WHIRLPOOL_PAYLOAD;
	if (process.env.WHIRLPOOL_APIPORT === undefined) values["apiport"] = DEFAULT_APIPORT;
	else values["apiport"] = parseInt(process.env.WHIRLPOOL_APIPORT);
	return values;
}

/**
 * Receive Beget authentication token.
 * @param {string} login Beget user login
 * @param {string} password Beget user password
 * @returns {Promise<string>} authentication token string
 */
async function getToken(login, password) {
	console.log("Receiving beget authentication token...");
	const credentials = { login: login, password: password };
	const { token } = await post("https://api.beget.com/v1/auth", credentials);
	return token;
}

/**
 * Get the first VPS ID.
 * Throw an error if no VPS found.
 * @param {string} token authentication token
 * @returns {Promise<string>} server ID
 */
async function getServer(token) {
	console.log("Receiving beget test server ID...");
	const { vps } = await get("https://api.beget.com/v1/vps/server/list", token);
	if (vps.length < 1) throw new Error("No VPS found on account!");
	return vps[0].id;
}

/**
 * Get the first SSH key ID.
 * Throw an error if no SSH keys found.
 * @param {string} token authentication token
 * @returns {Promise<string>} SSH key ID
 */
async function getSSHKey(token) {
	console.log("Receiving beget test server SSH key...");
	const { keys } = await get("https://api.beget.com/v1/vps/sshKey", token);
	if (keys.length < 1) throw new Error("No SSH keys found on account!");
	return keys[0].id;
}

/**
 * Get the required Ubuntu version application ID.
 * Throw an error if no such version found.
 * @param {string} version required Ubuntu version
 * @param {string} token authentication token
 * @returns {Promise<string>} Ubuntu application ID
 */
async function getUbuntuAppID(version, token) {
	console.log("Receiving beget Ubuntu app ID...");
	const { software } = await get("https://api.beget.com/v1/vps/marketplace/software/list?display_name=Ubuntu", token);
	const application = software.find((x) => x.version === version);
	if (application === undefined) throw new Error(`No Ubuntu version ${version} found!`);
	return application.id;
}

/**
 * Reinstall Beget VPS.
 * Performs server reset, removes all the user files and reinstalls the OS.
 * @param {string} server VPS ID
 * @param {string} ssh ID of the SSH key that will be added to the VPS
 * @param {string} key new VPS root user password
 * @param {string} osID new VPS OS ID
 * @param {string} token authentication token
 * @returns {Promise<object>} new VPS configuration object
 */
async function reinstallServer(server, ssh, key, osID, token) {
	console.log("Reinstalling beget test server...");
	const params = { id: server, ssh_keys: [ssh], password: key, software: { id: osID } };
	const { vps } = await post(`https://api.beget.com/v1/vps/server/${server}/reinstall`, params, token);
	return vps;
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
async function waitForServer(ip, key, user, waitTimes, sleepTime) {
	console.log("Waiting for beget test server to come online...");
	const sshConn = new NodeSSH();
	for (let step = 0; step < waitTimes; step++) {
		try {
			return await sshConn.connect({ host: ip, username: user, password: key });
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
	ensureCertificatesExist();
	console.log("Ensuring python and pip are installed and available on server...");
	const pipRes = await sshConn.execCommand("sudo apt-get update && sudo apt-get install -y --no-install-recommends python3-dev python3-pip");
	if (pipRes.code != 0) throw new Error(`Python and pip installation failed, error code: ${pipRes.code}`);
	console.log("Determining current git branch...");
	const gitBranch = execSync("git rev-parse --abbrev-ref HEAD").toString().trim();
	console.log("Copying whirlpool installation script to beget test server...");
	await sshConn.putFile(INSTALL_SCRIPT, "install.pyz");
	console.log("Running whirlpool installation script on beget test server...");
	const installArgs = `-s ${gitBranch} -a ${whirlpoolIP} -e ${whirlpoolIP} -o ${ownerPayload} -v ${viridianPayload} -p ${apiport}`;
	const installRes = await sshConn.execCommand(`python3 install.pyz -o -g -a back whirlpool ${installArgs}`);
	if (installRes.code != 0) throw new Error(`Installation script failed, error code: ${installRes.code}`);
	console.log("Closing connection to beget test server...");
	sshConn.dispose();
}

// Script body:

const args = parseArguments();
const token = await getToken(args.login, args.password);

const serverID = await getServer(token);
const ssh = await getSSHKey(token);
const ubuntuID = await getUbuntuAppID(UBUNTU_VERISON, token);

const vps = await reinstallServer(serverID, ssh, args.key, ubuntuID, token);
const conn = await waitForServer(vps.ip_address, args.key, args.user, WAIT_TIMES, SLEEP_TIME);
await runDeployCommand(conn, vps.ip_address, args.key, args.payload, args.apiport);

if (args.verbose) console.log(`Viridian connection link is: ${YELLOW}${UNDER}seaside+whirlpool://${vps.ip_address}:${args.apiport}${RESET}`);
