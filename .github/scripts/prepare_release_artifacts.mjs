import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { renameSync } from "node:fs";
import { execSync } from "node:child_process";

import { globSync } from "glob";

const BOLD = "\x1b[1m";
const BLUE = "\x1b[34m";
const RESET = "\x1b[0m";

/**
 * Print usage help message and exit with code 0.
 */
function printHelpMessage() {
	console.log(`${BOLD}File renaming script useage${RESET}:`);
	console.log(`\t${BLUE}-h --help${RESET}: Print this message again and exit.`);
	console.log(`\t${BLUE}[glob...]${RESET}: Files to remove current git version from.`);
	process.exit(0);
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
		}
	};
	const { values, positionals } = parseArgs({ options, allowPositionals: true });
	if (values.help) printHelpMessage();
	return positionals;
}

/**
 * Retrieve current Git branch name (just like 'Create Executable Branch Name' action in 'build.yml' does).
 * @returns {string} current branch name
 */
function getVersionValue() {
	const gitBranch = execSync("git describe --exact-match --tags").toString().trim();
	const cleanVersion = gitBranch.replaceAll("/", "-");
	console.log(`Current version: ${cleanVersion}`);
	return cleanVersion;
}

/**
 * Rename files in a glob, removing current Git version from their names.
 * @param {string} glob file glob to rename
 * @param {string} version Git version to remove
 */
function renameFileGlob(glob, version) {
	const globPath = join(dirname(import.meta.dirname), "..", "..", glob);
	for (const file of globSync(globPath)) {
		const newName = file.replaceAll(`-${version}`, "");
		console.log(`Renaming '${file}' to '${newName}'...`);
		renameSync(file, newName);
	}
}

// Script body:

const positionals = parseArguments();
const version = getVersionValue();

for (const glob of positionals) renameFileGlob(glob, version);
