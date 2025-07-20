const dns = require("dns");
const net = require("net");

const target = process.argv[2];

if (!target) {
	console.error("Usage: node resolve-target.js <target>");
	process.exit(1);
}

// Check if target is already a valid IP address
if (net.isIP(target)) {
	console.log(target);
	process.exit(0);
}

// Otherwise, resolve the target as a host name
dns.lookup(target, (err, address, _) => {
	if (err) {
		console.error(`Could not resolve ${target}:`, err.message);
		process.exit(1);
	}
	console.log(address);
});
