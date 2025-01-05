/**
 * Sleep for the specified time (in seconds).
 * @param {int} time to sleep (in seconds)
 * @returns {Promise<void>}
 */
export async function sleep(seconds) {
	return new Promise((r) => setTimeout(r, seconds * 1000));
}
