#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define SECRET_API_SUBJECT_TO_CHANGE
#include <libsecret/secret.h>

#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h>


static void
wait_for_quit (void)
{
	GString *str;
	char c;
	ssize_t n;
	time_t start;

	str = g_string_sized_new (10);
	start = time (NULL);
	do {
		errno = 0;
		n = read (0, &c, 1);
		if (n == 0 || (n < 0 && errno == EAGAIN))
			g_usleep (G_USEC_PER_SEC / 10);
		else if (n == 1) {
			g_string_append_c (str, c);
			if (strstr (str->str, "QUIT") || (str->len > 10))
				break;
		} else
			break;
	} while (time (NULL) < start + 20);
	g_string_free (str, TRUE);
}


int
main (int argc, char *argv[])
{
    char *vpn_name = NULL, *vpn_uuid = NULL;
	GHashTable *data = NULL, *secrets = NULL;

	GOptionContext *context;
	GOptionEntry entries[] = {
		{ "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL },
		{ "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL },
		{ NULL }
	};

	context = g_option_context_new ("- seaside auth dialog");
	g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);


	if (!nm_vpn_service_plugin_read_vpn_details (0, &data, &secrets)) {
		fprintf (stderr, "Failed to read '%s' (%s) data and secrets from stdin.\n", vpn_name, vpn_uuid);
		return 1;
	}

	fprintf(stdout, "\n\n");
    fflush(stdout);
	wait_for_quit();

	if (data)
		g_hash_table_unref (data);
	if (secrets)
		g_hash_table_unref (secrets);
	return 0;
}
