#ifndef IFACE_COMMON_H
#define IFACE_COMMON_H

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <gtk/gtk.h>
#include <NetworkManager.h>

#include "editor.h"

#define SEASIDE_EDITOR_PLUGIN_ERROR NM_CONNECTION_ERROR
#define SEASIDE_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY NM_CONNECTION_ERROR_INVALID_PROPERTY

#define SEASIDE_PLUGIN_NAME "SeasideVPN"
#define SEASIDE_PLUGIN_DESC "An obscure P2P network PPTP VPN distributed system"

#define NM_SEASIDE_KEY_CERTIFICATE "certificate"
#define NM_SEASIDE_KEY_PROTOCOL "protocol"

typedef struct {
	GtkWidget *widget;
	GtkSizeGroup *group;
	gboolean window_added;
	char *certificate_filename;
	GtkWidget *label_selected_certificate;
	GtkWidget *radio_typhoon;
	GtkWidget *radio_port;
	GtkWidget *filechooser_widget;
} SeasideEditorPrivate;

void stuff_changed_cb(GtkWidget* widget, gpointer user_data) {
	g_signal_emit_by_name(SEASIDE_EDITOR(user_data), "changed");
}

NMVpnEditor *create_seaside_editor(NMConnection *connection, GError **error);

#endif /* IFACE_COMMON_H */
