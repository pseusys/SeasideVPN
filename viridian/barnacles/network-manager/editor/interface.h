#ifndef IFACE_COMMON_H
#define IFACE_COMMON_H

#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <gtk/gtk.h>
#include <NetworkManager.h>

#include "editor.h"

typedef struct {
	GtkWidget *widget;
	GtkSizeGroup *group;
	gboolean window_added;
	char *certificate_filedata;
	char *protocol_name;
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
