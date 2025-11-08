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

NMVpnEditor *create_seaside_editor(NMConnection *connection, GError **error);

#endif /* IFACE_COMMON_H */
