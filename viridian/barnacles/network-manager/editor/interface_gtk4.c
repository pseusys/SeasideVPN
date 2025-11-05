#include <gtk/gtk.h>

#include "interface.h"

// UI WIDGET:

static void seaside_editor_interface_init(NMVpnEditorInterface* iface_class);

G_DEFINE_TYPE_WITH_CODE(SeasideEditor, seaside_editor, G_TYPE_OBJECT, G_ADD_PRIVATE(SeasideEditor) G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR, seaside_editor_interface_init))

typedef struct {
	GMainLoop *loop;
	GFile *file;
} DialogData;

static void on_file_dialog_done(GObject *source_object, GAsyncResult *res, gpointer user_data) {
	DialogData *data = (DialogData *)user_data;
	GError *error = NULL;

	data->file = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(source_object), res, &error);
	if (error) {
		g_warning("File dialog error: %s", error->message);
		g_error_free(error);
	}

	g_main_loop_quit(data->loop);
}

static void choose_certificate_cb(GtkWidget *button, gpointer user_data) {
	SeasideEditor *self = SEASIDE_EDITOR(user_data);
	SeasideEditorPrivate *priv = seaside_editor_get_instance_private(self);

	GtkFileDialog *dialog = gtk_file_dialog_new();
	gtk_file_dialog_set_title(dialog, "Select Seaside Certificate");
	gtk_file_dialog_set_modal(dialog, TRUE);
	gtk_file_dialog_set_accept_label(dialog, "_Open");

	GListStore *filters = g_list_store_new(GTK_TYPE_FILE_FILTER);

	GtkFileFilter *filter_cert = gtk_file_filter_new();
	gtk_file_filter_set_name(filter_cert, "Seaside Certificate Files (*.sea)");
	gtk_file_filter_add_pattern(filter_cert, "*.sea");
	g_list_store_append(filters, filter_cert);
	g_object_unref(filter_cert);

	GtkFileFilter *filter_all = gtk_file_filter_new();
	gtk_file_filter_set_name(filter_all, "All Files");
	gtk_file_filter_add_pattern(filter_all, "*");
	g_list_store_append(filters, filter_all);
	g_object_unref(filter_all);

	gtk_file_dialog_set_filters(dialog, G_LIST_MODEL(filters));
	g_object_unref(filters);

	if (priv->certificate_filename) {
		GFile *initial_file = g_file_new_for_path(priv->certificate_filename);
		gtk_file_dialog_set_initial_file(dialog, initial_file);
		g_object_unref(initial_file);
	}

	DialogData data = { g_main_loop_new(NULL, FALSE), NULL };
	gtk_file_dialog_open(dialog, NULL, NULL, on_file_dialog_done, &data);  // Parent is NULL; adjust if needed

	g_main_loop_run(data.loop);

	if (data.file) {
		char *filename = g_file_get_path(data.file);
		g_free(priv->certificate_filename);
		priv->certificate_filename = filename;
		gtk_label_set_text(GTK_LABEL(priv->label_selected_certificate), g_path_get_basename(filename));
		stuff_changed_cb(NULL, self);
		g_object_unref(data.file);
	}

	g_main_loop_unref(data.loop);
	g_object_unref(dialog);
}

static gboolean check_validity(SeasideEditor* self, GError** error) {
	SeasideEditorPrivate *priv = seaside_editor_get_instance_private(self);
	char *filename = g_strdup(priv->certificate_filename);

	if (!filename || !strlen(filename)) {
		g_warning("Error reading filename!");
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, SEASIDE_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY, "No certificate file selected");
		g_free(filename);
		return FALSE;
	}

	if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
		g_warning("Error checking filename existence!");
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, SEASIDE_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY, "Selected certificate file does not exist: %s", filename);
		g_free(filename);
		return FALSE;
	}

	g_free(filename);
	return TRUE;
}

static gboolean init_editor_plugin(SeasideEditor* self, NMConnection* connection, GError** error) {
	g_message("Initializing SeasideVPN editor plugin (GTK4)...");

	SeasideEditorPrivate* priv = seaside_editor_get_instance_private(self);
	NMSettingVpn* s_vpn = nm_connection_get_setting_vpn(connection);

	GtkBuilder *builder = gtk_builder_new_from_resource("/org/freedesktop/network-manager-seasidevpn/dialog_gtk4.ui");
	if (!builder) {
		g_warning("Error loading SeasideVPN editor interface UI!");
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
		return FALSE;
	}

	priv->widget = GTK_WIDGET(gtk_builder_get_object(builder, "root_box"));
	if (!priv->widget) {
		g_warning("Error building SeasideVPN editor interface UI!");
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
		g_object_unref(builder);
		return FALSE;
	}
	g_object_ref_sink(priv->widget);

	priv->filechooser_widget = GTK_WIDGET(gtk_builder_get_object(builder, "filechooser_certificate"));
	priv->label_selected_certificate = GTK_WIDGET(gtk_builder_get_object(builder, "label_selected_certificate"));
	priv->radio_typhoon = GTK_WIDGET(gtk_builder_get_object(builder, "radio_typhoon"));
	priv->radio_port = GTK_WIDGET(gtk_builder_get_object(builder, "radio_port"));

	if (!priv->filechooser_widget || !priv->label_selected_certificate || !priv->radio_typhoon || !priv->radio_port) {
		g_object_unref(priv->widget);
		g_object_unref(builder);
		return FALSE;
	}

	if (s_vpn) {
		const char* cert_value = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE);
		if (cert_value) {
			priv->certificate_filename = g_strdup(cert_value);
			gtk_label_set_text(GTK_LABEL(priv->label_selected_certificate), g_path_get_basename(cert_value));
		}

		const char* proto_value = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_PROTOCOL);
		if (proto_value) {
			if (g_strcmp0(proto_value, "typhoon") == 0)
				gtk_check_button_set_active(GTK_CHECK_BUTTON(priv->radio_typhoon), TRUE);
			else if (g_strcmp0(proto_value, "port") == 0)
				gtk_check_button_set_active(GTK_CHECK_BUTTON(priv->radio_port), TRUE);
			else {
				g_object_unref(priv->widget);
				g_object_unref(builder);
				return FALSE;
			}
		} else {
			gtk_check_button_set_active(GTK_CHECK_BUTTON(priv->radio_typhoon), TRUE);
		}
	}

	g_signal_connect(G_OBJECT(priv->filechooser_widget), "clicked", G_CALLBACK(choose_certificate_cb), self);
	g_signal_connect(G_OBJECT(priv->radio_typhoon), "toggled", G_CALLBACK(stuff_changed_cb), self);
	g_signal_connect(G_OBJECT(priv->radio_port), "toggled", G_CALLBACK(stuff_changed_cb), self);

	g_object_unref(builder);
	return TRUE;
}

static GObject* get_widget(NMVpnEditor* iface) {
	SeasideEditor* self = SEASIDE_EDITOR(iface);
	SeasideEditorPrivate* priv = seaside_editor_get_instance_private(self);
	return G_OBJECT(priv->widget);
}

static gboolean update_connection(NMVpnEditor* iface, NMConnection* connection, GError** error) {
	g_message("Updating SeasideVPN connection...");

	SeasideEditor* self = SEASIDE_EDITOR(iface);
	SeasideEditorPrivate* priv = seaside_editor_get_instance_private(self);
	if (!check_validity(self, error)) return FALSE;

	NMSettingVpn* s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
	g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, SEASIDE_PLUGIN_SERVICE, NULL);

	if (priv->certificate_filename && strlen(priv->certificate_filename)) nm_setting_vpn_add_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE, priv->certificate_filename);

	const char* protocol_value = "typhoon";
	if (gtk_check_button_get_active(GTK_CHECK_BUTTON(priv->radio_typhoon)))
		protocol_value = "typhoon";
	else if (gtk_check_button_get_active(GTK_CHECK_BUTTON(priv->radio_port)))
		protocol_value = "port";
	nm_setting_vpn_add_data_item(s_vpn, NM_SEASIDE_KEY_PROTOCOL, protocol_value);

	nm_connection_add_setting(connection, NM_SETTING(s_vpn));
	return TRUE;
}

static NMVpnEditor* nm_vpn_editor_interface_new(NMConnection* connection, GError** error) {
	g_message("Constructing SeasideVPN editor interface...");
	if (error) g_return_val_if_fail(*error == NULL, NULL);

	NMVpnEditor* object = g_object_new(SEASIDE_TYPE_EDITOR, NULL);
	if (!object) {
		g_warning("Error creating SeasideVPN editor interface!");
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, 0, "Error creating SeasideVPN editor interface");
		return NULL;
	}

	if (!init_editor_plugin(SEASIDE_EDITOR(object), connection, error)) {
		g_warning("Error initializing SeasideVPN editor interface UI!");
		g_object_unref(object);
		return NULL;
	}
	return object;
}

static void dispose(GObject* object) {
	SeasideEditor* self = SEASIDE_EDITOR(object);
	SeasideEditorPrivate* priv = seaside_editor_get_instance_private(SEASIDE_EDITOR(self));

	g_free(priv->certificate_filename);
	if (priv->group) g_object_unref(priv->group);
	if (priv->widget) g_object_unref(priv->widget);

	G_OBJECT_CLASS(seaside_editor_parent_class)->dispose(object);
}

static void seaside_editor_class_init (SeasideEditorClass* req_class) {
	GObjectClass* object_class = G_OBJECT_CLASS(req_class);
	object_class->dispose = dispose;
}

static void seaside_editor_init(SeasideEditor* plugin) {}

static void seaside_editor_interface_init(NMVpnEditorInterface* iface_class) {
	g_message("Initializing SeasideVPN editor interface...");

	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

G_MODULE_EXPORT NMVpnEditor *create_seaside_editor(NMConnection *connection, GError **error) {
	return nm_vpn_editor_interface_new(connection, error);
}
