#include <gtk/gtk.h>

#include "interface.h"

// UI WIDGET:

static void seaside_editor_interface_init(NMVpnEditorInterface* iface_class);

G_DEFINE_TYPE_WITH_CODE(SeasideEditor, seaside_editor, G_TYPE_OBJECT, G_ADD_PRIVATE(SeasideEditor) G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR, seaside_editor_interface_init))

static gboolean check_validity(SeasideEditor* self, GError** error) {
	SeasideEditorPrivate *priv = seaside_editor_get_instance_private(self);
	char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(priv->filechooser_widget));

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
	g_message("Initializing SeasideVPN editor plugin (GTK3)...");

	SeasideEditorPrivate* priv = seaside_editor_get_instance_private(self);
	NMSettingVpn* s_vpn = nm_connection_get_setting_vpn(connection);

	GtkBuilder *builder = gtk_builder_new_from_resource("/org/freedesktop/network-manager-seasidevpn/dialog_gtk3.ui");
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
	priv->radio_typhoon = GTK_WIDGET(gtk_builder_get_object(builder, "radio_typhoon"));
	priv->radio_port = GTK_WIDGET(gtk_builder_get_object(builder, "radio_port"));

	if (!priv->filechooser_widget || !priv->radio_typhoon || !priv->radio_port) {
		g_object_unref(priv->widget);
		g_object_unref(builder);
		return FALSE;
	}

	GtkFileFilter *filter_cert = gtk_file_filter_new();
	gtk_file_filter_set_name(filter_cert, "Seaside Certificate Files (*.sea)");
	gtk_file_filter_add_pattern(filter_cert, "*.sea");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(priv->filechooser_widget), filter_cert);

	GtkFileFilter *filter_all = gtk_file_filter_new();
	gtk_file_filter_set_name(filter_all, "All Files");
	gtk_file_filter_add_pattern(filter_all, "*");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(priv->filechooser_widget), filter_all);

	if (s_vpn) {
		const char* cert_value = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE);
		if (cert_value) gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(priv->filechooser_widget), cert_value);

		const char* proto_value = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_PROTOCOL);
		if (proto_value) {
			if (g_strcmp0(proto_value, "typhoon") == 0)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(priv->radio_typhoon), TRUE);
			else if (g_strcmp0(proto_value, "port") == 0)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(priv->radio_port), TRUE);
			else {
				g_object_unref(priv->widget);
				g_object_unref(builder);
				return FALSE;
			}
		} else {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(priv->radio_typhoon), TRUE);
		}
	}

	g_signal_connect(G_OBJECT(priv->filechooser_widget), "file-set", G_CALLBACK(stuff_changed_cb), self);
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

	char* filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(priv->filechooser_widget));
	if (filename && strlen(filename)) nm_setting_vpn_add_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE, filename);
	g_free(filename);

	const char* protocol_value = "typhoon";
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(priv->radio_typhoon)))
		protocol_value = "typhoon";
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(priv->radio_port)))
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
