#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include <NetworkManager.h>

#define SEASIDE_EDITOR_PLUGIN_ERROR NM_CONNECTION_ERROR
#define SEASIDE_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY NM_CONNECTION_ERROR_INVALID_PROPERTY

#include "editor.h"

#define SEASIDE_PLUGIN_NAME "SeasideVPN"
#define SEASIDE_PLUGIN_DESC "An obscure P2P network PPTP VPN distributed system"

#define NM_SEASIDE_KEY_CERTIFICATE "certificate"
#define NM_SEASIDE_KEY_PROTOCOL "protocol" 

// PLUGIN:

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void seaside_editor_plugin_interface_init(NMVpnEditorPluginInterface* iface_class);

G_DEFINE_TYPE_EXTENDED(SeasideEditorPlugin, seaside_editor_plugin, G_TYPE_OBJECT, 0, G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN, seaside_editor_plugin_interface_init))

// UI WIDGET:

static void seaside_editor_interface_init(NMVpnEditorInterface* iface_class);

typedef struct {
	GtkBuilder *builder;
	GtkWidget *widget;
	GtkSizeGroup *group;
	gboolean window_added;
} SeasideEditorPrivate;

G_DEFINE_TYPE_WITH_CODE(SeasideEditor, seaside_editor, G_TYPE_OBJECT, G_ADD_PRIVATE(SeasideEditor) G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR, seaside_editor_interface_init))

typedef enum {
	NM_SEASIDE_IMPORT_EXPORT_ERROR_UNKNOWN = 0,
	NM_SEASIDE_IMPORT_EXPORT_ERROR_NOT_SEASIDE,
	NM_SEASIDE_IMPORT_EXPORT_ERROR_BAD_DATA,
} NMSeasideImportError;

// CODE:

#define NM_SEASIDE_IMPORT_EXPORT_ERROR nm_seaside_import_export_error_quark()

static GQuark nm_seaside_import_export_error_quark(void) {
	static GQuark quark = 0;
	if (G_UNLIKELY(quark == 0)) quark = g_quark_from_static_string("nm-seaside-import-export-error-quark");
	return quark;
}

static NMConnection* import(NMVpnEditorPlugin* iface, const char* path, GError** error) {
	g_message("Importing SeasideVPN connection...");

	NMConnection* connection = nm_simple_connection_new();

	NMSettingConnection* s_con = NM_SETTING_CONNECTION(nm_setting_connection_new());
	nm_connection_add_setting(connection, NM_SETTING(s_con));

	NMSettingVpn* s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
	g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, SEASIDE_PLUGIN_SERVICE, NULL);
	nm_connection_add_setting(connection, NM_SETTING(s_vpn));

	NMSettingIP4Config* s_ip4 = NM_SETTING_IP4_CONFIG(nm_setting_ip4_config_new());
	nm_connection_add_setting(connection, NM_SETTING(s_ip4));

	nm_setting_vpn_add_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE, path);
	return connection;
}

static gboolean check_validity(SeasideEditor* self, GError** error) {
	SeasideEditorPrivate *priv = seaside_editor_get_instance_private(self);
	GtkWidget* widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "filechooser_certificate"));
	char* filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(widget));

    if (!filename || !strlen(filename)) {
        g_set_error (error, SEASIDE_EDITOR_PLUGIN_ERROR, SEASIDE_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY, "No certificate file selected");
        g_free(filename);
        return FALSE;
    }

    if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
        g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, SEASIDE_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY, "Selected certificate file does not exist: %s", filename);
        g_free(filename);
        return FALSE;
    }

    g_free(filename);
	return TRUE;
}

static void stuff_changed_cb(GtkWidget* widget, gpointer user_data) {
	g_signal_emit_by_name(SEASIDE_EDITOR(user_data), "changed");
}

static gboolean init_editor_plugin(SeasideEditor* self, NMConnection* connection, GError** error) {
	g_message("Initializing SeasideVPN editor plugin...");

	SeasideEditorPrivate* priv = seaside_editor_get_instance_private(self);
	NMSettingVpn* s_vpn = nm_connection_get_setting_vpn(connection);

	GtkWidget* filechooser = GTK_WIDGET(gtk_builder_get_object(priv->builder, "filechooser_certificate"));
	if (!filechooser) return FALSE;

	GtkFileFilter *filter_cert = gtk_file_filter_new();
	gtk_file_filter_set_name(filter_cert, "Seaside Certificate Files (*.sea)");
	gtk_file_filter_add_pattern(filter_cert, "*.sea");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(filechooser), filter_cert);

	GtkFileFilter *filter_all = gtk_file_filter_new();
	gtk_file_filter_set_name(filter_all, "All Files");
	gtk_file_filter_add_pattern(filter_all, "*");
	gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(filechooser), filter_all);

	GtkRadioButton* radio_typhoon = GTK_RADIO_BUTTON(gtk_builder_get_object(priv->builder, "radio_typhoon"));
	GtkRadioButton* radio_port = GTK_RADIO_BUTTON(gtk_builder_get_object(priv->builder, "radio_port"));
	if (!radio_typhoon || !radio_port) return FALSE;

	if (s_vpn) {
		const char* cert_value = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE);
		if (cert_value) gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(filechooser), cert_value);

		const char* proto_value = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_PROTOCOL);
		if (proto_value) {
			if (radio_typhoon && g_strcmp0(proto_value, "typhoon") == 0)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_typhoon), TRUE);
			else if (radio_port && g_strcmp0(proto_value, "port") == 0)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_port), TRUE);
			else
				return FALSE;
		} else {
			if (radio_typhoon)
				gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio_typhoon), TRUE);
		}
	}

	g_signal_connect(G_OBJECT(filechooser), "file-set", G_CALLBACK(stuff_changed_cb), self);
	g_signal_connect(G_OBJECT(radio_typhoon), "toggled", G_CALLBACK(stuff_changed_cb), self);
	g_signal_connect(G_OBJECT(radio_port), "toggled", G_CALLBACK(stuff_changed_cb), self);
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

	GtkWidget* filechooser = GTK_WIDGET(gtk_builder_get_object(priv->builder, "filechooser_certificate"));
	const char* filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(filechooser));
	if (filename && strlen(filename)) nm_setting_vpn_add_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE, filename);

	GtkRadioButton* radio_typhoon = GTK_RADIO_BUTTON(gtk_builder_get_object(priv->builder, "radio_typhoon"));
	GtkRadioButton* radio_port = GTK_RADIO_BUTTON(gtk_builder_get_object(priv->builder, "radio_port"));

	const char* protocol_value = "typhoon";
	if (radio_typhoon && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(radio_typhoon)))
		protocol_value = "typhoon";
	else if (radio_port && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(radio_port)))
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
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, 0, "could not create seaside object");
		return NULL;
	}

	SeasideEditorPrivate* priv = seaside_editor_get_instance_private(SEASIDE_EDITOR(object));
	priv->builder = gtk_builder_new();

	if (!gtk_builder_add_from_resource(priv->builder, "/org/freedesktop/network-manager-seasidevpn/dialog.ui", error)) {
		g_object_unref(object);
		return NULL;
	}

	priv->widget = GTK_WIDGET(gtk_builder_get_object(priv->builder, "root_box"));
	if (!priv->widget) {
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, 0, "could not load UI widget");
		g_object_unref(object);
		return NULL;
	}
	g_object_ref_sink(priv->widget);

	if (!init_editor_plugin(SEASIDE_EDITOR(object), connection, error)) {
		g_object_unref(object);
		return NULL;
	}
	return object;
}

static void dispose(GObject* object) {
	SeasideEditor* self = SEASIDE_EDITOR(object);
	SeasideEditorPrivate* priv = seaside_editor_get_instance_private(SEASIDE_EDITOR(self));

	if (priv->group) g_object_unref(priv->group);
	if (priv->widget) g_object_unref(priv->widget);
	if (priv->builder) g_object_unref(priv->builder);

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

static guint32 get_capabilities (NMVpnEditorPlugin* iface) {
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT;
}

static NMVpnEditor* get_editor(NMVpnEditorPlugin* iface, NMConnection* connection, GError** error) {
	return nm_vpn_editor_interface_new(connection, error);
}

static void get_property(GObject* object, guint prop_id, GValue* value, GParamSpec* pspec) {
	switch (prop_id) {
		case PROP_NAME:
			g_value_set_string(value, SEASIDE_PLUGIN_NAME);
			break;
		case PROP_DESC:
			g_value_set_string(value, SEASIDE_PLUGIN_DESC);
			break;
		case PROP_SERVICE:
			g_value_set_string(value, SEASIDE_PLUGIN_SERVICE);
			break;
		default:
			G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
			break;
	}
}

static void seaside_editor_plugin_class_init(SeasideEditorPluginClass* req_class) {
	g_message("Constructing SeasideVPN plugin class interface...");

	GObjectClass* object_class = G_OBJECT_CLASS(req_class);
	object_class->get_property = get_property;

	g_object_class_override_property(object_class, PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);
	g_object_class_override_property(object_class, PROP_DESC, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
	g_object_class_override_property(object_class, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void seaside_editor_plugin_init(SeasideEditorPlugin* plugin) {}

static void seaside_editor_plugin_interface_init(NMVpnEditorPluginInterface* iface_class) {
	g_message("Constructing SeasideVPN plugin interface interface...");

	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = import;
}

G_MODULE_EXPORT NMVpnEditor* nm_vpn_editor_factory_seaside(NMVpnEditorPlugin *editor_plugin, NMConnection* connection, GError** error) {
	g_message("SeasideVPN editor factory called...");
	if (error) g_return_val_if_fail(*error == NULL, NULL);
	return nm_vpn_editor_interface_new(connection, error);
}


G_MODULE_EXPORT NMVpnEditorPlugin* nm_vpn_editor_plugin_factory(GError** error) {
	g_message("SeasideVPN editor plugin factory called...");
	if (error) g_return_val_if_fail(*error == NULL, NULL);
	return g_object_new(SEASIDE_TYPE_EDITOR_PLUGIN, NULL);
}
