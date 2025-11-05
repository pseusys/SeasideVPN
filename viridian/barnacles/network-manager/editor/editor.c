#include <dlfcn.h>

#include <NetworkManager.h>

#include "editor.h"

// PLUGIN:

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void seaside_editor_plugin_interface_init(NMVpnEditorPluginInterface* iface_class);

G_DEFINE_TYPE_EXTENDED(SeasideEditorPlugin, seaside_editor_plugin, G_TYPE_OBJECT, 0, G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN, seaside_editor_plugin_interface_init))

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

static guint32 get_capabilities (NMVpnEditorPlugin* iface) {
    g_message("Checking SeasideVPN capabilities...");
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static NMVpnEditor* get_editor(NMVpnEditorPlugin* iface, NMConnection* connection, GError** error) {
	g_message("Getting SeasideVPN editor...");

	unsigned int gtk_major = 3;
	void *handle = dlopen(NULL, RTLD_NOW);
	if (handle) {
		unsigned int (*get_major_version)(void) = (unsigned int (*)(void)) dlsym(handle, "gtk_get_major_version");
		if (get_major_version) {
			gtk_major = get_major_version();
		}
		dlclose(handle);
	} else {
		g_warning("Failed to open process handle for symbol lookup: %s", dlerror());
	}

	const char *libname;
	if (gtk_major >= 4) {
		libname = EDITOR_INTERFACE_PATH "-gtk4.so";
	} else {
		libname = EDITOR_INTERFACE_PATH "-gtk3.so";
	}

	void *editor_handle = dlopen(libname, RTLD_LAZY);
	if (!editor_handle) {
        g_warning("Failed to open interface library:  %s: %s", libname, dlerror());
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, 0, "Failed to load editor library %s: %s", libname, dlerror());
		return NULL;
	}

	NMVpnEditor *(*create_func)(NMConnection *, GError **) = (NMVpnEditor *(*)(NMConnection *, GError **)) dlsym(editor_handle, "create_seaside_editor");
	if (!create_func) {
        g_warning("Failed to resolve create_seaside_editor symbol: %s", dlerror());
		g_set_error(error, SEASIDE_EDITOR_PLUGIN_ERROR, 0, "Failed to resolve create_seaside_editor symbol: %s", dlerror());
		dlclose(editor_handle);
		return NULL;
	}

	return create_func(connection, error);
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
}

G_MODULE_EXPORT NMVpnEditor* nm_vpn_editor_factory_seaside(NMVpnEditorPlugin *editor_plugin, NMConnection* connection, GError** error) {
	g_message("SeasideVPN editor factory called...");
	if (error) g_return_val_if_fail(*error == NULL, NULL);
	return get_editor(NM_VPN_EDITOR_PLUGIN(editor_plugin), connection, error);
}

G_MODULE_EXPORT NMVpnEditorPlugin* nm_vpn_editor_plugin_factory(GError** error) {
	g_message("SeasideVPN editor plugin factory called...");
	if (error) g_return_val_if_fail(*error == NULL, NULL);
	return g_object_new(SEASIDE_TYPE_EDITOR_PLUGIN, NULL);
}
