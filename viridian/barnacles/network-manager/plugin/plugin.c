#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <errno.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <glib.h>
#include <glib-unix.h>
#include <NetworkManager.h>

#include "plugin.h"
#include "../../../reef/shared_library/include/seaside.h"

/* Shared library base names to try letting the loader find them */
#define LIB_BASENAME "libseaside.so"

#define IP_TEMPLATE "%u.%u.%u.%u"
#define IP(x) ((uint8_t*) &x)[3], ((uint8_t*) &x)[2], ((uint8_t*) &x)[1], ((uint8_t*) &x)[0] 

typedef bool (*vpn_start_fn)(const char*, uintptr_t, const char*, struct VPNConfig**, void**, void*, void (*)(void*, char*), char**);
typedef bool (*vpn_stop_fn)(void*, char**);

/* Private plugin state */
typedef struct {
    void *lib_handle;
    void *coordinator;
    vpn_start_fn vpn_start;
    vpn_stop_fn vpn_stop;
} NMSeasidePluginPrivate;

G_DEFINE_TYPE_WITH_PRIVATE(NMSeasidePlugin, nm_seaside_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

typedef struct {
    NMVpnServicePlugin* plugin;
    VPNConfig* cfg;
} IdleConfigData;

typedef struct {
    NMVpnServicePlugin *plugin;
    char *message;
} CaptureErrorData;

static gboolean capture_error_idle(gpointer data) {
    g_debug("DBUS runtime: Starting synchronous error report...");
    CaptureErrorData *d = (CaptureErrorData *)data;

    if (d->message) {
        g_debug("DBUS runtime: Setting plugin failure...");
        nm_vpn_service_plugin_failure(d->plugin, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);

        g_debug("DBUS runtime: Requesting disconnect from NM...");
        nm_vpn_service_plugin_disconnect(d->plugin, NULL);

        g_error("DBUS runtime: Error running SeasideVPN interface: %s", d->message);
        free(d->message);

    } else
        g_debug("DBUS runtime: SeasideVPN interface exited cleanly!");

    g_free(d);
    g_debug("DBUS runtime: Error reported successfully!");
    return G_SOURCE_REMOVE;
}

static void
capture_error(void* plugin_ptr, char* error)
{
    g_debug("DBUS runtime: Starting asynchronous error report...");
    CaptureErrorData *d = g_new(CaptureErrorData, 1);
    d->plugin = (NMVpnServicePlugin *) plugin_ptr;
    d->message = error;
    g_idle_add(capture_error_idle, d);
    g_debug("DBUS runtime: Asynchronous report sent!");
}

/* Try to dlopen letting the system search for the library; fall back to explicit paths. */
static gboolean
seaside_load_library(NMSeasidePluginPrivate *priv, GError **error)
{
    if (priv->lib_handle)
        return TRUE;

    /* Let the loader search soname */
    priv->lib_handle = dlopen(LIB_BASENAME, RTLD_NOW | RTLD_LOCAL);
    if (!priv->lib_handle) {
        g_set_error (error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
                     "Error loading libseaside: %s", dlerror());
        return FALSE;
    }

    /* Resolve symbols */
    priv->vpn_start = (vpn_start_fn) dlsym(priv->lib_handle, "vpn_start");
    priv->vpn_stop  = (vpn_stop_fn) dlsym(priv->lib_handle, "vpn_stop");

    if (!priv->vpn_start || !priv->vpn_stop) {
        g_set_error (error,
                     NM_VPN_PLUGIN_ERROR,
                     NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
                     "Error reading libseaside symbols");
        dlclose(priv->lib_handle);
        priv->lib_handle = NULL;
        return FALSE;
    }

    return TRUE;
}

/* Build and send NM IPv4 config from VPNConfig */
static gboolean
seaside_set_vpnconfig_idle(gpointer user_data)
{
    g_debug("DBUS config: Starting asynchronous configuration setting...");
    IdleConfigData *data = (IdleConfigData *)user_data;

    GVariantBuilder gen_builder;
    g_debug("DBUS config: Initializing general configuration...");
    g_variant_builder_init(&gen_builder, G_VARIANT_TYPE_VARDICT);

    if (data->cfg->tunnel_name && data->cfg->tunnel_name[0]) {
        g_debug("DBUS config: Setting tunnel name to: %s...", data->cfg->tunnel_name);
        g_variant_builder_add(&gen_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, g_variant_new_string(data->cfg->tunnel_name));
    }

    if (data->cfg->tunnel_mtu) {
        g_debug("DBUS config: Setting tunnel MTU to: %u...", data->cfg->tunnel_mtu);
        g_variant_builder_add(&gen_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_MTU, g_variant_new_uint32(data->cfg->tunnel_mtu));
    }

    if (data->cfg->remote_address) {
        g_debug("DBUS config: Setting tunnel remote gateway to: " IP_TEMPLATE "...", IP(data->cfg->remote_address));
        g_variant_builder_add(&gen_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, g_variant_new_uint32(g_htonl(data->cfg->remote_address)));
    }

    g_debug("DBUS config: Setting IPv4 configuration to allowed...");
	g_variant_builder_add(&gen_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4, g_variant_new_boolean(TRUE));

    g_debug("DBUS config: Sending general configuration...");
    nm_vpn_service_plugin_set_config(data->plugin, g_variant_builder_end(&gen_builder));

    GVariantBuilder ipv4_builder;
    g_debug("DBUS config: Initializing IPv4 configuration...");
    g_variant_builder_init(&ipv4_builder, G_VARIANT_TYPE_VARDICT);

    if (data->cfg->tunnel_gateway) {
        g_debug("DBUS config: Setting tunnel internal gateway to: " IP_TEMPLATE "...", IP(data->cfg->tunnel_gateway));
        g_variant_builder_add(&ipv4_builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_INT_GATEWAY, g_variant_new_uint32(g_htonl(data->cfg->tunnel_gateway)));
    }

    if (data->cfg->tunnel_address) {
        g_debug("DBUS config: Setting tunnel address to: " IP_TEMPLATE "...", IP(data->cfg->tunnel_address));
        g_variant_builder_add(&ipv4_builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, g_variant_new_uint32(g_htonl(data->cfg->tunnel_address)));
    }

    if (data->cfg->tunnel_prefix) {
        g_debug("DBUS config: Setting tunnel prefix to: %u...", data->cfg->tunnel_prefix);
        g_variant_builder_add(&ipv4_builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, g_variant_new_uint32(data->cfg->tunnel_prefix));
    }

    if (data->cfg->dns_address) {
        g_debug("DBUS config: Setting tunnel DNS address to: " IP_TEMPLATE "...", IP(data->cfg->dns_address));
        GVariantBuilder dns_builder;
        g_variant_builder_init(&dns_builder, G_VARIANT_TYPE("au"));
        g_variant_builder_add(&dns_builder, "u", g_htonl(data->cfg->dns_address));
        g_variant_builder_add(&ipv4_builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DNS, g_variant_builder_end(&dns_builder));
    }

    g_debug("DBUS config: Sending IPv4 configuration...");
    nm_vpn_service_plugin_set_ip4_config(data->plugin, g_variant_builder_end(&ipv4_builder));

    g_free(data->cfg);
    g_free(data);
    g_debug("DBUS config: Configuration sent!");
    return G_SOURCE_REMOVE;
}

/* real_connect: invoked by NM when starting a VPN session */
static gboolean
real_connect(NMVpnServicePlugin *plugin, NMConnection *connection, GError **error)
{
    g_debug("DBUS connect: Starting...");
    NMSeasidePluginPrivate *priv = nm_seaside_plugin_get_instance_private(NM_SEASIDE_PLUGIN(plugin));
    NMSettingVpn *s_vpn = nm_connection_get_setting_vpn(connection);

    if (!s_vpn) {
        g_warning("DBUS connect: Error extracting settings");
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
                    "Error extracting settings");
        return FALSE;
    }

    g_debug("DBUS connect: Reading configuration data...");
    const char *certifile = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFILE);
    const char *certificate = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE);
    const char *protocol = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_PROTOCOL);

    gsize certificate_length = 0;
    char * certificate_data = NULL;

    if (!certificate) {
        g_warning("DBUS connect: Error extracting 'certificate' parameter");
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS, "Error extracting 'certificate' parameter");
        return FALSE;
    } else g_debug("DBUS connect: Certificate parameter read: %s", certificate);

    if (certifile) {
        g_debug("DBUS connect: Certificate parameter is a file name!");
        certificate_data = (char *)g_strdup(certificate);
    } else {
        certificate_data = (char *)g_base64_decode((const guchar *)certificate, &certificate_length);
        g_debug("DBUS connect: Certificate parameter is embedded data (%ld bytes)!", certificate_length);
    }

    if (!protocol) {
        g_warning("DBUS connect: Error extracting 'protocol' parameter");
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS, "Error extracting 'protocol' parameter");
        return FALSE;
    } else g_debug("DBUS connect: Protocol parameter read: %s", protocol);

    if (!seaside_load_library(priv, error)) {
        g_warning("DBUS connect: Error loading Seaside Reef DLL");
        return FALSE;
    } else g_debug("DBUS connect: Seaside Reef DLL loaded!");

    VPNConfig *cfg;
    char *err_string;
    g_debug("DBUS connect: Starting viridian...");
    if (!priv->vpn_start(certificate_data, certificate_length, protocol, &cfg, &priv->coordinator, (void*) plugin, capture_error, &err_string)) {
        g_warning("DBUS connect: Error starting viridian: %s", err_string);
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED, "Error starting viridian: %s", err_string);
        free(err_string);
        return FALSE;
    } else g_debug("DBUS connect: Viridian started!");

    IdleConfigData *data = g_new(IdleConfigData, 1);
    data->plugin = plugin;
    data->cfg = cfg;
    g_debug("DBUS connect: Scheduling configuration setting...");
    g_idle_add(seaside_set_vpnconfig_idle, data);

    g_debug("DBUS connect: Success!");
    g_free(certificate_data);
    return TRUE;
}

/* real_disconnect: invoked by NM when stopping the VPN session */
static gboolean
real_disconnect(NMVpnServicePlugin *plugin, GError **error)
{
    g_debug("DBUS disconnect: Starting...");
    NMSeasidePluginPrivate *priv = nm_seaside_plugin_get_instance_private(NM_SEASIDE_PLUGIN(plugin));

    if (priv->coordinator && priv->vpn_stop) {
        char *err_string;

        g_debug("DBUS disconnect: Stopping SeasideVPN interface...");
        if (!priv->vpn_stop(priv->coordinator, &err_string)) {
            g_warning("DBUS disconnect: Error stopping SeasideVPN interface: %s", err_string);
            g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED, "Error stopping SeasideVPN interface: %s", err_string);
            free(err_string);
        } else g_debug("DBUS disconnect: SeasideVPN interface stopped successfully!");

        priv->coordinator = NULL;
    } else g_debug("DBUS disconnect: SeasideVPN interface was never run!");

    nm_vpn_service_plugin_disconnect(plugin, NULL);
    g_debug("DBUS disconnect: Success!");
    return TRUE;
}

static gboolean
empty_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
    g_debug("DBUS need secrets: Skipped!");
    return FALSE;
}

static gboolean
empty_new_secrets (NMVpnServicePlugin *base_plugin,
                  NMConnection *connection,
                  GError **error)

{
    g_debug("DBUS new secrets: Skipped!");
    return TRUE;
}

/* GObject init/class functions */
static void
nm_seaside_plugin_init(NMSeasidePlugin *plugin)
{
    NMSeasidePluginPrivate *priv = nm_seaside_plugin_get_instance_private(plugin);
    priv->lib_handle = NULL;
    priv->coordinator = NULL;
    priv->vpn_start = NULL;
    priv->vpn_stop = NULL;
}

static void
nm_seaside_plugin_class_init(NMSeasidePluginClass *klass)
{
    NMVpnServicePluginClass *parent = NM_VPN_SERVICE_PLUGIN_CLASS(klass);
    parent->connect = real_connect;
    parent->need_secrets = empty_need_secrets;
    parent->disconnect = real_disconnect;
    parent->new_secrets = empty_new_secrets;
}

/* Factory to create a plugin instance and register D-Bus service name */
NMSeasidePlugin *
nm_seaside_plugin_new(void)
{
    GError *error = NULL;
    NMSeasidePlugin *plugin = g_initable_new(NM_TYPE_SEASIDE_PLUGIN, NULL, &error,
                                             NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME,
                                             NM_DBUS_SERVICE_SEASIDE,
                                             NULL);
    if (!plugin) {
        g_warning("Error creating SeasideVPN NM plugin: %s", error ? error->message : "unknown");
        g_clear_error(&error);
    }
    return plugin;
}

static gboolean
signal_handler (gpointer user_data)
{
	g_main_loop_quit (user_data);
	return G_SOURCE_REMOVE;
}

/* Minimal main: instantiate plugin and run main loop */
int main(int argc, char *argv[])
{
    g_debug("Starting SeasideVPN NM plugin...");
    NMSeasidePlugin *plugin = nm_seaside_plugin_new();
    if (!plugin) return EXIT_FAILURE;

    g_debug("Starting SeasideVPN NM plugin main loop...");
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    g_signal_connect(plugin, "quit", G_CALLBACK(g_main_loop_quit), loop);

    g_unix_signal_add (SIGTERM, signal_handler, loop);
	g_unix_signal_add (SIGINT, signal_handler, loop);
    g_main_loop_run(loop);

    g_debug("SeasideVPN NM plugin main loop stopped!");
    g_main_loop_unref(loop);
    g_object_unref(plugin);
    return EXIT_SUCCESS;
}
