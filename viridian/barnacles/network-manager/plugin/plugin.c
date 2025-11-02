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

typedef bool (*vpn_init_fn)(const char*, const char*, struct VPNConfig*, void**, char**);
typedef bool (*vpn_start_fn)(void*, const void*, char**);
typedef bool (*vpn_stop_fn)(void*, char**);

/* Private plugin state */
typedef struct {
    void *lib_handle;
    void *coordinator;
    vpn_init_fn vpn_init;
    vpn_start_fn vpn_start;
    vpn_stop_fn vpn_stop;
    gboolean running;
} NMSeasidePluginPrivate;

G_DEFINE_TYPE_WITH_PRIVATE(NMSeasidePlugin, nm_seaside_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

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
    priv->vpn_init  = (vpn_init_fn) dlsym(priv->lib_handle, "vpn_init");
    priv->vpn_start = (vpn_start_fn) dlsym(priv->lib_handle, "vpn_start");
    priv->vpn_stop  = (vpn_stop_fn) dlsym(priv->lib_handle, "vpn_stop");

    if (!priv->vpn_init || !priv->vpn_start || !priv->vpn_stop) {
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
static void
seaside_set_ip4_from_vpnconfig(NMVpnServicePlugin *plugin, const VPNConfig *cfg)
{
    GVariantBuilder gen_builder;
    g_variant_builder_init(&gen_builder, G_VARIANT_TYPE_VARDICT);

    if (cfg->tunnel_name && cfg->tunnel_name[0]) {
        GVariant *v = g_variant_new_string(cfg->tunnel_name);
        g_variant_builder_add(&gen_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, v);
    }

    if (cfg->tunnel_mtu) {
        GVariant *v = g_variant_new_uint32(cfg->tunnel_mtu);
        g_variant_builder_add(&gen_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_MTU, v);
    }

    if (cfg->tunnel_address) {
        GVariant *v = g_variant_new_uint32(g_htonl(cfg->tunnel_address));
        g_variant_builder_add(&gen_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, v);
    }

    GVariant *gen_dict = g_variant_builder_end(&gen_builder);
    nm_vpn_service_plugin_set_config(plugin, gen_dict);

    GVariantBuilder ipv4_builder;
    g_variant_builder_init(&ipv4_builder, G_VARIANT_TYPE_VARDICT);

    if (cfg->tunnel_address) {
        GVariant *v = g_variant_new_uint32(g_htonl(cfg->tunnel_address));
        g_variant_builder_add(&ipv4_builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, v);
    }

    if (cfg->tunnel_prefix) {
        GVariant *v = g_variant_new_uint32(cfg->tunnel_prefix);
        g_variant_builder_add(&ipv4_builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, v);
    }

    if (cfg->dns_address) {
        GVariantBuilder dns_builder;
        g_variant_builder_init(&dns_builder, G_VARIANT_TYPE("au"));
        g_variant_builder_add(&dns_builder, "u", g_htonl(cfg->dns_address));
        GVariant *dns_variant = g_variant_builder_end(&dns_builder);
        g_variant_builder_add(&ipv4_builder, "{sv}", NM_VPN_PLUGIN_IP4_CONFIG_DNS, dns_variant);
    }

    GVariant *ipv4_dict = g_variant_builder_end(&ipv4_builder);
    nm_vpn_service_plugin_set_ip4_config(plugin, ipv4_dict);
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
    const char *certificate = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_CERTIFICATE);
    const char *protocol = nm_setting_vpn_get_data_item(s_vpn, NM_SEASIDE_KEY_PROTOCOL);

    if (!certificate) {
        g_warning("DBUS connect: Error extracting 'certificate' parameter");
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                    "Error extracting 'certificate' parameter");
        return FALSE;
    } else g_debug("DBUS connect: Certificate parameter read: %s", certificate);

    if (!protocol) {
        g_warning("DBUS connect: Error extracting 'protocol' parameter");
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
                    "Error extracting 'protocol' parameter");
        return FALSE;
    } else g_debug("DBUS connect: Protocol parameter read: %s", protocol);

    if (!seaside_load_library(priv, error)) {
        g_warning("DBUS connect: Error loading Seaside Reef DLL");
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
                    "Error loading Seaside Reef DLL");
        return FALSE;
    } else g_debug("DBUS connect: Seaside Reef DLL loaded!");

    VPNConfig cfg;
    memset(&cfg, 0, sizeof(cfg));

    void *viridian;
    char *err_string;

    /* Synchronous initialization: library fills VPNConfig */
    g_debug("DBUS connect: Initializing viridian...");
    if (!priv->vpn_init(certificate, protocol, &cfg, &viridian, &err_string)) {
        g_warning("DBUS connect: Error initializing viridian: %s", err_string);
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED, "Error initializing viridian: %s", err_string);
        free(err_string);
        return FALSE;
    } else g_debug("DBUS connect: Viridian initialized!");

    /* Tell NetworkManager about the IP config we want applied */
    g_debug("DBUS connect: Setting IPv4 parameters...");
    seaside_set_ip4_from_vpnconfig(plugin, &cfg);

    /* Start engine in background; pass plugin pointer so callbacks are instance-specific */
    g_debug("DBUS connect: Starting viridian...");
    if (!priv->vpn_start(viridian, &priv->coordinator, &err_string)) {
        g_warning("DBUS connect: Error starting viridian: %s", err_string);
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED, "Error starting viridian: %s", err_string);
        free(err_string);
        return FALSE;
    } else g_debug("DBUS connect: Viridian started!");

    priv->running = TRUE;
    g_debug("DBUS connect: Success!");
    return TRUE;
}

/* real_disconnect: invoked by NM when stopping the VPN session */
static gboolean
real_disconnect(NMVpnServicePlugin *plugin, GError **error)
{
    g_debug("DBUS disconnect: Starting...");
    NMSeasidePluginPrivate *priv = nm_seaside_plugin_get_instance_private(NM_SEASIDE_PLUGIN(plugin));

    if (priv->coordinator && priv->running && priv->vpn_stop) {
        char *err_string;

        g_debug("DBUS disconnect: Stopping SeasideVPN interface...");
        if (!priv->vpn_stop(priv->coordinator, &err_string)) {
            g_warning("DBUS disconnect: Error stopping SeasideVPN interface: %s", err_string);
            g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED, "Error stopping SeasideVPN interface: %s", err_string);
            free(err_string);
        } else g_debug("DBUS disconnect: SeasideVPN interface stopped successfully!");

        priv->coordinator = NULL;
        priv->running = FALSE;
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

/* GObject init/class functions */
static void
nm_seaside_plugin_init(NMSeasidePlugin *plugin)
{
    NMSeasidePluginPrivate *priv = nm_seaside_plugin_get_instance_private(plugin);
    priv->lib_handle = NULL;
    priv->coordinator = NULL;
    priv->vpn_init = NULL;
    priv->vpn_start = NULL;
    priv->vpn_stop = NULL;
    priv->running = FALSE;
}

static void
nm_seaside_plugin_class_init(NMSeasidePluginClass *klass)
{
    NMVpnServicePluginClass *parent = NM_VPN_SERVICE_PLUGIN_CLASS(klass);
    parent->connect = real_connect;
    parent->need_secrets = empty_need_secrets;
    parent->disconnect = real_disconnect;
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
