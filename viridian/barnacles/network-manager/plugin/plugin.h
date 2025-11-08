#ifndef NM_SEASIDE_PLUGIN_H
#define NM_SEASIDE_PLUGIN_H

#include <glib.h>
#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h>

#define NM_DBUS_SERVICE_SEASIDE SEASIDE_PLUGIN_SERVICE
#define NM_DBUS_INTERFACE_SEASIDE SEASIDE_PLUGIN_SERVICE
#define NM_DBUS_PATH_SEASIDE "/org/freedesktop/NetworkManager/seasidevpn"

#define NM_SEASIDE_KEY_CERTIFILE   "certifile"
#define NM_SEASIDE_KEY_CERTIFICATE "certificate"
#define NM_SEASIDE_KEY_PROTOCOL    "protocol"

/* Type macros */
#define NM_TYPE_SEASIDE_PLUGIN            (nm_seaside_plugin_get_type ())
#define NM_SEASIDE_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SEASIDE_PLUGIN, NMSeasidePlugin))
#define NM_SEASIDE_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SEASIDE_PLUGIN, NMSeasidePluginClass))
#define NM_IS_SEASIDE_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SEASIDE_PLUGIN))
#define NM_IS_SEASIDE_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SEASIDE_PLUGIN))
#define NM_SEASIDE_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SEASIDE_PLUGIN, NMSeasidePluginClass))

typedef struct {
    NMVpnServicePlugin parent;
} NMSeasidePlugin;

typedef struct {
    NMVpnServicePluginClass parent;
} NMSeasidePluginClass;

GType nm_seaside_plugin_get_type (void);
NMSeasidePlugin *nm_seaside_plugin_new (void);

#endif /* NM_SEASIDE_PLUGIN_H */
