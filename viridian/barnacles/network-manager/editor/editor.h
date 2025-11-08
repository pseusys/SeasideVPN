#ifndef NM_SEASIDE_EDITOR_H
#define NM_SEASIDE_EDITOR_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <glib-object.h>


#define SEASIDE_EDITOR_PLUGIN_ERROR NM_CONNECTION_ERROR
#define SEASIDE_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY NM_CONNECTION_ERROR_INVALID_PROPERTY


#define SEASIDE_TYPE_EDITOR_PLUGIN (seaside_editor_plugin_get_type())
#define SEASIDE_EDITOR_PLUGIN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), SEASIDE_TYPE_EDITOR_PLUGIN, SeasideEditorPlugin))
#define SEASIDE_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), SEASIDE_TYPE_EDITOR_PLUGIN, SeasideEditorPluginClass))
#define SEASIDE_IS_EDITOR_PLUGIN(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEASIDE_TYPE_EDITOR_PLUGIN))
#define SEASIDE_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), SEASIDE_TYPE_EDITOR_PLUGIN))
#define SEASIDE_EDITOR_PLUGIN_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), SEASIDE_TYPE_EDITOR_PLUGIN, SeasideEditorPluginClass))

typedef struct _SeasideEditorPlugin SeasideEditorPlugin;
typedef struct _SeasideEditorPluginClass SeasideEditorPluginClass;

struct _SeasideEditorPlugin {
	GObject parent;
};

struct _SeasideEditorPluginClass {
	GObjectClass parent;
};

GType seaside_editor_plugin_get_type(void);


#define SEASIDE_TYPE_EDITOR (seaside_editor_get_type())
#define SEASIDE_EDITOR(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), SEASIDE_TYPE_EDITOR, SeasideEditor))
#define SEASIDE_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST((klass), SEASIDE_TYPE_EDITOR, SeasideEditorClass))
#define SEASIDE_IS_EDITOR(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEASIDE_TYPE_EDITOR))
#define SEASIDE_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), SEASIDE_TYPE_EDITOR))
#define SEASIDE_EDITOR_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS((obj), SEASIDE_TYPE_EDITOR, SeasideEditorClass))

typedef struct _SeasideEditor SeasideEditor;
typedef struct _SeasideEditorClass SeasideEditorClass;

struct _SeasideEditor {
	GObject parent;
};

struct _SeasideEditorClass {
	GObjectClass parent;
};

GType seaside_editor_get_type(void);


#define SEASIDE_PLUGIN_NAME "SeasideVPN"
#define SEASIDE_PLUGIN_DESC "An obscure P2P network PPTP VPN distributed system"

#define NM_SEASIDE_KEY_CERTIFILE   "certifile"
#define NM_SEASIDE_KEY_CERTIFICATE "certificate"
#define NM_SEASIDE_KEY_PROTOCOL "protocol"

#define NM_SEASIDE_PROTOCOL_DEFAULT "typhoon"


#endif	/* NM_SEASIDE_EDITOR_H */
