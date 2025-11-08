#ifndef NM_SEASIDE_COMMON_H
#define NM_SEASIDE_COMMON_H

#include <NetworkManager.h>

#include "seaside.h"


#define NM_SEASIDE_KEY_CERTIFILE "certifile"
#define NM_SEASIDE_KEY_CERTIFICATE "certificate"
#define NM_SEASIDE_KEY_PROTOCOL "protocol"

typedef unsigned int (*get_major_version_fn)(void);
typedef NMVpnEditor* (*create_seaside_editor_fn)(NMConnection*, GError**);

typedef bool (*vpn_start_fn)(const char*, uintptr_t, const char*, struct VPNConfig**, void**, void*, void (*)(void*, char*), char**);
typedef bool (*vpn_stop_fn)(void*, char**);

typedef union {
	void* pointer;
	get_major_version_fn get_major_version;
	create_seaside_editor_fn create_seaside_editor;
	vpn_start_fn vpn_start;
	vpn_stop_fn vpn_stop;
} dll_function;


#endif /* NM_SEASIDE_COMMON_H */
