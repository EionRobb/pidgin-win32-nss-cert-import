/*
 * Plugin to configure NSS
 *
 * Copyright (C) 2014, Daniel Atallah <datallah@pidgin.im>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02111-1301, USA.
 */
#include "internal.h"
#include "debug.h"
#include "plugin.h"
#include "version.h"

#ifdef _WIN32
# ifndef HAVE_LONG_LONG
#define HAVE_LONG_LONG
/* WINDDK_BUILD is defined because the checks around usage of
 * intrisic functions are wrong in nspr */
#define WINDDK_BUILD
# endif
#endif

#include <nspr.h>
#include <nss.h>
#include <nssb64.h>
#include <ocsp.h>
#include <pk11func.h>
#include <prio.h>
#include <secerr.h>
#include <secmod.h>
#include <ssl.h>
#include <sslerr.h>
#include <sslproto.h>

/* There's a bug in some versions of this header that requires that some of
   the headers above be included first. This is true for at least libnss
   3.15.4. */
#include <certdb.h>

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS 0
#include <wincrypt.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>


static gboolean
plugin_load(PurplePlugin *plugin) {
	
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertContext = NULL;
	gchar *stores[] = {"CA", "ROOT", "AuthRoot", "MY", NULL};
	
	CERTCertDBHandle *certdb = CERT_GetDefaultCertDB();
	CERTCertificate *crt_dat;
	CERTCertTrust trust;
	
	guint i;
	for (i = 0; stores[i] && *stores[i]; i++) {
		hCertStore = CertOpenSystemStoreA(0, stores[i]);
		if (!hCertStore)
			return FALSE;
		
		pCertContext = CertEnumCertificatesInStore(hCertStore, NULL);
		while (pCertContext != NULL)
		{
			unsigned char *cert_data = pCertContext->pbCertEncoded;
			int cert_len = pCertContext->cbCertEncoded;
			
			crt_dat = CERT_DecodeCertFromPackage((char *)cert_data, cert_len);
			if (crt_dat != NULL) {
			
				purple_debug_info("win32-cert-import", "Trusting %s\n", crt_dat->subjectName);
				
				if (CERT_IsCACert(crt_dat, NULL)) {
					trust.sslFlags = CERTDB_TRUSTED_CA | CERTDB_TRUSTED_CLIENT_CA;
				} else {
					trust.sslFlags = CERTDB_TRUSTED;
				}
				trust.emailFlags = 0;
				trust.objectSigningFlags = 0;

				CERT_ChangeCertTrust(certdb, crt_dat, &trust);
	
			}
	
			
			pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext);
		}
		
		CertCloseStore(hCertStore, 0);
	}
	
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin) {
	//TODO

	return TRUE;
}


static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	2,
	1,
	PURPLE_PLUGIN_STANDARD,				/**< type           */
	NULL,						/**< ui_requirement */
	0,						/**< flags          */
	NULL,						/**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,			/**< priority       */

	"core-eionrobb-win32-nss-cert-import",					/**< id             */
	N_("Win32 Cert Importer"),				/**< name           */
	DISPLAY_VERSION,				/**< version        */
							/**  summary        */
	N_("Imports Windows system certificates into NSS for Pidgin to use"),
							/**  description    */
	N_("Imports Windows system certificates into NSS for Pidgin to use"),
	"Eion Robb <eionrobb@gmail.com>",		/**< author         */
	"",					/**< homepage       */

	plugin_load,					/**< load           */
	plugin_unload,					/**< unload         */
	NULL,						/**< destroy        */

	NULL,						/**< ui_info        */
	NULL,						/**< extra_info     */
	NULL,					/**< prefs_info     */
	NULL,
	/* Padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin *plugin) {
	info.dependencies = g_list_prepend(info.dependencies, "ssl-nss");
}

PURPLE_INIT_PLUGIN(win32-nss-cert-import, init_plugin, info)
