#define GCR_API_SUBJECT_TO_CHANGE 1
#include <gcr/gcr.h>
#include <gio/gio.h>
#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "noctalia-prompt.h"
#include "ipc-client.h"

#define FALLBACK_GCR_PROMPTER "/usr/lib/gcr-prompter"

static GcrSystemPrompter *the_prompter = NULL;
static GMainLoop *main_loop = NULL;
static guint timeout_id = 0;
static gboolean registered = FALSE;

static gboolean
on_timeout (gpointer user_data)
{
    timeout_id = 0;
    g_debug ("Inactivity timeout reached, quitting");
    g_main_loop_quit (main_loop);
    return G_SOURCE_REMOVE;
}

static void
reset_timeout (void)
{
    if (timeout_id != 0) {
        g_source_remove (timeout_id);
        timeout_id = 0;
    }
    /* Quit after 30 seconds of inactivity */
    timeout_id = g_timeout_add_seconds (30, on_timeout, NULL);
}

static void
on_prompting_changed (GObject    *obj,
                      GParamSpec *pspec,
                      gpointer    user_data)
{
    gboolean prompting = gcr_system_prompter_get_prompting (the_prompter);

    if (prompting) {
        g_debug ("Prompting started, stopping timeout");
        /* Stop timeout while prompting */
        if (timeout_id != 0) {
            g_source_remove (timeout_id);
            timeout_id = 0;
        }
    } else {
        g_debug ("Prompting finished, restarting timeout");
        /* Restart timeout when done prompting */
        reset_timeout ();
    }
}

static void
on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         user_data)
{
    GError *error = NULL;

    g_debug ("D-Bus session bus acquired, registering prompter");

    gcr_system_prompter_register (the_prompter, connection);
    registered = TRUE;

    g_message ("Registered as %s", name);
}

static void
on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         user_data)
{
    g_message ("D-Bus name acquired: %s", name);
}

static void
on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         user_data)
{
    g_warning ("D-Bus name lost: %s", name);
    g_main_loop_quit (main_loop);
}

static void
fallback_to_gcr_prompter (char *argv[])
{
    g_message ("Falling back to %s", FALLBACK_GCR_PROMPTER);

    /* Check if fallback exists */
    if (access (FALLBACK_GCR_PROMPTER, X_OK) != 0) {
        g_warning ("Fallback %s not available: %s",
                   FALLBACK_GCR_PROMPTER, g_strerror (errno));
        exit (1);
    }

    /* Exec the original gcr-prompter, inheriting our argv */
    execv (FALLBACK_GCR_PROMPTER, argv);

    /* If exec returns, it failed */
    g_warning ("Failed to exec %s: %s", FALLBACK_GCR_PROMPTER, g_strerror (errno));
    exit (1);
}

int
main (int argc, char *argv[])
{
    guint owner_id;

    setlocale (LC_ALL, "");

    /* Enable debug output if requested */
    if (g_getenv ("NOCTALIA_KEYRING_DEBUG") != NULL) {
        g_log_set_handler (NULL, G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO |
                           G_LOG_LEVEL_MESSAGE | G_LOG_LEVEL_WARNING |
                           G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR,
                           g_log_default_handler, NULL);
    }

    g_message ("noctalia-keyring-prompter starting");

    /* Check if noctalia-polkit socket is available */
    if (!noctalia_ipc_ping ()) {
        g_message ("noctalia-polkit socket not available");
        fallback_to_gcr_prompter (argv);
        /* Not reached */
    }

    g_message ("noctalia-polkit socket is available, starting keyring prompter");

    /* Create system prompter with our custom prompt type */
    the_prompter = gcr_system_prompter_new (GCR_SYSTEM_PROMPTER_SINGLE,
                                            NOCTALIA_TYPE_PROMPT);

    g_signal_connect (the_prompter, "notify::prompting",
                      G_CALLBACK (on_prompting_changed), NULL);

    main_loop = g_main_loop_new (NULL, FALSE);

    /* Acquire the D-Bus name */
    owner_id = g_bus_own_name (G_BUS_TYPE_SESSION,
                               "org.gnome.keyring.SystemPrompter",
                               G_BUS_NAME_OWNER_FLAGS_REPLACE,
                               on_bus_acquired,
                               on_name_acquired,
                               on_name_lost,
                               NULL, NULL);

    reset_timeout ();

    g_main_loop_run (main_loop);

    g_message ("Shutting down");

    /* Cleanup */
    if (timeout_id != 0)
        g_source_remove (timeout_id);

    g_bus_unown_name (owner_id);

    if (registered)
        gcr_system_prompter_unregister (the_prompter, TRUE);

    g_object_unref (the_prompter);
    g_main_loop_unref (main_loop);

    return 0;
}
