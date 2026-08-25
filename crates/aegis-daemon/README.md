# Aegis daemon boundary configuration

The daemon serves its existing newline-delimited JSON protocol over a Unix
domain socket. The socket is owner-only (0600) by default and every accepted
connection is checked using Unix peer credentials. The socket owner is always
authorized; additional primary UIDs or GIDs may be supplied as comma-separated
numeric values:

    AEGIS_DAEMON_SOCKET_PATH=/run/aegis/aegis-daemon.sock
    AEGIS_DAEMON_SCAN_ROOT=/srv/workspace
    AEGIS_DAEMON_ALLOWED_UIDS=1000,1001
    AEGIS_DAEMON_ALLOWED_GIDS=2000

When AEGIS_DAEMON_ALLOWED_GIDS is set, the socket is mode 0660; otherwise it
remains 0600. Peer authorization is still enforced in the process, so
filesystem mode is defense in depth rather than the authorization mechanism.

AEGIS_DAEMON_SCAN_ROOT defaults to the daemon's current directory. scan_file
and scan_dir requests are resolved and canonicalized beneath that root.
Relative paths are root-relative. Absolute paths, .. traversal, and symlinks
whose canonical target is outside the root are rejected before the scanner is
called.

Migration requirements:

1. Choose a private socket parent directory and set
   AEGIS_DAEMON_SOCKET_PATH; the parent must already exist and be writable by
   the daemon service.
2. Set AEGIS_DAEMON_SCAN_ROOT to every tree the service is intended to scan.
   A service that previously scanned arbitrary absolute paths must be
   reconfigured explicitly; there is no unrestricted compatibility mode.
3. If clients run under another account, set the UID/GID allowlists and grant
   the service account access to the socket parent and approved root.
4. Restart the daemon so the new socket and policy are applied. Existing
   authorized clients keep the same request/response protocol.
