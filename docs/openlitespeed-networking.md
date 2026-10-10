# Managed OpenLiteSpeed listeners and index files

## Automatic IPv4 and IPv6 listeners

The panel manages HTTP and HTTPS listeners together with the enabled website registry. IPv4 remains available on `*:80` and `*:443`. On a host with usable IPv6, the panel also prepares `OLSWPanelHTTPIPv6` on `[ANY]:80` and `OLSWPanelHTTPSIPv6` on `[ANY]:443`.

Detection checks the local host: an up interface must have a usable public IPv6 address and a valid default route, and the kernel must permit an IPv6 socket. Link-local, loopback, unique-local, unusable addresses and failed probes do not enable optional listeners. DNS queries and external connection tests are not used to decide whether to generate the listeners.

Fresh installation and subsequent managed website configuration updates perform this detection. Upgrade step `1.0.75` also reconciles an existing panel-managed registry when OpenLiteSpeed is already running. It does not start a stopped service or replace an unrecognized registry. Optional IPv6 failures preserve IPv4 operation and appear in the installation or panel logs. Configuration is validated before restart, generated wildcard listeners are checked locally afterwards, and existing recovery paths remain in place. Panel configuration-test and restart commands have a 60-second limit so a stalled subprocess cannot wait indefinitely during upgrade.

All generated listeners share the same enabled website and alias mappings. HTTPS uses the existing listener fallback certificate and the website's existing SNI certificate configuration. No duplicate website, database or certificate is created for IPv6.

IPv4 fallback must also pass real IPv4 wildcard binding checks for ports 80 and 443. A successful restart command alone is insufficient; failed binding restores the previous registry and returns an error.

Listener checks request process ownership from `ss -p` and compare each owner PID's `/proc/<pid>/exe` with the configured OpenLiteSpeed binary by actual file identity. A process name alone is insufficient. Another server occupying port 80 or 443, missing ownership information, or unreadable executable identity fails the check and enters the existing recovery path. The installer uses the same executable identity check against its installed OpenLiteSpeed binary and rejects loopback-only or specific-host IPv4 sockets.

DNS still needs the appropriate A and AAAA records. The IPv6 address in the AAAA record must reach this server, and both the host firewall and cloud security group must permit the desired HTTP/HTTPS traffic. The panel does not modify DNS or cloud firewall rules. A local listener record proves socket binding; it does not prove that the website is reachable from the internet.

Use **Security Center → Access Control → Listening Details** to inspect the actual sockets after refreshing. `0.0.0.0` means an IPv4 wildcard address; `::` means an IPv6 wildcard address. The table reports real observations rather than assuming IPv6 is enabled because a domain has an AAAA record.

The upstream [OpenLiteSpeed listener documentation](https://github.com/litespeedtech/openlitespeed/blob/master/dist/docs/Listeners_General_Help.html) and [socket implementation](https://github.com/litespeedtech/openlitespeed/blob/master/src/socket/coresocket.cpp) describe the listener address and socket behavior.

## Website index files

Managed websites use their own virtual-host index settings, with `useServer 0` and `indexFiles index.php,index.html`. OpenLiteSpeed checks these filenames in order. The PHP entry point has priority for WordPress and PHP applications, followed by an HTML homepage. The legacy `index.htm` filename is no longer included in newly generated managed configurations.

The fallback virtual host uses only `index.html` and disables script execution. Server-level installer defaults do not override a managed website's explicit index settings. Changing DNS or adding an IPv6 listener does not change a website's index files.

## HTTPS protocols and PHP limits

Managed HTTPS listeners and each website's SNI certificate block use `sslProtocol 24`, permitting TLS 1.2 and 1.3. OpenLiteSpeed's protocol bits are 8 and 16 respectively; the old value 30 also allowed TLS 1.0 and 1.1. This matches the [upstream default and protocol definitions in OpenLiteSpeed v1.9.3](https://github.com/litespeedtech/openlitespeed/blob/v1.9.3/src/sslpp/sslcontext.h#L55-L62). Website certificate paths and chain settings remain unchanged.

Configuration regeneration reads the site's persisted `lsphp_max_children`. Clearing cache, applying PHP settings and a managed configuration rebuild retain this limit rather than falling back to 10. Legacy zero values still use the existing default of 10. `maxConns` and `PHP_LSAPI_CHILDREN` remain equal. A per-site ceiling is not an aggregate VPS memory budget; use actual resource measurements for many busy sites.

## Configuration history and new WordPress rewrites

Enabled-site changes and paused-site configuration writes keep at most seven automatic previous virtual-host configurations per website. Identical writes do not create a new version. Current configuration, other websites and manually named files remain intact. This small configuration-history limit is separate from database and website-file backup retention.

New WordPress deployments prepare the standard root `.htaccess` before the first virtual-host load, only when it is absent. Existing package rules are preserved, and the generic reinstall/import deployment does not create these rules. Real files and directories retain their handlers; WordPress permalinks route through `index.php`. The rules match [WordPress core's root permalink rules](https://developer.wordpress.org/reference/classes/wp_rewrite/mod_rewrite_rules/). Later plugin-specific rewrite edits still need the normal OpenLiteSpeed configuration reload; this change does not add a background watcher or override plugin rules in the virtual host.

## Trusted CDN proxy ranges

OpenLiteSpeed reads trusted proxy addresses from the server's `accessControl` → `allow` directive with a `T` suffix, together with `useIpInProxyHeader 2` (Trusted IP Only). An otherwise unreferenced `trusted-ip-list` file does not connect custom CDN ranges to this ACL. See the [official visitor-IP configuration guide](https://docs.openlitespeed.org/config/logs/visitorip/).

The panel now appends explicitly enabled, selected CDN ranges to the one recognized server allow directive. It preserves the original administrator-owned line, permissions and Linux owner, records its own additions, and restores the original line when its trust entries are removed. Unknown structures, additional server includes, manual edits to the managed line and nonempty server deny lists stop automatic trust additions for manual review. This prevents a more specific trusted subnet from overriding an administrator's deny rule.

Upgrade step `1.0.76` reconciles enabled CDN ranges only for a recognized, running, unpaused managed service. It does not start a stopped service. Configuration and restart failures trigger restoration; incomplete database, ACL or virtual-host recovery is reported explicitly rather than claiming success. A startup reconciliation failure is logged without preventing panel startup; a normal settings save returns the error.

Official range refreshes require both Cloudflare IPv4 and IPv6 endpoints to succeed with nonempty valid ranges of the expected address family. A timeout, empty response, invalid range or family mismatch preserves the previous Cloudflare cache. When a website has actually selected an enabled Cloudflare group that uses this cache, refresh also reconciles the real server `allow ...T` ACL before applying Fail2ban. An unchanged ACL does not restart OpenLiteSpeed. Unselected, disabled or explicitly static-range groups do not trigger this cache-driven ACL update. A selected but stopped or paused service leaves the original cache and configuration in place and reports that refresh must be retried after the service resumes. Application failure restores the previous cache snapshot, owned ACL and any attempted Fail2ban configuration; incomplete recovery is returned as an error.

The official-range timer defaults to enabled and runs each Monday at 04:00 in the server's system timezone. `Persistent=true` catches a scheduled run missed while the timer was stopped; starting the timer does not otherwise force a download. The manual refresh and timer both refresh Cloudflare and the crawler identification caches. This weekly download is independent of the two-minute per-website Cloudflare WAF ban reconciliation. The timer's CLI exits with a nonzero status on application failure so systemd records the failed oneshot. Its next-run display describes the schedule, and the overall last-refresh timestamp does not prove that each individual source downloaded successfully.

Listener-address changes retain the full service restart because OpenLiteSpeed requires stop/start for port changes. Configuration generation, SQLite state, PHP helper and real file-operation checks run locally, but this Windows review cannot establish native Linux ownership, startup, actual TLS negotiation, custom-CDN request handling or end-to-end WordPress HTTP behavior. Those checks remain part of release validation.
