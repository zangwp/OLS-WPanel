# WordPress access, cache and security status

The Website details page separates saved options from evidence of actual behavior.

## Administrator access

The **Overview** tab shows the current WordPress login URL and its source. Detection uses WordPress’s own login URL, including active login plugins. A manual URL changes only the panel button destination and must remain on this website. It does not rename a WordPress endpoint.

WordPress setup is preserved. Before setup is complete, the panel links to the installation wizard; users still choose their site title, administrator account and password there.

Panel-authorized administrator sign-in is off by default. Enable it deliberately, then confirm the current panel password and configured panel MFA each time. Select an existing WordPress administrator; the panel does not create users or retain website passwords. Authorization is random, expires after 60 seconds, is usable once, and travels in an HTTPS POST rather than a URL. Redemption binds it to the originating panel session, website, PHP user, settings generation and unchanged WordPress administrator identity.

This feature requires website HTTPS, the site PHP cURL extension with Unix socket support, and the panel’s local broker. Recognized MFA/authentication plugins and detected authentication hooks disable authorized sign-in. This feature replaces the ordinary WordPress sign-in flow with panel authorization; compatibility with arbitrary plugins that register only during browser login cannot be guaranteed. Keep it disabled for unverified custom authentication systems and use ordinary WordPress login. Existing hidden-login rules may also disable it. Logging out of the panel, revoking pending authorizations or changing access settings invalidates unused authorization. An already established WordPress session remains governed by WordPress.

The optional panel-managed login suffix changes the actual login entry through a named MU plugin. It requires WordPress permalinks and compatible OpenLiteSpeed rewrites, and refuses suffixes that conflict with existing files, directories, pages or routes. Before reporting success, the panel checks the new route at the local origin with certificate validation retained and restores the previous configuration on failure. Leave the suffix blank to restore the default. If recovery is necessary, rename the `ols-wpanel-access.php` file identified on the page over SSH; do not edit unrelated plugins.

## Page and object caches

For WordPress, LiteSpeed Cache decides which responses are cacheable. The panel configures OpenLiteSpeed’s cache module and lookup support while leaving default public caching off. An extra panel checkbox is not needed, and old panel flags cannot turn on indiscriminate public caching. Generic PHP website controls retain their existing behavior.

The status cards show three separate facts: the managed OLS configuration, saved plugin page-cache settings, and saved Redis object-cache settings. Configuration checking does not prove a running worker loaded it, and Redis configuration does not prove a successful Redis connection.

**Verify Cache Hit** makes up to two anonymous requests to this website’s local-origin homepage and examines LiteSpeed cache headers. It does not follow redirects, skip TLS validation, send login cookies or probe arbitrary addresses. A cache hit confirms that request only. A miss, cookie, private response or excluded homepage can be legitimate; it does not automatically mean the plugin is disabled. CDN edge-cache behavior requires a separate check.

## Website security verification

Each item gives its reason, evidence source, collection time and relevant setting shortcut. The states have different scopes:

- **Configuration checked** means that settings or rules exist; request enforcement has not been established.
- **Runtime components ready** means that required components, such as the site’s Fail2ban log monitor, were checked. No artificial failed login or attack is generated.
- **Core policy verified** means that the site’s WordPress core was loaded as the website user with third-party content, normal network calls and SQL writes isolated. It checks core behavior, not every plugin or production request. Site `wp-config.php` remains executable website-owned code within the existing site-user trust boundary.
- **Request verified** requires actual TLS, harmless path-check or recent trusted request-log evidence. This does not imply that every attack class is blocked or that an IP ban occurred.

Verification failures and configuration changes invalidate previous positive evidence. SQL-injection rules remain limited to documented URI/query patterns; they are not a complete WAF. Monitoring and backup settings show readiness rather than claiming a restore test was performed.
