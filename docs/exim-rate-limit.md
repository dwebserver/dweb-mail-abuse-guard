# Exim authenticated-recipient rate limit

The file `packaging/exim/authenticated-recipient-limit.acl` is an optional synchronous safety net for the existing `acl_smtp_rcpt` ACL. It keys the counter by `$authenticated_id`, uses `per_rcpt`, and therefore counts recipients across concurrent and sequential authenticated connections.

Start with the `warn` statement. Confirm the rates in `/var/log/exim_mainlog`, adjust the threshold for the server, and use Exim's configuration and SMTP ACL test tools before deploying any rejection. cPanel owns its Exim configuration, so make the integration through WHM's supported Exim advanced editor and keep a copy outside generated configuration files.

The enforcing example is commented out. A production change should be staged, tested with a dedicated authenticated mailbox, and accompanied by a documented rollback. Never paste it over an existing RCPT ACL: it is one statement inside that ACL, not a replacement ACL.

The rate limiter is a ceiling, not compromise attribution. The watchdog remains responsible for correlating source diversity and provider rejections and for performing mailbox-scoped containment.
