# Security policy

Please do not open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting for this repository. Include the affected version, platform, reproduction steps, impact, and any suggested mitigation. We will acknowledge a complete report within three business days and coordinate disclosure after a fix is available.

The supported security boundary is the latest released version on a maintained cPanel/Exim platform. The daemon is expected to run unprivileged. The packaged helper and sudo rule are security-sensitive; local changes that broaden their accepted commands or bypass mailbox ownership checks are outside the supported boundary.
