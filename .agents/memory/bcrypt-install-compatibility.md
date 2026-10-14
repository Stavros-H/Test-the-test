---
name: Bcrypt install compatibility
description: Why this app uses bcrypt 6 rather than bcrypt 5.
---

Bcrypt 5 pulls in `@mapbox/node-pre-gyp`, which depends on a `tar` version blocked by Replit's package security policy. Bcrypt 6 installs without that dependency chain.

**Why:** The original dependency set could not install in this Replit environment because the package firewall rejected the transitive tar package.

**How to apply:** Keep bcrypt at version 6 or later when changing auth dependencies; do not downgrade to bcrypt 5 without confirming the full dependency tree installs under the current firewall policy.
