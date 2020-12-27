# Dovecot Cheatsheet

> The email server.

## Table of Contents

* [Import from Existing Mailstore](#import-from-existing-mailstore)

### Import from Existing Mailstore

Run this for all users and the emails will get imported and indexed properly.

```bash
doveadm -v import -u user@domain.com maildir:/path/to/domain.com/user/ "" all
```
