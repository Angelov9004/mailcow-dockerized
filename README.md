# mailcow: dockerized - 🐮 + 🐋 = 💕

[![Translation status](https://translate.mailcow.email/widgets/mailcow-dockerized/-/translation/svg-badge.svg)](https://translate.mailcow.email/engage/mailcow-dockerized/)
[![Twitter URL](https://img.shields.io/twitter/url/https/twitter.com/mailcow_email.svg?style=social&label=Follow%20%40mailcow_email)](https://twitter.com/mailcow_email)
![Mastodon Follow](https://img.shields.io/mastodon/follow/109388212176073348?domain=https%3A%2F%2Fmailcow.social&label=Follow%20%40doncow%40mailcow.social&link=https%3A%2F%2Fmailcow.social%2F%40doncow)


## Want to support mailcow?

Please [consider a support contract with Servercow](https://www.servercow.de/mailcow?lang=en#support) to support further development. _We_ support _you_ while _you_ support _us_. :)

You can also [get a SAL](https://www.servercow.de/mailcow?lang=en#sal) which is a one-time payment with no liabilities or returning fees.

Or just spread the word: moo.

## Many thanks to our GitHub Sponsors ❤️
A big thank you to everyone supporting us on GitHub Sponsors—your contributions mean the world to us! Special thanks to the following amazing supporters:

### 100$/Month Sponsors
  <a href="https://www.colba.net/" target=_blank><img
    src="https://avatars.githubusercontent.com/u/204464723" height="58"
  /></a>
  <a href="https://www.maehdros.com/" target=_blank><img
    src="https://avatars.githubusercontent.com/u/173894712" height="58"
  /></a>

### 50$/Month Sponsors
  <a href="https://github.com/vnukhr" target=_blank><img
    src="https://avatars.githubusercontent.com/u/7805987?s=52&v=4" height="58"
  /></a>

## Python + PostgreSQL stack (this branch)

This branch runs the mailcow UI/API as a Python service (`api-mailcow`, FastAPI) on top of PostgreSQL 16
(`postgres-mailcow`) instead of PHP-FPM on MariaDB. The mail components (Postfix, Dovecot, Rspamd, SOGo, ...)
are unchanged and read their lookup tables from PostgreSQL. Security behaviour of the original UI (password
schemes, sessions, CSRF, fail2ban integration, API keys with IP allow lists, roles/ACLs, two-factor auth) is kept.

See [docs/PYTHON_POSTGRES_PORT.md](docs/PYTHON_POSTGRES_PORT.md) for the layout, the migration procedure from an
existing MariaDB installation and the list of features that are not ported yet.

## Info, documentation and support

Please see [the official documentation](https://docs.mailcow.email/) for installation and support instructions. 🐄

🐛 **If you found a critical security issue, please mail us to [info at servercow.de](mailto:info@servercow.de).**

## Cowmunity

[mailcow community](https://community.mailcow.email)

[Telegram mailcow channel](https://telegram.me/mailcow)

[Telegram mailcow Off-Topic channel](https://t.me/mailcowOfftopic)

[Official 𝕏 (Twitter) Account](https://twitter.com/mailcow_email)

[Official Mastodon Account](https://mailcow.social/@doncow)

Telegram desktop clients are available for [multiple platforms](https://desktop.telegram.org). You can search the groups history for keywords.

## Misc

**Important**: mailcow makes use of various open-source software. Please assure you agree with their license before using mailcow.
Any part of mailcow itself is released under **GNU General Public License, Version 3**.

mailcow is a registered word mark of The Infrastructure Company GmbH, Parkstr. 42, 47877 Willich, Germany.

The project is managed and maintained by The Infrastructure Company GmbH.

Originated from @andryyy (André)
