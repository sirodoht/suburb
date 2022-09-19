# Polis

[Polis](https://pol.is/) is an AI powered sentiment gathering platform. More
organic than surveys and less effort than focus groups, Polis meets the basic
human need to be understood, at scale.

For a detailed methods paper, see
[Polis: Scaling Deliberation by Mapping High Dimensional Opinion Spaces][methods-paper].

[methods-paper]: https://www.e-revistes.uji.es/index.php/recerca/article/view/5516/6558

## This fork: sirodoht/polis

This is a friendly fork to experiment with latest Node.js version and other
improvements.

## Fork differences

* No Docker config
* No Heroku config
* No bundlewatch
* Yes Nix config
* No nginx config
* No SSL config
* Yes Caddy config
* Single Node.js (and npm) version for all front components + server
* Latest LTS Node.js version for e2e tests
* e2e cypress updated to v10

## Deployment

See [Server Playbook](server-playbook.md).

## Architecture

* `database/` is migrations and config for the PostgreSQL database
* `server/` is the main Node.js server
    * connects to: database
    * connects to: file-server
* `math/` is the statistics service in Clojure
    * connects to: server
    * connects to: database
* `file-server/` is the service that serves the JS frontend apps:
    * `client-admin/` is for conversation administrators
    * `client-participation/` is for end-users
    * `client-report/` is for detailed analytics reports
* `caddy/` is configs for Caddy server, used as reverse proxy
    * connects to: server

## Comment Translation

**Note:** This feature is optional.

We use Google to automatically translate submitted comments into the language of
participants, as detected by the browser's language.

1. Ensure the `client-participation` [user interface is manually translated][translate-ui] into participant language(s).
    - Noteworthy strings include: [`showTranslationButton`, `hideTranslationButton`, `thirdPartyTranslationDisclaimer`][translate-strings]
1. Click `Set up a project` button within the [Cloud Translation Quickstart Guide][gtranslate-quickstart].
    - Follow the wizard and download the JSON private key, aka credentials file.
1. Convert the file contents into a base64-encoded string. You can do this in many ways, including:
    - copying its contents into [a client-side base64 encoder web app][base64-encoder] (inspect the simple JS code), or
    - using your workstation terminal: `cat path/to/My-Project-abcdef0123456789.json | base64` (linux/mac)
1. Configure `GOOGLE_CREDENTIALS_BASE64` within `server/.env`
1. Configure `SHOULD_USE_TRANSLATION_API=true` within `server/.env`

[translate-ui]: #translating-the-user-interface
[translate-strings]: /client-participation/js/strings/en_us.js#L96-L98
[gtranslate-quickstart]: https://cloud.google.com/translate/docs/basic/setup-basic
[base64-encoder]: https://codepen.io/bsngr/pen/awuDh

## Email Transports

We use [Nodemailer](https://nodemailer.com/about/) to send email. Nodemailer
uses various built-in and packaged _email transports_ to send email via SMTP or
API, either directly or via third-party platforms.

Each transport needs a bit of hardcoded scaffold configuration to make it work,
which we welcome via code contribution. But after this, others can easily use
the same email transport by setting some configuration values via environment
variable or otherwise.

We use `EMAIL_TRANSPORT_TYPES` to set email transports and their fallback
order. Each transport has a keyword (e.g., `maildev`). You may set one or more
transports, separated by commas. If you set more than one, then each transport
will "fallback" to the next on failure.

For example, if you set `aws-ses,mailgun`, then we'll try to send via
`aws-ses`, but on failure, we'll try to send via `mailgun`. If Mailgun fails,
the email will not be sent.

### Configuring transport: `maildev`

Note: The [MailDev](https://github.com/maildev/maildev) email transport is
for **development purposes only**. Ensure it's disabled in production!

1. Add `maildev` into the `EMAIL_TRANSPORT_TYPES` configuration.

### Configuring transport: `aws-ses`

1. Add `aws-ses` into the `EMAIL_TRANSPORT_TYPES` configuration.
1. Set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` configuration.

### Configuring transport: `mailgun`

1. Add `mailgun` into the `EMAIL_TRANSPORT_TYPES` configuration.
1. Set the `MAILGUN_API_KEY` and `MAILGUN_DOMAIN` configuration.

### Adding a new transport

1. [Find a transport for the service you require][transports] (or write your own!)
1. Add any new transport configuration to `getMailOptions(...)` in
   [`server/email/senders.js`][mail-senders].
1. Submit a pull request.

[transports]: https://github.com/search?q=nodemailer+transport
[mail-senders]: /server/email/senders.js

## License

[AGPLv3 with additional permission under section 7](/LICENSE)
