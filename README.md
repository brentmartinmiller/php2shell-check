# php2shell-check

A read-only triage script for WordPress sites after **PHP2Shell**
(CVE-2026-109618 and CVE-2026-109619), the pair of critical remote code
execution bugs in the PHP engine disclosed on October 21, 2026.

Patching PHP closes the door, but exploitation attempts were observed as
early as **October 17**, before the public disclosure. Any site that was
reachable on an unpatched PHP during that window may already have a backdoor,
and updating PHP won't remove it. This script checks one or many WordPress
sites for the things an attacker with code execution typically leaves behind,
and writes a Markdown report for each.

It **never modifies or deletes anything**. It lists, verifies and reports.
What to do with the findings is up to you.

## What it checks

| Area | Check |
|---|---|
| PHP | Installed CLI version vs. the fixed releases (8.2.35, 8.3.36, 8.4.27, 8.5.12). Flags end-of-life branches with no official fix. |
| Core integrity | `wp core verify-checksums` against wordpress.org |
| Plugin integrity | `wp plugin verify-checksums --all`, and lists premium/custom plugins it can't verify |
| Uploads | Any PHP-executable file under `wp-content/uploads` (ignores "Silence is golden" stubs) |
| Recent changes | PHP and config files modified since the window start (default 2026-10-17) |
| Prepend hooks | `auto_prepend_file` / `auto_append_file` in `.user.ini`, `.htaccess`, `php.ini` |
| Must-use plugins | Contents of `wp-content/mu-plugins` (runs on every request, hidden from the normal plugin list) |
| Code patterns | Classic web-shell signatures (`eval(base64_decode(...))`, `$_POST[...]()`, etc.) in `wp-content` |
| Users | All administrators, and any account registered inside the window |
| Database | `siteurl`/`home`, options and posts containing injected scripts or obfuscated code |
| Cron | WP-Cron scheduled events |
| Server | The site user's crontab and SSH `authorized_keys` |

WP-CLI is run with `--skip-plugins --skip-themes` so a backdoored plugin or
theme can't execute while the check runs.

## Requirements

On each machine being checked:

- `bash` 4+, GNU `find` and `grep` (standard on Linux hosts)
- [WP-CLI](https://wp-cli.org/) for the checksum, user and database checks.
  Without it the file-system checks still run and the report says what was skipped.
- `php` on the path, for the version check

For remote sites: SSH key access from the machine you run the script on.
The script runs itself over SSH; nothing needs to be installed on the remote
host beyond the above.

## Usage

```bash
chmod +x php2shell-check.sh

# One local site
./php2shell-check.sh /var/www/example.com

# One remote site
./php2shell-check.sh deploy@203.0.113.10:/var/www/html

# Many sites from a list
./php2shell-check.sh sites.txt
```

`sites.txt` has one site per line, either a local path or `user@host:path`.
Relative remote paths are relative to the SSH user's home directory. Lines
starting with `#` are ignored. See `sites.txt.example`.

Non-standard SSH ports, keys and jump hosts belong in `~/.ssh/config`:

```
Host client-a
    HostName 203.0.113.10
    Port 2222
    User deploy
    IdentityFile ~/.ssh/client-a
```

Then list the site as `client-a:/var/www/html`.

### Options

Set these as environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SINCE` | `2026-10-17` | Start of the window for "recently modified" and "recently registered" checks |
| `WP` | `wp` | WP-CLI command on the target, e.g. `WP="php $HOME/wp-cli.phar"` for shared hosts |
| `OUT` | `./php2shell-reports` | Where reports are written |

```bash
WP="php $HOME/wp-cli.phar" SINCE=2026-10-15 ./php2shell-check.sh sites.txt
```

## Output

`php2shell-reports/SUMMARY.md` is a table with one row per site:

| Site | CLI PHP | ⚠️ Problems | 🔎 Review | Report |
|---|---|---|---|---|
| client-a:/var/www/html | 8.3.36 | 0 | 2 | client-a_var_www_html.md |

Each site's report is a Markdown file with one section per check, using:

- ⚠️ **likely problem**: unpatched PHP, failed checksums, PHP in uploads
- 🔎 **review by hand**: things that are often legitimate but need a look
  (recently changed files, admin list, mu-plugins, cron events)
- ✅ clean
- ℹ️ information

Start with the ⚠️ items, then work through 🔎.

## Reading the results

**Attempts are not breaches.** Nearly every PHP site on the internet is being
scanned right now. Exploitation attempts in your access logs tell you the site
was targeted, not that it was compromised. The file and database checks are
what tell you that.

**Checksums beat timestamps.** Attackers can set a file's modification time
to anything. A clean "recently modified" list is reassuring; a clean
`verify-checksums` result is evidence.

**Some hits are normal.**

- `auto_prepend_file` pointing at `wordfence-waf.php` is Wordfence, not malware.
- Analytics and header-script plugins store `<script src=...>` in options.
- Some obfuscated premium plugins trip the code-pattern check.
- Updating plugins or core during the window puts files in the "recently changed" list.

**CLI PHP ≠ web PHP.** The version check reads the command-line PHP. PHP-FPM
or mod_php can be running a different version. Confirm with `phpinfo()` or
your hosting panel. Distro packages (Debian, Ubuntu, RHEL) may also backport
the fix without changing the version number; check the package changelog
for the CVE IDs.

## If you find something

Don't just delete the web shell and move on. The attacker had code
execution as the web server user, so assume they read `wp-config.php` and
have your database credentials.

1. Take the site offline or put it behind maintenance mode.
2. Preserve evidence: copy the access/error logs and the suspicious files
   somewhere safe before cleaning.
3. Restore from a backup taken before October 17 if you have one. If not,
   reinstall core and plugins from fresh downloads and audit the theme and
   uploads by hand.
4. Rotate **everything**: database password, WordPress salts in
   `wp-config.php`, all admin passwords, any API keys stored in the site,
   and SFTP/SSH credentials.
5. Update PHP, WordPress core, plugins and themes **before** bringing the
   site back online.
6. Re-run this script and check the logs for a week afterward.

## Limitations

- It looks for common indicators, not every possible backdoor. A clean
  report lowers the odds of compromise; it doesn't prove it.
- It doesn't parse web server logs. Pull those separately and look for
  unusual POST traffic from the 17th onward.
- Shared hosting often has no SSH or WP-CLI. For those sites, use the
  host's file manager and malware scanner, and ask the host when they
  patched PHP.
- WordPress only. The PHP version check is useful on any PHP host, but the
  rest assumes a WordPress layout.

## Contributing

Issues and pull requests are welcome, especially additional indicators of
compromise as the PHP2Shell campaigns develop, and support for other PHP
applications (Drupal, Magento, Laravel). Keep the script read-only.

## References

- [PHP security advisory](https://www.php.net/) and the GitHub advisories
  GHSA-w8hw-w9fx-j79w (CVE-2026-109618) and GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- [Wiz Research: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)
- [Calif: php2shell](https://calif.io/php2shell/)
- [Sansec: PHP2Shell](https://sansec.io/research/php2shell)
- [watchTowr FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)

## License

MIT. See [LICENSE](LICENSE).
