# php2shell-check

A read-only triage script for WordPress sites after **PHP2Shell**
(CVE-2026-109618 and CVE-2026-109619), the pair of critical remote code
execution bugs in the PHP engine disclosed on October 21, 2026.

Patching PHP closes the door, but Amazon's honeypots logged an exploitation
attempt on **October 17**, four days before the public disclosure, while the
bugs were still under embargo. That is the earliest activity anyone has
published, not the day attacks began, so treat it as a floor. Any site that
was reachable on an unpatched PHP during that window may already have a
backdoor, and updating PHP won't remove it. This script checks one or many
WordPress sites for the things an attacker with code execution typically
leaves behind, and writes a Markdown report for each.

It **never modifies or deletes anything**. It lists, verifies and reports.
What to do with the findings is up to you.

## What it checks

| Area | Check |
|---|---|
| PHP | Installed CLI version vs. the fixed releases (8.2.35, 8.3.36, 8.4.27, 8.5.12). Flags end-of-life branches, which got no release from php.net; see [Older PHP branches](#older-php-branches). |
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

- `bash` 3.2+, `find`, `grep` and `sort -V` (standard on Linux hosts; also works from a stock macOS workstation)
- [WP-CLI](https://wp-cli.org/) for the checksum, user and database checks.
  Without it the file-system checks still run and the report says what was skipped.
- `php` on the path, for the version check

For remote sites: SSH key access from the machine you run the script on.
The script runs itself over SSH; nothing needs to be installed on the remote
host beyond the above.

## Usage

### On the server itself

```bash
curl -O https://raw.githubusercontent.com/brentmartinmiller/php2shell-check/main/php2shell-check.sh
chmod +x php2shell-check.sh

# One site
./php2shell-check.sh /var/www/example.com
less php2shell-reports/*.md

# Every site on the box
printf '%s\n' /var/www/*/public_html > sites.txt
./php2shell-check.sh sites.txt
cat php2shell-reports/SUMMARY.md
```

Run it as the user that owns the site files where you can. It works as root
(WP-CLI gets `--allow-root`), but the crontab and SSH-key checks then inspect
root's instead of the web user's.

### From your workstation, against many servers

```bash
git clone https://github.com/brentmartinmiller/php2shell-check.git
cd php2shell-check
cp sites.txt.example sites.txt   # edit: one site per line
./php2shell-check.sh sites.txt
```

For each `user@host:path` entry the script SSHes in, runs itself there, and
brings the report back to `php2shell-reports/` on your machine. Nothing is
installed on the remote host. SSH runs with `BatchMode=yes`, so key-based
access that works without a password prompt is required.

### Shared hosting

Most shared hosts (Hostinger, SiteGround, Bluehost and the like) offer SSH but
often don't have `wp` on the path. Check with `which wp`. If it's missing,
download WP-CLI once into your home directory and point the script at it:

```bash
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
WP="php $HOME/wp-cli.phar" ./php2shell-check.sh domains/example.com/public_html
```

Without WP-CLI the file-system checks still run and the report notes what was
skipped. Either way, ask the host directly when they rolled out the patched
PHP, since that's the one thing an account-level check can't see.

### Site list format

`sites.txt` has one site per line, either a local path or `user@host:path`.
Relative remote paths are relative to the SSH user's home directory. Lines
starting with `#` are ignored. See `sites.txt.example`. The file is in
`.gitignore` so client hostnames don't end up in a commit.

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
| `SINCE` | `2026-10-17` | Start of the window for "recently modified" and "recently registered" checks. This is the first confirmed exploitation attempt, not the first attack; set it earlier for sites that matter |
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
`verify-checksums` result is evidence. This matters more than usual here:
whoever was exploiting this on October 17 had four quiet days before anyone
was looking, which is plenty of time to backdate a file and trim a log.

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

### Older PHP branches

php.net shipped fixed releases only for the supported branches, 8.2 through
8.5. The script flags anything older as a likely problem because there is no
version number it can compare against, but the real situation varies:

- **7.4, 8.0 and 8.1** are end-of-life, but the PHP security team published
  limited source backports of the fix, and the common third-party package
  repositories picked them up: deb.sury.org for Debian and Ubuntu, Remi's
  repository for RHEL, Fedora and derivatives, and the AlmaLinux and other
  enterprise-distro updates. A host running one of these branches may already
  be patched with the version number unchanged. Verify through the package
  changelog rather than `php -v`, for example on Debian or Ubuntu:

  ```bash
  zgrep CVE-2026-109618 /usr/share/doc/php8.1-common/changelog.Debian.gz
  ```

  Treat an unpatched 7.4 to 8.1 host as vulnerable until that check passes,
  and plan the move to 8.2 or later regardless; 8.2 itself reaches end of
  life on December 31, 2026.
- **7.3 and older, and all of PHP 5**, received nothing. The bugs reach back
  to PHP 5.4, so any site still on these branches should be assumed exposed
  from October 17 onward and moved to a supported PHP as part of the cleanup.

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
- It doesn't parse web server logs. Pull those separately, and do it soon:
  if the host rotates logs weekly, the pre-disclosure window is about to age
  out. The one network indicator published so far is a multipart POST whose
  body contains `PHP_SESSION_UPLOAD_PROGRESS`. Look from the 17th onward at
  minimum, and further back if the logs allow it.
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

- [PHP October 2026 security releases](https://www.php.net/archive/2026.php)
  and the PHP advisories
  [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
  (CVE-2026-109618, RCE via OOM corruption) and
  [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
  (CVE-2026-109619, RCE via stale global state)
- [Amazon Threat Intelligence: PHP2Shell exploitation prior to public disclosure](https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/),
  the source for the October 17 date and the `PHP_SESSION_UPLOAD_PROGRESS` indicator
- [Wiz Research: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)
- [Calif: php2shell](https://calif.io/php2shell/)
- [Sansec: PHP2Shell](https://sansec.io/research/php2shell)
- [watchTowr FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)

## License

MIT. See [LICENSE](LICENSE).
