# Sherlock GUI

A desktop OSINT front end. The **Username** tab runs
[Sherlock](https://github.com/sherlock-project/sherlock) and
[Maigret](https://github.com/soxoj/maigret) side by side (~370 + ~3000 sites),
merges their results into one table and adds what the command lines lack:

- **Description** and **Category** for every site (social, developer,
  gaming, adult, forum...) with a category filter
- **Detection**, **HTTP** and **Engine** columns so you can see *why* and *who*
  said a profile exists
- a **false-positive filter**: every claimed result gets a confidence
  (High / Medium / Low) from a known-flaky-site list, the HTTP status, bot-wall
  and soft-404 detection, engine agreement, redirects to generic/login pages
  and whether the username appears in the page; Low rows are hidden by default
- **Verify claimed** (or *Auto-verify when finished*): re-requests every claimed
  URL with a second, independent request and marks each row Verified / Unclear /
  Failed / Blocked
- a **page preview pane**: title, description, heading, the sentences that
  mention the username, and whatever Maigret extracted (name, bio, ids...)
- **username variations** (dan.lowther -> danlowther, dan_lowther, danlowther1,
  realdanlowther ... editable patterns)
- **profile pictures**: *Fetch pictures* downloads the picture from every
  claimed profile page, shows it in the preview pane, and marks rows that
  share the same picture (which also raises their confidence - the same
  photo on two sites is the strongest sign the accounts are one person);
  right-click any row to send its picture to a reverse image search
- several usernames at once, proxy support, CSV / TXT / JSON export buttons,
  light/dark mode. Every site is always searched - there is no NSFW toggle.

Four more tabs:

- **Email** - [holehe](https://github.com/megadose/holehe) asks ~120 services
  whether an address is registered (password-reset style probes; nothing is
  sent to the address), plus Gravatar and mail-domain (MX) checks.
- **Phone** - offline parsing with `phonenumbers`: validity, region, line
  type, original carrier, time zones, E.164 / national formats, quick links.
- **Domain** - registration data via RDAP (WHOIS fallback), DNS records,
  a web probe, and every hostname seen in public TLS certificates (crt.sh).
- **Image** - reverse image search with no API key: an image URL (or any
  row's profile picture, via right-click) opens in Google Lens, Bing Visual
  Search, Yandex Images and TinEye; a local file opens each engine's upload
  page with the path on the clipboard. Images are fingerprinted (dHash) so
  a photo can be compared against every profile picture fetched on the
  Username tab.

Works on Windows and macOS. Builds to a standalone app that needs no Python
on the target machine.

## Which file do I use?

| I want to... | Windows | macOS |
|---|---|---|
| Run it from source (self-setup) | `run.bat` | `run.command` |
| Build a standalone app | `build-exe.bat` -> `dist\Sherlock GUI\Sherlock GUI.exe` (keep the folder together) | `build-app.command` -> `dist/Sherlock GUI.app` |

Both build scripts install their own prerequisites: Windows finds a real Python
3.9+ (ignoring the Store stub) or installs 3.12 silently via winget / python.org;
macOS installs Homebrew and `python` + `python-tk` if no bundle-able Python
exists (Apple's own python3 is refused - its Tk is too old to ship). Sherlock,
Maigret, holehe and every other dependency are baked into the built app;
Maigret/holehe/whois are *optional* - if one cannot be installed the build
still succeeds and the app says which tab or engine is missing. Each build writes a
log (`build-win-log.txt` / `build-mac-log.txt`) and runs a self-test at the end;
"PROBLEMS FOUND" means look at the log.

The `.command` files are committed with the executable bit set, so a `git clone`
or GitHub ZIP download double-clicks straight away - no `chmod`. If a copy has
lost that bit (e.g. zipped up on Windows and unzipped on the Mac) and Finder
says it "could not be executed", run it once from Terminal as
`bash build-app.command` (or `bash run.command`); the script then repairs the
permissions on both `.command` files itself.

## Using it

Each tab opens with a short description of what it does and what the results
mean (switch off under **Settings > Show tab descriptions**); **Help > What each
tab does** has the full guide.

1. Type one or more usernames (space or comma separated) and press **Search**
   (or Enter).
2. Rows arrive live. Claimed profiles are coloured by confidence: green High,
   amber Medium, red Low. Double-click opens the profile; right-click for
   copy / verify / mark-as-flaky.
3. **Verify claimed** re-checks every claimed row, hidden ones included (tick *Auto-verify when finished* to do it automatically). Verified rows go
   green; Failed and Blocked rows drop to Low and disappear while
   *Hide likely false positives* is on.
4. **File > Export** writes the *visible* rows as CSV, JSON or a plain list
   of URLs.

### Filters ("Show" bar)

| Control | Effect |
|---|---|
| Hide likely false positives | hides Claimed rows scored Low |
| Min confidence | Any / Medium / High - hides anything below |
| Available | also list sites where the username is free |
| Unknown / errors | also list timeouts, WAF blocks, illegal usernames |
| Descriptions | show/hide the Description and Category columns |
| Category | one category only |
| Filter | free text across username, site, URL, description, reason |

### How confidence is scored

Sherlock decides a profile exists from one of three rules per site: an HTTP
status code, a redirect, or an "error message" string missing from the page.
Bot walls, rate limits and soft-404 pages fool those rules. So:

- **Low**: site is on the false-positive list; HTTP 403 / 429 / 5xx; a
  Cloudflare/AWS/PerimeterX challenge page; a "not found / doesn't exist /
  suspended" message in the page title or body; the engines disagree; the
  request was redirected to a homepage or login page; or a Verify
  re-request failed or was blocked.
- **Medium**: the username does not appear anywhere in the returned page, the
  page is nearly empty, Maigret flagged it as a look-alike "similar" page, or no
  page text was available to inspect.
- **High**: everything else, and anything Verify confirms (a flaky-list site
  that verifies only rises to Medium).

The **Why** column spells out the reasons for each row.

The false-positive site list ships with the sites Sherlock is most often wrong
about (Xbox Gamertag, Kik, Wattpad, Fiverr, Spotify, Instagram, TikTok...).
Edit it under **Settings > False-positive site list...**, or right-click any
row to add or remove its site. It is saved with your other settings.

### Engines

**Settings** lets you switch Sherlock and Maigret on and off individually and
limit Maigret to its top 500 / 1500 sites when you want a faster run (all
~3000 by default). Both run at the same time; a profile both engines find is
one row with Engine = `Maigret + Sherlock`, and the two agreeing counts
towards its confidence while disagreeing pulls it down. The app's own
checker (same detection rules, browser User-Agent) is what Verify uses, and it
stands in for Sherlock automatically if the package cannot be imported.

## Files

```
sherlock-gui/
  sherlock_gui.py            the app (Tkinter GUI, four tabs)
  engines.py                 Sherlock + Maigret runners, built-in checker, scoring, Verify
  tools.py                   holehe email checker, phone lookup, domain lookup
  images.py                  profile-picture finder, dHash fingerprints, reverse-search links
  site_info.py               site descriptions, categories, default flaky list
  sherlock_gui_app.py        frozen entry point (selftest, crash log, -psn_ strip)
  requirements.txt           required: sherlock-project, requests, phonenumbers, dnspython, pillow...
  requirements-optional.txt  optional: maigret, holehe, httpx, python-whois
  run.bat / run.command      from-source launchers (self-setup venv per OS)
  build-exe.bat              Windows standalone build (onedir - the app is large)
  ensure_python.ps1          Windows helper: find or install a real Python
  build-app.command          macOS standalone build
  sherlock_gui.json          your settings - created beside the app on first close
```

Settings live beside the exe / next to the `.app` (never inside the bundle).
A crash at start-up is written to `sherlock-gui-crash.log` in the same place
and shown in a dialog.

## Notes

- **Stop** aborts Sherlock at its next result, halts Maigret's event loop and
  drops any queued built-in checks; only requests already on the wire carry on
  until they time out. Closing the window stops every worker the same way and
  the process exits within three seconds regardless.
- The site list comes from the `data.json` inside the installed
  `sherlock-project` package, so updating the package (`pip install -U
  sherlock-project` in the venv, then rebuild) updates the sites.
- Descriptions are hand-written for the ~350 best-known sites; anything
  newer gets a category from keyword heuristics and its domain as the
  description.
