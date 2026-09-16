# Project page

This directory contains only the sources for the public project documentation.
It does not change the extension, printer, installer, API or package version.

## Build the stylesheet

Use Node.js 22 or newer. From this directory:

```sh
npm ci
npm run build
npm run check
```

Tailwind CSS is pinned in `package-lock.json`. Only `../index.html` is scanned.
Commit the generated `../assets/site.css` with changes to HTML or `input.css`.
No sibling Fin3000 checkout, external fonts, JavaScript CDN or runtime build is
needed to serve the page.

## Preview

From the repository root:

```sh
python3 -m http.server 8780 --bind 127.0.0.1 --directory docs
```

Open http://127.0.0.1:8780/. This is a static documentation preview; it does not
connect a Fin3000 account or install a printer.

## Publication

After local acceptance and a reviewed pull request into the public GitHub
`main` branch, a maintainer can enable GitHub Pages in this repository's
Settings → Pages: **Deploy from a branch**, branch **main**, directory **/docs**.

Expected public address: https://fin3000.github.io/fin3000-printer/

The checked-in CSS and `docs/.nojekyll` allow GitHub to serve these static files.
No custom domain, DNS change, extension-store upload or application deployment
is involved. Check the final public URL after GitHub's Pages deployment succeeds.
Do not describe a page as live before that check.

## Content and assets

Keep download and store claims aligned with the actual public release status.
The Linux printer and browser timer must not be presented as signed public
releases until those releases exist. Each page has its own canonical URL, title,
description and visible product-specific text, with contextual links to
https://fin3000.com/ and its tools catalog. No ranking improvements are promised.

Fin3000 and platform artwork is reused unchanged; provenance and trademark
notes are in `../assets/NOTICE.txt`. No analytics, forms, cookies or remote fonts
are embedded. GitHub's hosting infrastructure still handles ordinary requests;
the page does not claim that no processing occurs.
