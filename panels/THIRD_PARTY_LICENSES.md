# Third-party code in the panels

The mailbox panel's formatting editor uses two browser libraries and a few
icons. The libraries' prebuilt bundles are kept unchanged in
`panels/vendor/` (only the trailing `sourceMappingURL` comment is removed)
and are inlined into the panel when the server serves it, because the
panel's sandbox does not load scripts from anywhere else. Neither bundle
makes network requests. The icons' SVG paths are copied into the panel.

| Name | Version | Licence | Source | File | Licence text |
|---|---|---|---|---|---|
| Squire | 2.4.10 | MIT | https://github.com/neilj/Squire (npm package `squire-rte`, `dist/squire.js`) | `vendor/squire.js` | `vendor/LICENSE-squire.txt` |
| DOMPurify | 3.4.17 | Apache-2.0 or MPL-2.0 (dual licence) | https://github.com/cure53/DOMPurify (npm package `dompurify`, `dist/purify.min.js`) | `vendor/purify.js` | `vendor/LICENSE-dompurify.txt`, `vendor/LICENSE-dompurify-MPL.txt` |
| Lucide icons | 1.70.0 | ISC (the icons italic and link derive from Feather, MIT; both notices are in the licence text) | https://lucide.dev, https://github.com/lucide-icons/lucide (npm package `lucide-static`) | SVG paths copied into the toolbar in `mailbox.html`: bold, italic, underline, list, list-ordered, text-quote, link, unlink, remove-formatting | `vendor/LICENSE-lucide.txt` |

To update a library, install the exact version with npm outside the
repository, review the new bundle, copy it over the file above, and change
the version here.
