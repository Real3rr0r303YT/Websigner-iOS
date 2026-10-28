# Vendored browser libraries

These files are served by GitHub Pages together with the site, so the Web Signer
doesn't depend on a third-party CDN. They were copied unmodified from npm.

| File | Package | Version | License |
| --- | --- | --- | --- |
| `jszip.min.js` | [jszip](https://github.com/Stuk/jszip) | 3.10.1 | MIT or GPL-3.0-or-later |
| `forge.min.js` | [node-forge](https://github.com/digitalbazaar/forge) | 1.3.1 | BSD-3-Clause or GPL-2.0 |
| `nacl-fast.min.js` | [tweetnacl](https://github.com/dchest/tweetnacl-js) | 1.0.3 | Unlicense (public domain) |
| `qrcode.js` | [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) | 1.4.4 | MIT |
| `sealedbox.js` | Written for WebSigner; bundles BLAKE2b from [blakejs](https://github.com/dcposch/blakejs) 1.2.1 | — | GPL-3.0-or-later / blakejs: MIT |

`sealedbox.js` implements libsodium's `crypto_box_seal`, which the GitHub API
requires for Actions secrets.

To update a library, run `npm pack <package>@<version>`, copy the file from the
package's `dist/` folder, and update this table.
