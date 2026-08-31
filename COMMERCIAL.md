# Commercial Licence

This software is dual-licensed. You may use it under **either** of the
following, at your option:

1. the **GNU Affero General Public License v3.0** (see `LICENSE`), at no cost; or
2. a **commercial licence** purchased from the copyright holder.

You only need to read further if the AGPL does not work for you.

## What the AGPL requires

The AGPL is a strong copyleft licence. If you distribute this software, or
offer it to third parties over a network, you must make the **complete
corresponding source code** of your version available to those users under the
AGPL — including any modifications you made and any code you linked into it.

For most on-premise deployments this is not a burden. Running the software on
your own site, for your own vehicles, without handing it to anybody else, is
plain internal use: the AGPL asks nothing of you.

The obligation bites in three situations:

- **You resell it.** Shipping the software (modified or not) to customers as
  part of a product or an installation service is distribution.
- **You host it for others.** Operating it as a service that people outside
  your organisation interact with over a network triggers AGPL §13, even
  without distribution.
- **You want to keep your changes closed.** Site-specific integrations, custom
  detector weights wired into the pipeline, or a proprietary module linked
  against this code all fall under the same source-disclosure requirement.

## What the commercial licence changes

A commercial licence removes the source-disclosure obligations. Specifically it
grants the right to:

- distribute the software, in binary or source form, without releasing your own
  source code;
- offer it as a hosted or managed service without AGPL §13 disclosure;
- keep modifications, integrations and trained model weights proprietary;
- sublicense it as an embedded component of your own product.

It also comes with what a commercial buyer generally needs and the AGPL
deliberately does not provide: a defined warranty, indemnification, a support
undertaking, and a named contact for security issues.

## Which one applies to you

| Situation | AGPL is enough | Commercial licence needed |
|---|:---:|:---:|
| One site, your own vehicles, no modifications | ✅ | |
| One site, your own modifications, kept in-house | ✅ | |
| Evaluation, research, teaching | ✅ | |
| You publish your modifications under the AGPL | ✅ | |
| Installing it for a paying customer | | ✅ |
| Reselling it inside a hardware bundle | | ✅ |
| Multi-tenant hosting for other companies | | ✅ |
| Keeping your integration or weights closed | | ✅ |

If your situation is not on this list, ask rather than guess. A short email
costs less than a licence dispute.

## Licence keys are not the licence

The software enforces a signed licence key at runtime (`src/lpr/license.py`).
That mechanism is a **technical** control, not the legal grant. Possessing a
working key does not by itself confer commercial rights, and the absence of one
does not remove rights the AGPL gives you. The two are independent: the
document you agreed to is what governs.

Circumventing the key check is permitted under the AGPL for a version you are
entitled to run and modify. It is not permitted under the commercial licence,
and it does not create commercial rights you did not buy.

## Third-party components

This project depends on separately licensed software, and a commercial licence
for this project does not relicense any of it. The obligations of those
components remain yours to meet. The dependencies with the strongest terms are
listed in `README.md`; `ultralytics` in particular is itself AGPL-3.0, so a
commercial deployment that includes YOLO needs a commercial arrangement with
Ultralytics as well as with us.

Model weights are not covered by this licence at all. Weights fetched by
`scripts/fetch_models.py` carry their own upstream terms; weights you train
yourself are yours.

## Contact

Hasan Efe Avcı — <hasanefeavc@gmail.com>

Please include your intended deployment (number of sites, number of cameras,
whether you are reselling, and whether you need to keep modifications closed).
That is enough to quote against.
