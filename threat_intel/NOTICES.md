# Third-Party Threat Intelligence Notices

The auto-generated catalogs in this directory (`auto-*.json`) are derived
from public threat-intelligence feeds. Bumblebee itself is Apache-2.0
licensed; the upstream feeds carry their own licenses and copyright
notices, reproduced here to satisfy the attribution requirements of
both Apache-2.0 §4 and the MIT permission notice.

---

## OSSF Malicious Packages — `auto-osv-malicious-*.json`

- **Repository:** https://github.com/ossf/malicious-packages
- **License:** Apache License, Version 2.0
- **Mirrored via:** https://osv.dev (per-ecosystem `all.zip` from
  `osv-vulnerabilities.storage.googleapis.com`)

Licensed under the Apache License, Version 2.0; the upstream
repository does not ship a `NOTICE` file. See
https://www.apache.org/licenses/LICENSE-2.0 for the full license text.

---

## Datadog Malicious Software Packages Dataset — `auto-datadog-malicious-*.json`

- **Repository:** https://github.com/DataDog/malicious-software-packages-dataset
- **License:** Apache License, Version 2.0
- **Detector:** Datadog [GuardDog](https://github.com/DataDog/guarddog)
- **Dataset segments used:** `samples/npm`, `samples/pypi`,
  `samples/ide_extensions`, `samples/ai-skills`

Upstream `NOTICE` file (reproduced per Apache-2.0 §4(d)):

> Malicious Software Packages
> Copyright 2023-Present Datadog, Inc.
>
> This product includes software developed at Datadog
> (https://www.datadoghq.com/).

Suggested citation (from the upstream README):

```
@misc{OpenSourceDatasetMaliciousSoftwarePackages,
  month = Mar,
  day = 20,
  date = 2023,
  journal = {Open-Source Dataset of Malicious Software Packages},
  publisher = {Datadog Security Labs},
  url = https://github.com/datadog/malicious-software-packages-dataset,
}
```

Note: malicious packages may contain legitimate, licensed code; in
those cases the applicable license is the one of the original package
indicated in the metadata of its `setup.py` (PyPI) or `package.json`
(npm).

---

## VSXSentry — `auto-vsxsentry-editor-extensions.json`

- **Repository:** https://github.com/mthcht/awesome-lists (path:
  `Lists/VSCODE%20Extensions/feeds/vsxsentry_malicious_feed.csv`)
- **License:** MIT License

> MIT License
>
> Copyright (c) 2024 @mthcht thunting.io
>
> Permission is hereby granted, free of charge, to any person obtaining
> a copy of this software and associated documentation files (the
> "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to
> the following conditions:
>
> The above copyright notice and this permission notice shall be
> included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

---

## MalExt Sentry — `auto-malext-sentry-browser-extensions.json`

- **Repository:** https://github.com/toborrm9/malicious_extension_sentry
- **License:** MIT License

> MIT License
>
> Copyright (c) 2025-2026 toborrm9
>
> Permission is hereby granted, free of charge, to any person obtaining
> a copy of this software and associated documentation files (the
> "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to
> the following conditions:
>
> The above copyright notice and this permission notice shall be
> included in all copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

---

## ExtSentry — `auto-extsentry-browser-extensions.json`

- **Repository:** https://github.com/ExtSentry/ExtSentry.github.io
- **License:** MIT License (code)
- **Data classification:** `TLP:CLEAR` (no redistribution restriction)
- **Upstream data:** sourced from
  https://github.com/mthcht/awesome-lists (see VSXSentry notice above
  for the underlying copyright).

ExtSentry repackages the mthcht/awesome-lists browser-extensions list
hourly into many output formats; the MIT license terms above apply to
the repacked feed.

---

## Notes for downstream redistributors

Anyone redistributing this directory should preserve this `NOTICES.md`
file. Bumblebee's own license (Apache-2.0) is in the repository root
`LICENSE`; nothing here overrides it.

The hand-curated catalogs in this directory (files NOT prefixed with
`auto-`) are original work by the bumblebee maintainers and contributors
and are covered by the repository's root Apache-2.0 license.
