<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
-->

# Rules that cite the standards they satisfy

- Rules carry the controls of CIS Ubuntu Linux 26.04, DISA STIG, CIS Controls v8, NIST SP 800-53 and 800-171, PCI DSS 4, ISO 27001:2022, HIPAA and the dev-sec baselines as tags, so `--tags cis`, `--tags 'cis-ubuntu-26.04:5.2.*'` or `--tags pci-dss` runs one standard or one of its sections. See [rules](how-to/rules.md).
- A rule that matches a Lynis test names it, so a team moving from Lynis keeps its reference points.
- Where two standards contradict each other, such as forced password rotation against NIST SP 800-63B, the run reports one conflict and fails the host on neither, and `--prefer 'cis-ubuntu-26.04:*'` lets one standard win every conflict. See [conflicting standards](how-to/rule-book.md#conflicting-standards).
- A threshold a standard picks defaults to that standard’s number and changes with `--var`, and a waiver with an expiry date silences a finding you accept until it is due again.
