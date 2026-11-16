<!--
SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
SPDX-License-Identifier: AGPL-3.0-only
pf-cli-managed: yes
-->

<!-- textlint-disable terminology,common-misspellings -->

[English](../../README.md) · [Español](../es/README.md)

# Systemlint

Systemlint збирає факти про хост, кореневу файлову систему чи образ контейнера, а потім оцінює їх декларативними правилами. Збирання й оцінювання — окремі кроки, тож один збережений документ фактів слугує будь-якій кількості політик.

Ядро читає кожен файл і виконує кожну команду; кожен плагін — окремий статичний бінарний файл, який лише перетворює ці байти на факти. Написаний на Rust.

[![Stand with Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/badges/StandWithUkraine.svg)](https://damian-buho.github.io/support-ukraine/) [![Projectfile inside](https://badges.kiota.ch/static/v1?label=projectfile&message=inside&labelColor=0d0d0d&color=8c6723&style=flat-square)](https://projectfile.org) [![License](https://badges.kiota.ch/static/v1?label=license&message=AGPL-3.0-only&color=1e5913&style=flat-square)](LICENSE) [![Cosign](https://badges.kiota.ch/static/v1?label=cosign&message=enabled&color=1e5913&style=flat-square)](https://docs.sigstore.dev/cosign/verifying/verify/)

![Project status](https://badges.kiota.ch/static/v1?label=status&message=maintained&color=1d63ed&style=flat-square) [![Last commit on kiota.ch](https://badges.kiota.ch/gitea/last-commit/damian-buho/systemlint?gitea_url=https://kiota.ch&label=last%20commit%20on%20kiota.ch&style=flat-square)](https://kiota.ch/damian-buho/systemlint)

[![Publish pipeline on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/published.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Vulnerability audit on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/audited.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Dependency freshness on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/check-outdated.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions) [![Analysis sweep on kiota.ch](https://kiota.ch/damian-buho/systemlint/badges/workflows/analyzed.yaml/badge.svg?style=flat-square)](https://kiota.ch/damian-buho/systemlint/actions)

## Можливості

- Правила, які знають, для яких хостів вони написані
- Швидкий збір лише для читання
- Виправлення, які він робить сам, і лише ті, що забирають доступ
- Знахідки, які прочитає людина, конвеєр і екранний читач
- Правила, що посилаються на стандарти, яким вони відповідають

Також успадковує можливості B19 / Ubuntu — повний перелік див. у [Можливості](FEATURES.md).

## Що надає цей проєкт

- **Виконуваний файл** `systemlint` — команда `systemlint`
- **Образ контейнера** `kiota.ch/damian-buho/systemlint:latest`

## Підтримувані платформи

- `linux/amd64`
- `linux/arm64`

## Встановлення

### Образ контейнера

Завантажте опублікований образ контейнера:

```sh
docker pull kiota.ch/damian-buho/systemlint:latest
```

Стабільні випуски також публікують теґи `X.Y.Z`, `X.Y` і `X` — завантажте той рівень точності, який хочете зафіксувати.

### Готовий архів

Завантажте архів для своєї архітектури й розпакуйте його в `/usr/local`:

```sh
systemlint --version
```

Архів містить ядро, його плагіни, збирачі та набори правил у `bin/`, `lib/systemlint/` і `share/systemlint/`.

## Використання

Перевірте образ контейнера зі збереженими власниками й правами (Docker 28 або новіший), у форматі SARIF:

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --mount type=image,source=ubuntu:26.04,target=/subject --entrypoint systemlint kiota.ch/damian-buho/systemlint:latest check --root /subject --format sarif > systemlint.sarif
```

Перевірте хост, на якому запускаєте, лише для читання, від root і лише з можливістю читати будь-який файл:

```sh
docker run --rm --network none --read-only --cap-drop ALL --cap-add DAC_READ_SEARCH --user 0 --volume /:/host:ro --entrypoint systemlint kiota.ch/damian-buho/systemlint:latest check --root /host
```

## Збирання

Клонуйте репозиторій і виконайте `make` — кожен крок збирання, ціль і точка входу описані в [Збирання](BUILD.md).

## Документація

- [Local accounts and groups](../how-to/accounts.md)
- [apt sources](../how-to/apt.md)
- [Authentication configuration](../how-to/auth.md)
- [Linting images in CI](../how-to/ci.md)
- [Collectors](../how-to/collectors.md)
- [Configuration: files, layers and precedence](../how-to/configuration.md)
- [Environment variables](../how-to/env.md)
- [File permissions](../how-to/files.md)
- [Outputs: SARIF and Prometheus metrics](../how-to/outputs.md)
- [Plugin protocol v1](../how-to/protocol.md)
- [Rule book: how to write a shipped rule](../how-to/rule-book.md)
- [Rules and rulesets](../how-to/rules.md)
- [Kernel parameters, modules and audit rules, AIDE, AppArmor, Docker, systemd units, plain-text servers, running services, listening sockets, ufw and nftables](../how-to/services.md)
- [OpenSSH server](../how-to/sshd.md)

## Політики

- [Як зробити внесок](CONTRIBUTING.md)
- [Політика безпеки](SECURITY.md)
- [Як отримати підтримку](SUPPORT.md)
- [Кодекс поведінки](CODE_OF_CONDUCT.md)
- [Політика щодо ШІ та LLM](AI_POLICY.md)

## Посилання

- [Специфікація Projectfile](https://projectfile.org)

## Ліцензія

Цей проєкт ліцензовано на умовах AGPL-3.0-only — див. файл [LICENSE](LICENSE) для подробиць.

<!-- textlint-enable -->
