#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
#
# SPDX-License-Identifier: AGPL-3.0-only

# Collects facts from an image or root once, privileged, then lints them twice unprivileged: human and SARIF.
set -euo pipefail

if [[ -n "${IMAGE:-}" && -n "${ROOT:-}" ]] || [[ -z "${IMAGE:-}" && -z "${ROOT:-}" ]]; then
  echo "::error::set exactly one of image and root (image='${IMAGE:-}', root='${ROOT:-}')"
  exit 2
fi

version="${VERSION:-}"
if [[ -z "${version}" ]]; then
  case "${ACTION_REF:-}" in
    '' | *[!0-9.]*) version=latest ;;
    *) version="${ACTION_REF}" ;;
  esac
fi
tool="${SYSTEMLINT_IMAGE:-kiota.ch/damian-buho/systemlint:${version}}"
echo "systemlint image ${tool} (version ${version}, action ref ${ACTION_REF:-none})"

pull() {
  if docker pull --quiet "$1" > /dev/null; then
    echo "pulled $1"
  elif docker image inspect "$1" > /dev/null 2>&1; then
    echo "pull of $1 failed, using the local copy"
  else
    echo "::error::image $1 is neither pullable nor local"
    exit 1
  fi
}
pull "${tool}"

out="${RUNNER_TEMP:-$(mktemp --directory)}/systemlint"
mkdir --parents "${out}"
facts="${out}/facts.json"
sarif="${out}/systemlint.sarif"
human="${out}/report.txt"

sandbox=(--rm --interactive --network none --read-only --security-opt no-new-privileges --cap-drop ALL --entrypoint /usr/local/bin/systemlint)
config=()
if [[ -n "${CONFIG:-}" ]]; then
  sandbox+=(--volume "$(realpath -- "${CONFIG}"):/etc/systemlint/config.yaml:ro")
  config=(--config /etc/systemlint/config.yaml)
  echo "config ${CONFIG}"
fi

subject=()
if [[ -n "${IMAGE:-}" ]]; then
  pull "${IMAGE}"
  docker image inspect "${IMAGE}" > "${out}/image-config.json"
  subject=(--mount "type=image,source=${IMAGE},target=/subject" --volume "${out}/image-config.json:/image-config.json:ro")
  where=(--root /subject --image-config /image-config.json)
  echo "subject image ${IMAGE}"
else
  subject=(--volume "$(realpath -- "${ROOT}"):/subject:ro")
  where=(--root /subject)
  echo "subject root ${ROOT}"
fi

docker run "${sandbox[@]}" --user 0 --cap-add DAC_READ_SEARCH "${subject[@]}" "${tool}" "${config[@]}" --quiet facts "${where[@]}" --json > "${facts}"
echo "facts ${facts}: $(wc --bytes < "${facts}") bytes"

lint=("${config[@]}" lint -)
if [[ -n "${TAGS:-}" ]]; then
  lint+=(--tags "${TAGS}")
fi
user=(--user "$(id --user):$(id --group)")
docker run "${sandbox[@]}" "${user[@]}" "${tool}" "${lint[@]}" --format sarif --fail-on never < "${facts}" > "${sarif}"
status=0
docker run "${sandbox[@]}" "${user[@]}" "${tool}" "${lint[@]}" --fail-on "${FAIL_ON:-error}" < "${facts}" > "${human}" || status=$?
cat -- "${human}"
echo "lint exit ${status} at fail_on ${FAIL_ON:-error}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf '### Systemlint\n\n```text\n%s\n```\n' "$(cat -- "${human}")" >> "${GITHUB_STEP_SUMMARY}"
fi
result=pass
if [[ "${status}" -eq 1 ]]; then
  result=fail
fi
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'facts=%s\nsarif=%s\nresult=%s\n' "${facts}" "${sarif}" "${result}" >> "${GITHUB_OUTPUT}"
fi
exit "${status}"
