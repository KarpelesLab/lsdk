#!/bin/sh
# Host-onboard a TEST device with the all-zero seed and PIN 1111.
#
# The device must be wiped and in recovery mode. The PIN and recovery phrase
# travel in clear over USB: never use this on a device that holds funds.
#
# Seed: 24-word phrase of all-zero entropy ("abandon" x23 + "art").
# Extra arguments are passed to `lsdk onboard` (e.g. --device /dev/hidrawN).
set -eu

cd "$(dirname "$0")"

WORDS="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

exec cargo run -q --release --features cli --bin lsdk -- \
    onboard --pin 1111 --words "$WORDS" --i-understand-the-seed-travels-over-usb "$@"
