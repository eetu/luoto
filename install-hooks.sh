#!/usr/bin/env bash
# Point git at the repo's tracked hooks (.githooks/). Run once after cloning.
set -e
git config core.hooksPath .githooks
echo "Installed: core.hooksPath -> .githooks"
