#!/bin/bash

# Copyright 2015 The Kubernetes Authors All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

KUBE_ROOT=$(dirname "${BASH_SOURCE}")/../..
source "${KUBE_ROOT}/hack/lib/init.sh"

kube::golang::setup_env

gendeepcopy=$(kube::util::find-binary "gendeepcopy")

function generate_version() {
  local group_version=$1
  local TMPFILE="/tmp/deep_copy_generated.$(date +%s).go"

  echo "Generating for ${group_version}"

  sed 's/YEAR/2015/' hack/boilerplate/boilerplate.go.txt > $TMPFILE
  cat >> $TMPFILE <<EOF
// DO NOT EDIT. THIS FILE IS AUTO-GENERATED BY \$KUBEROOT/hack/update-generated-deep-copies.sh.

EOF

  "${gendeepcopy}" -v "${group_version}" -f - -o "${group_version}=" >>  "$TMPFILE"

  local dest="pkg/$(kube::util::group-version-to-pkg-path "${group_version}")/deep_copy_generated.go"
  rm -f "${dest}"
  mv "${TMPFILE}" "${dest}"
}

function generate_deep_copies() {
  local group_versions="$@"
  for ver in ${group_versions}; do
    # Ensure that the version being processed is registered by setting
    # KUBE_API_VERSIONS.
    if [ -z ${ver##*/} ]; then
      apiVersions=""
    else
      apiVersions="${ver}"
    fi
    KUBE_API_VERSIONS="${apiVersions:-}" generate_version "${ver}"
  done
}

# v1 is in the group ""
# Currently pkg/api/deep_copy_generated.go is generated by the new go2idl generator.
# All others (mentioned above) are still generated by the old reflection-based generator.
# TODO: Migrate these to the new generator.
DEFAULT_VERSIONS="v1 authorization/__internal authorization/v1beta1 extensions/__internal extensions/v1beta1 componentconfig/__internal componentconfig/v1alpha1 metrics/__internal metrics/v1alpha1 tpm/v1"
VERSIONS=${VERSIONS:-$DEFAULT_VERSIONS}
generate_deep_copies "$VERSIONS"
