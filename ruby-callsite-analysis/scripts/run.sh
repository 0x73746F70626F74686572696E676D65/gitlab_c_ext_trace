#!/usr/bin/env bash
set -euo pipefail
analysis_repo="$(cd "$(dirname "$0")/../.." && pwd)"
python_bin="${PYTHON_BIN:-python3}"
gitlab_source="${1:?Pass the pinned GitLab checkout directory}"
results_dir="${2:-$analysis_repo/ruby-callsite-analysis/results}"
PYTHONHASHSEED=1 "$python_bin" "$analysis_repo/ruby-callsite-analysis/scripts/analyze.py" \
  --repo "$analysis_repo" --gitlab "$gitlab_source" \
  --native-data "$analysis_repo/ruby-callsite-analysis/inputs/native" --out "$results_dir"
"$python_bin" "$analysis_repo/ruby-callsite-analysis/scripts/finalize.py" --out "$results_dir"
"$python_bin" "$analysis_repo/ruby-callsite-analysis/scripts/validate.py" \
  --repo "$analysis_repo" --gitlab "$gitlab_source" --out "$results_dir"
