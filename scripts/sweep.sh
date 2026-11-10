#!/usr/bin/env bash
# Fetches the pinned corpus (bench/corpus.toml) into a gitignored directory,
# runs `epic audit` on each, and writes JSON results + a summary table to
# bench/results/. Re-run to reproduce; existing clones are checked out to
# their pin again rather than re-cloned.
#
# Protocols with role = "sweep" make up the 5-protocol production sweep
# total. role = "supplementary" protocols (e.g. the real Squads V4, tracked
# separately from the squads-mpl entry that was previously mislabeled
# "squads-v4") are audited and reported but never summed into that total.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS_DIR="$REPO_ROOT/bench/corpus"
RESULTS_DIR="$REPO_ROOT/bench/results"
RAW_DIR="$RESULTS_DIR/raw"
COVERAGE_DIR="$RESULTS_DIR/coverage"
MANIFEST="$REPO_ROOT/bench/corpus.toml"

mkdir -p "$CORPUS_DIR" "$RAW_DIR" "$COVERAGE_DIR"

echo "Building epic (release)..."
cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml" -p epic >/dev/null
EPIC_BIN="$REPO_ROOT/target/release/epic"

# Parses bench/corpus.toml's fixed [[protocol]] / name / repo / commit / role
# shape line by line — the manifest's schema is small and owned by this
# script, so a real TOML parser would be dead weight here.
names=()
repos=()
commits=()
roles=()
name="" ; repo="" ; commit="" ; role="sweep"
flush() {
    if [[ -n "$name" ]]; then
        names+=("$name"); repos+=("$repo"); commits+=("$commit"); roles+=("$role")
    fi
}
while IFS= read -r line; do
    case "$line" in
        '[[protocol]]') flush; name="" ; repo="" ; commit="" ; role="sweep" ;;
        name\ =\ *) name=$(sed -E 's/name = "(.*)"/\1/' <<<"$line") ;;
        repo\ =\ *) repo=$(sed -E 's/repo = "(.*)"/\1/' <<<"$line") ;;
        commit\ =\ *) commit=$(sed -E 's/commit = "(.*)"/\1/' <<<"$line") ;;
        role\ =\ *) role=$(sed -E 's/role = "(.*)"/\1/' <<<"$line") ;;
    esac
done < "$MANIFEST"
flush

TOTAL_ALL=0
: > "$RESULTS_DIR/timing.tsv"
for i in "${!names[@]}"; do
    n="${names[$i]}"; r="${repos[$i]}"; c="${commits[$i]}"
    dest="$CORPUS_DIR/$n"
    if [[ ! -d "$dest/.git" ]]; then
        echo "Cloning $n from $r..."
        git clone --quiet "$r" "$dest"
    fi
    echo "Checking out $n @ $c..."
    (cd "$dest" && { git checkout --quiet "$c" 2>/dev/null || { git fetch --quiet origin "$c" && git checkout --quiet "$c"; }; })

    echo "Auditing $n..."
    /usr/bin/time -l "$EPIC_BIN" audit "$dest" --format json \
        > "$RAW_DIR/$n.json" 2> "$RAW_DIR/$n.time"
    secs=$(grep "real" "$RAW_DIR/$n.time" | awk '{print $1}')
    peak_kb=$(( $(grep "peak memory footprint" "$RAW_DIR/$n.time" | awk '{print $1}') / 1024 ))
    echo -e "$n\t$secs\t${peak_kb}KB" >> "$RESULTS_DIR/timing.tsv"

    count=$(jq 'length' "$RAW_DIR/$n.json")
    if [[ "${roles[$i]}" == "sweep" ]]; then
        TOTAL_ALL=$((TOTAL_ALL + count))
    fi
    echo "$n (${roles[$i]}): $count findings"

    echo "Measuring coverage for $n..."
    "$EPIC_BIN" coverage "$dest" --format json > "$COVERAGE_DIR/$n.json"
done

sweep_json=()
for i in "${!names[@]}"; do
    [[ "${roles[$i]}" == "sweep" ]] && sweep_json+=("$RAW_DIR/${names[$i]}.json")
done

SUMMARY_FILE="$RESULTS_DIR/summary.md"
{
    echo "# Sweep summary"
    echo
    echo "| Protocol | Findings |"
    echo "|---|---|"
    for i in "${!names[@]}"; do
        [[ "${roles[$i]}" == "sweep" ]] || continue
        n="${names[$i]}"
        echo "| $n | $(jq 'length' "$RAW_DIR/$n.json") |"
    done
    echo
    echo "**Total: $TOTAL_ALL**"
    echo
    echo "## Per rule"
    echo
    echo "| Rule | Count |"
    echo "|---|---|"
    jq -s 'add | group_by(.rule_id) | map("\(.[0].rule_id)\t\(length)") | .[]' -r "${sweep_json[@]}" \
        | sort | awk -F'\t' '{print "| " $1 " | " $2 " |"}'
    echo
    echo "## Per severity"
    echo
    echo "| Severity | Count |"
    echo "|---|---|"
    jq -s 'add | group_by(.severity) | map("\(.[0].severity)\t\(length)") | .[]' -r "${sweep_json[@]}" \
        | sort | awk -F'\t' '{print "| " $1 " | " $2 " |"}'
    echo
    echo "## Supplementary (not in sweep total)"
    echo
    echo "| Protocol | Findings |"
    echo "|---|---|"
    for i in "${!names[@]}"; do
        [[ "${roles[$i]}" == "supplementary" ]] || continue
        n="${names[$i]}"
        echo "| $n | $(jq 'length' "$RAW_DIR/$n.json") |"
    done
    for i in "${!names[@]}"; do
        [[ "${roles[$i]}" == "supplementary" ]] || continue
        n="${names[$i]}"
        echo
        echo "### $n — per rule"
        echo
        echo "| Rule | Count |"
        echo "|---|---|"
        jq 'group_by(.rule_id) | map("\(.[0].rule_id)\t\(length)") | .[]' -r "$RAW_DIR/$n.json" \
            | sort | awk -F'\t' '{print "| " $1 " | " $2 " |"}'
    done
    echo
    echo "## Coverage"
    echo
    echo "A 0-finding protocol with low coverage is not the same as a"
    echo "0-finding protocol with full coverage — this table is what tells"
    echo "them apart."
    echo
    echo "| Protocol | Handlers | Resolved | Fully analyzed |"
    echo "|---|---|---|---|"
    for i in "${!names[@]}"; do
        n="${names[$i]}"
        jq -r --arg n "$n" '"| \($n) | \(.total_handlers) | \(.resolved_to_struct) | \(.fully_analyzed) |"' \
            "$COVERAGE_DIR/$n.json"
    done
    echo
    echo "### Unresolved / partially analyzed handlers, by protocol"
    for i in "${!names[@]}"; do
        n="${names[$i]}"
        skipped=$(jq '[.handlers[] | select(.status.status != "FullyAnalyzed")] | length' "$COVERAGE_DIR/$n.json")
        [[ "$skipped" == "0" ]] && continue
        echo
        echo "**$n** ($skipped not fully analyzed):"
        echo
        jq -r '.handlers[] | select(.status.status != "FullyAnalyzed") |
            "- \(.name) (\(.file)): \(.status.status) — \(.status.reason // .status.boundary_warnings // "CFG build failed")"' \
            "$COVERAGE_DIR/$n.json"
    done
    echo
    echo "## Timing / peak memory"
    echo
    echo "| Protocol | Wall time | Peak RSS |"
    echo "|---|---|---|"
    awk -F'\t' '{print "| " $1 " | " $2 "s | " $3 " |"}' "$RESULTS_DIR/timing.tsv"
} > "$SUMMARY_FILE"

echo
echo "Sweep total: $TOTAL_ALL findings"
cat "$SUMMARY_FILE"
