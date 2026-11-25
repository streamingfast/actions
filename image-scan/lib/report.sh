#!/usr/bin/env bash
# Rendering helpers of the image-scan actions, sourced (not executed) by gate/scan.sh and weekly/scan.sh. Needs jq.
#
# Like scanner.sh and weekly/scan.sh this is where the scanner output format is known: SARIF as written by
# `docker scout cves --format sarif`, one rule per CVE with `properties` holding cvssV3_severity, security-severity,
# purls, affected_version and fixed_version. A field Scout does not provide is rendered as "unknown" / "no fix", the
# helpers never fail on a report they cannot read (they return an empty list), a missing table must not hide a finding.
#
# Rows are JSON arrays:
#   findings   [{id, severity, package, installed, fixed}]   severity: critical|high|medium|low|unknown, fixed: "" when none
#   statements [{id, status, justification, impact, timestamp, author, file, products}]   OpenVEX statements of vex-location,
#                                                                                       products: the product ids (purls, names)
#   suppressed [{id, severity, package, installed, fixed, status, statements: [{justification, impact, timestamp, author, file, scoped}]}]
#              status is "not_affected" when a statement explains the CVE, "" otherwise. statements are the ones whose products match
#              the scanned image (scoped true), else the most recent one of the CVE id with scoped false

# jq definitions shared by the renderings of a suppressed row (VEX_JQ_DEFS), and the matching of a statement product to an image.
# Image and products are compared the way Scout names them: pkg:oci/<repo>?repository_url=<registry> (with or without @sha256:
# digest and tag qualifier), pkg:docker/[<registry>/]<repo>, or a plain [<registry>/]<repo>[:tag][@digest]. A product without
# registry matches any registry, one without digest any digest, tags never count.
read -r -d '' VEX_JQ_DEFS <<'JQ' || true
def url_decode: gsub("%2[Ff]"; "/") | gsub("%3[Aa]"; ":") | gsub("%40"; "@");
def norm_registry: if . == "index.docker.io" or . == "registry-1.docker.io" then "docker.io" else . end;
def split_ref:
  sub("@.*$"; "") | sub(":[^/:]*$"; "") | index("/") as $i
  | (if $i == null then {registry: "", repo: .}
     else .[:$i] as $first
       | if ($first | test("[.:]")) or $first == "localhost" then {registry: ($first | norm_registry), repo: .[$i + 1:]} else {registry: "", repo: .} end
     end)
  | if .registry == "docker.io" then .repo |= sub("^library/"; "") else . end;
def digest_of: if test("^sha256:") then . else "" end;
def qualifier($key): (split("?")[1] // "" | (split("#")[0] // "") | split("&") | map(select(startswith($key + "="))) | .[0] // "" | sub("^[^=]*="; ""));
def image_ref:
  split("@") as $p
  | ($p[0] | split_ref | if .registry == "" then .registry = "docker.io" | .repo |= sub("^library/"; "") else . end) + {digest: ($p[1] // "" | digest_of)};
def product_ref:
  url_decode as $d
  | if startswith("pkg:oci/") then
      ($d | sub("^pkg:oci/"; "")) as $body
      | ($body | sub("[?#].*$"; "")) as $path
      | ($path | sub("@.*$"; "")) as $name
      | ($path | if test("@") then sub("^[^@]*@"; "") | digest_of else "" end) as $digest
      | ($body | qualifier("repository_url") | sub("^https?://"; "") | sub("/$"; "")) as $registry
      | if $registry == "" then {registry: "", repo: $name, digest: $digest}
        else (if $registry == $name or ($registry | endswith("/" + $name)) then $registry else $registry + "/" + $name end | split_ref) + {digest: $digest} end
    else
      ($d | sub("^pkg:docker/"; "") | sub("[?#].*$"; "")) as $path
      | ($path | split_ref) + {digest: ($path | if test("@") then sub("^[^@]*@"; "") | digest_of else "" end)}
    end;
def product_matches($image):
  (try product_ref catch null) as $p
  | $p != null and $p.repo == $image.repo
    and ($p.registry == "" or $p.registry == $image.registry)
    and ($p.digest == "" or $image.digest == "" or $p.digest == $image.digest);
def statement_text:
  "\(.justification | if . == "" then "no justification" else . end)\(if .impact == "" then "" else " - " + .impact end) [\(.file)]\(if .scoped then "" else " (statement not scoped to this image)" end)";
def suppressed_explanation:
  if (.statements | length) == 0 then "suppressed, not by a vex-location statement" else .statements | map(statement_text) | join(" | ") end;
JQ

# sarif_findings <report.sarif>: one row per CVE (the rules of the report, plus the rule ids only seen in results)
sarif_findings() {
  [[ -s "$1" ]] || { echo '[]'; return 0; }
  jq -c '
    def rule_text: ((.help.text // .fullDescription.text // .shortDescription.text // "") | tostring);
    def field($name): (rule_text | capture("(?m)^\\s*" + $name + ":\\s*(?<v>.+?)\\s*$").v? // "");
    def purl: ((.properties.purls // [])[0] // "");
    def severity:
      ((.properties.cvssV3_severity // "") | ascii_downcase) as $level
      | ((.properties["security-severity"] // "") | tonumber? // null) as $score
      | if ($level | IN("critical", "high", "medium", "low")) then $level
        elif $score != null then (if $score >= 9 then "critical" elif $score >= 7 then "high" elif $score >= 4 then "medium" else "low" end)
        else "unknown" end;
    def purl_name:
      if startswith("pkg:") then
        (sub("^pkg:"; "") | sub("[@?#].*$"; "")) as $path
        # the namespace of an OS package is the distribution (debian/openssl), the one of a golang package is its module path
        | if ($path | test("^(deb|apk|rpm)/")) then ($path | sub("^.*/"; "")) else ($path | sub("^[^/]+/"; "")) end
      else . end;
    def purl_version: if startswith("pkg:") and test("@") then (sub("^[^@]*@"; "") | sub("[?#].*$"; "")) else . end;
    def package:
      (if purl != "" then purl else field("Package") end) | if . == "" then "unknown" else purl_name end;
    def installed:
      . as $rule
      | (.properties.affected_version // (purl | if test("@") then purl_version else "" end))
      | if . == "" then ($rule | field("Affected version") | purl_version | if . == "" then "unknown" else . end) else . end;
    def fixed:
      (.properties.fixed_version // field("Fixed version") // "")
      | if test("^(|not fixed|none|n/a)$"; "i") then "" else . end;
    ([.runs[]?.tool.driver.rules[]? | {id, severity: severity, package: package, installed: installed, fixed: fixed}]) as $rules
    | ([.runs[]?.results[]?.ruleId] | unique | map({id: ., severity: "unknown", package: "unknown", installed: "unknown", fixed: ""})) as $fromResults
    | ($rules + $fromResults | group_by(.id) | map(.[0]))
    | sort_by([({"critical": 0, "high": 1, "medium": 2, "low": 3}[.severity] // 4), .id])' "$1" 2>/dev/null || echo '[]'
}

# vex_statements <file-or-directory>: statements of the OpenVEX documents (*.json, *.jsonld) of the location
vex_statements() {
  local location="$1" file
  local -a files=()
  if [[ -d "${location}" ]]; then
    while IFS= read -r -d '' file; do files+=("${file}"); done < <(find "${location}" -type f \( -name '*.json' -o -name '*.jsonld' \) -print0 | sort -z)
  elif [[ -f "${location}" ]]; then
    files=("${location}")
  fi
  ((${#files[@]})) || { echo '[]'; return 0; }
  for file in "${files[@]}"; do
    # vulnerability is an object ({name}) since OpenVEX 0.2.0 and a plain string before
    jq -c --arg file "${file}" '
      (.author // "") as $docAuthor | (.timestamp // "") as $docTimestamp
      | [.statements[]?
         | {id: (.vulnerability | if type == "object" then (.name // ."@id" // "") else (. // "") end | tostring),
            status: (.status // ""),
            justification: (.justification // ""),
            impact: (.impact_statement // .status_notes // ""),
            timestamp: (.timestamp // $docTimestamp),
            author: (.author // $docAuthor),
            file: $file,
            products: [.products[]? | if type == "object" then (."@id" // .identifiers.purl // "") else . end | tostring | select(. != "")]}]' "${file}" 2>/dev/null || echo '[]'
  done | jq -sc 'add // []'
}

# suppressed_findings <all-findings> <active-findings> <statements> [image]: the CVEs reported without the VEX documents and no longer
# with them, each with the not_affected statements that explain it. With an image these are the statements whose products match it
# (all of them, several documents may speak about the CVE); when none does, the most recent statement of the CVE id marked not scoped
# to the image. Without image, the most recent statement of the CVE id.
suppressed_findings() {
  jq -nc --argjson all "$1" --argjson active "$2" --argjson statements "$3" --arg image "${4:-}" "${VEX_JQ_DEFS}"'
    ($active | map(.id)) as $activeIds
    | (if $image == "" then null else ($image | image_ref) end) as $img
    | $all | map(select(.id as $id | $activeIds | index($id) | not))
    | map(. as $f
        | ($statements | map(select(.id == $f.id and .status == "not_affected"))) as $byId
        | (if $img == null then []
           else $byId | map(select(.products | any(.[]; product_matches($img)))) | map(. + {scoped: true}) | sort_by([.file, .timestamp]) end) as $scoped
        | (if ($scoped | length) > 0 then $scoped
           else ($byId | sort_by(.timestamp) | last // null | if . == null then [] else [. + {scoped: ($img == null)}] end) end) as $chosen
        | $f + {status: (if ($chosen | length) > 0 then "not_affected" else "" end),
                statements: ($chosen | map({justification, impact, timestamp, author, file: (.file | split("/") | last), scoped}))})' 2>/dev/null || echo '[]'
}

# stale_statements <all-findings> <statements>: not_affected statements matching no finding of the image (the fix shipped?)
stale_statements() {
  jq -nc --argjson all "$1" --argjson statements "$2" '
    ($all | map(.id)) as $ids
    | $statements | map(select(.status == "not_affected" and .id != "" and (.id as $id | $ids | index($id) | not)))' 2>/dev/null || echo '[]'
}

# ineffective_statements <statements>: statements Scout ignores, only not_affected suppresses a CVE
ineffective_statements() {
  jq -c 'map(select(.status != "not_affected"))' <<<"$1" 2>/dev/null || echo '[]'
}

# findings_text <findings>: aligned plain text table for the log
findings_text() {
  local table
  table="$(jq -r '(["CVE", "SEVERITY", "PACKAGE", "INSTALLED", "FIXED"] | @tsv),
    (.[] | [.id, .severity, .package, .installed, (if .fixed == "" then "no fix" else .fixed end)] | @tsv)' <<<"$1")"
  if command -v column >/dev/null 2>&1; then column -t -s $'\t' <<<"${table}"; else echo "${table}"; fi
}

# findings_markdown <findings> [limit]: markdown table, at most <limit> rows (default 100) to stay below the comment size limit
findings_markdown() {
  jq -r --argjson limit "${2:-100}" '
    def cell: tostring | gsub("[|]"; "\\|") | gsub("[\r\n]+"; " ");
    "| CVE | Severity | Package | Installed | Fixed |", "|---|---|---|---|---|",
    (.[:$limit][] | "| \(.id | cell) | \(.severity) | `\(.package | cell)` | \(.installed | cell) | \(if .fixed == "" then "no fix" else (.fixed | cell) end) |"),
    (if length > $limit then "", "… and \(length - $limit) more, see the scanner report below" else empty end)' <<<"$1"
}

# suppressed_text <suppressed>: one line per CVE for the log
suppressed_text() {
  jq -r "${VEX_JQ_DEFS}"'.[] | "\(.id) (\(.severity)) \(.package) \(.installed): \(suppressed_explanation)"' <<<"$1"
}

# suppressed_markdown <suppressed> [limit]
suppressed_markdown() {
  jq -r --argjson limit "${2:-100}" "${VEX_JQ_DEFS}"'
    def cell($max): tostring | gsub("[|]"; "\\|") | gsub("[\r\n]+"; " ") | if length > $max then .[:$max] + "…" else . end;
    def per_statement(f): if (.statements | length) == 0 then "" else .statements | map(f) | join("<br>") end;
    "| CVE | Severity | Package | Installed | Justification | Author | Statement date |", "|---|---|---|---|---|---|---|",
    (.[:$limit][] | "| \(.id | cell(40)) | \(.severity) | `\(.package | cell(80))` | \(.installed | cell(40)) | \(
        if .status == "" then "_suppressed, not by a statement of vex-location_"
        else per_statement(
          ([(.justification | select(. != "")), (.impact | select(. != "") | cell(300))] | join(": ") | if . == "" then "_none_" else . end)
          + " (`\(.file | cell(60))`)" + (if .scoped then "" else " _(statement not scoped to this image)_" end)) end) | \(per_statement(.author | cell(80))) | \(per_statement(.timestamp | cell(40))) |"),
    (if length > $limit then "", "… and \(length - $limit) more" else empty end)' <<<"$1"
}
