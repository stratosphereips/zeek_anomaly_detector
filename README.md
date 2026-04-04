# zeek_anomaly_detector
[![Docker Image CI](https://github.com/stratosphereips/zeek_anomaly_detector/actions/workflows/docker-image.yml/badge.svg)](https://github.com/stratosphereips/zeek_anomaly_detector/actions/workflows/docker-image.yml)
[![Python Checks](https://github.com/stratosphereips/zeek_anomaly_detector/actions/workflows/python-checks.yml/badge.svg)](https://github.com/stratosphereips/zeek_anomaly_detector/actions/workflows/python-checks.yml)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/stratosphereips/zeek_anomaly_detector/main?color=green)
![Docker Pulls](https://img.shields.io/docker/pulls/stratosphereips/zeek_anomaly_detector?color=green)

An anomaly detector for Zeek logs. It supports both classic Zeek TSV logs and line-delimited Zeek JSON logs, can process a single log or a directory of logs, and applies different anomaly detection strategies depending on the log type.

For a full architecture and methodology walkthrough, open [`docs/tool-explainer.html`](docs/tool-explainer.html) in a browser. That page explains the end-to-end data flow, feature engineering, models, directory scoring, baseline training, outputs, and design rationale in one place.

This is no longer a `conn.log`-only PCA script. The current implementation does all of the following:

- Reads `conn.log`, `http.log`, `files.log`, `ssh.log`, `weird.log`, `notice.log`, `known_services.log`, `known_hosts.log`, `software.log`, `arp.log`, `stats.log`, `capture_loss.log`, `packet_filter.log`, and any other Zeek logs that match the supported schemas.
- Auto-detects input format as Zeek TSV or Zeek JSON.
- Processes a full directory of `.log` files with one command.
- Builds shared context across logs using `uid` and `fuid`.
- Chooses a detector per log type instead of forcing the same model on every schema.
- Computes a directory-level maliciousness score at the end when running on a directory.

## Why The Design Changed

Different Zeek logs represent different kinds of evidence:

- `conn.log` is flow-oriented and benefits from multivariate anomaly detection.
- `http.log` and `files.log` contain application and content metadata that are useful for spotting scans, abuse, and unusual transfers.
- `ssh.log` is sparse but still useful when you model client/server banner rarity and cross-log context.
- `weird.log` and `notice.log` are already event-like and are better handled with rarity and prioritization than with a generic PCA model.
- `known_hosts.log`, `known_services.log`, and `software.log` are inventory/state logs. They are useful for novelty detection, not for classic flow outlier detection.
- `stats.log` and `capture_loss.log` are time-series/system telemetry and should be scored as deviations over time, not as independent flow records.

Using one global model across all of them produces poor results and unstable behavior. The current implementation uses the structure of each Zeek log type instead.

## How It Works

### 1. Input Handling

The tool accepts either:

- A single file with `-f`
- A directory with `-d`

For every file, it:

- Detects Zeek TSV or line-delimited JSON automatically
- Loads the log into a Pandas dataframe
- Keeps the original Zeek fields for display
- Builds detector-specific numeric features separately from the raw log fields

### 2. Cross-Log Correlation With `uid` And `fuid`

The detector does not score each log in isolation only. It first loads all logs in the directory and builds shared context.

#### `uid`

`uid` is the main Zeek transaction identifier used to tie together related activity across logs such as:

- `conn.log`
- `http.log`
- `files.log`
- `ssh.log`
- `weird.log`

The tool aggregates per-`uid` context such as:

- Number of related records in each log type
- Related connection bytes, packets, duration, and state rarity from `conn.log`
- Related HTTP count, body sizes, and status rarity from `http.log`
- Related file count, total bytes, and MIME rarity from `files.log`
- Related weird-event count and weird-name rarity from `weird.log`
- Related SSH counts and auth attempts from `ssh.log`

These aggregated values are then injected back into the per-log feature vectors.

This matters because a record that looks only mildly unusual in one log can become much more suspicious if:

- The same `uid` also triggered weird events
- The same `uid` downloaded a rare file
- The same `uid` had an abnormal HTTP status pattern
- The same `uid` is tied to a high-byte or unusual `conn.log` flow

#### `fuid`

`fuid` is the Zeek file identifier used to tie file activity across logs. The current implementation uses it mainly to enrich `http.log` with file context from `files.log`, including:

- Linked file count
- Linked file total bytes
- Linked MIME rarity
- Linked file source rarity

This is useful when an HTTP request is suspicious because of what it delivered, not just because of the request metadata itself.

### 3. Detector Selection By Log Type

The implementation uses three detector families:

- `IsolationForest` for rich multivariate logs
- Rarity scoring for event/inventory logs
- Time-series deviation scoring for telemetry logs

If `scikit-learn` is not installed, the `IsolationForest` path falls back to a standardized distance score instead of crashing.

### 4. Directory-Level Maliciousness Scoring

When you run the tool on a Zeek directory with `-d`, it does not stop at printing per-file anomalies. After all files are processed, it computes a directory-level maliciousness score intended to help distinguish:

- A mostly normal Zeek directory that still contains a few odd records
- A malicious or attack-heavy directory where anomalies are broader, more correlated, and concentrated in the attack-relevant logs

This score is printed at the end as a separate `Directory Summary`.

#### Why not just sum raw anomaly scores?

Because raw scores are not directly comparable:

- Different log types use different detectors
- Different detectors produce different score scales
- File size and feature spread affect score magnitude
- A benign directory can still have a few high local anomalies

So the directory score does not use raw totals directly.

#### What the directory score uses

The directory score combines the anomaly summary with a behavior profile learned from the whole directory.

The main components are:

1. `weighted_top`

- For each log, the tool computes the mean percentile rank of the top anomalous rows inside that log
- Those values are weighted by log importance
- Attack-relevant logs such as `conn`, `http`, `files`, `tls`, `weird`, and `notice` have higher weight than inventory logs such as `known_hosts`

2. `uid_correlation`

- Counts anomalous `uid` values that appear in two or more log types
- Gives extra weight to anomalous `uid` values seen in three or more log types

This is one of the most important signals, because coordinated activity across logs is more indicative of real malicious behavior than isolated anomalies.

3. `anomaly_fraction`

- Measures how much of each log is being flagged anomalous
- Uses a weighted, normalized anomaly fraction across files

This helps distinguish “a couple of odd rows” from “a large portion of relevant activity looks strange”.

4. `weird_notice`

- Adds weight when `weird.log` or `notice.log` also contain anomalous rows

This matters because these logs already represent unusual or alert-like behavior and often reinforce attack evidence.

5. `fuid_overlap`

- Adds weight when anomalous `http.log` transactions are linked through `fuid` to anomalous `files.log` records

This is useful for suspicious content delivery, payload transfer, and file-backed HTTP anomalies.

6. `behavior_score`

- Builds a source-level behavior profile from `conn.log`
- Measures broad scan-like activity such as:
  - high destination-port fanout
  - large per-destination port sweeps
  - high failed-connection fraction
  - short, zero-payload, service-missing connection patterns
- Keeps the strongest behavioral outliers and prints them in the `Directory Summary`

This is the part that lets the tool detect broad campaigns like simple Nmap scans even when they do not generate much `uid` overlap in higher-level logs.

#### Directory score formula

The current implementation uses this weighted combination:

```text
core_score =
100 * (
  0.35 * weighted_top +
  0.25 * uid_correlation +
  0.20 * anomaly_fraction +
  0.15 * weird_notice +
  0.05 * fuid_overlap
)

directory_score = min(100, core_score + 45 * behavior_score)
```

The final result is shown on a `0-100` scale and labeled as:

- `LOW`
- `MEDIUM`
- `HIGH`

These labels are intended for triage, not as a calibrated probability of compromise.

### 5. Training A Normal Baseline

You can train thresholds from known-normal Zeek directories by passing one or more `--normal-dir` values during a directory run.

Example with one normal directory:

```bash
python3 zeek-anomaly-detector.py \
  -d /path/to/suspect/zeek \
  -N /path/to/known-normal/zeek
```

Example with multiple normal directories:

```bash
python3 zeek-anomaly-detector.py \
  -d /path/to/suspect/zeek \
  -N /path/to/normal1 \
  -N /path/to/normal2 \
  -N /path/to/normal3
```

If you only want a single final line for the directory score, use `--summary-line`:

```bash
python3 zeek-anomaly-detector.py \
  -d /path/to/suspect/zeek \
  --summary-line
```

With a normal baseline, the same one-line output also includes the baseline verdict:

```bash
python3 zeek-anomaly-detector.py \
  -d /path/to/suspect/zeek \
  -N /path/to/normal1 \
  -N /path/to/normal2 \
  --summary-line
```

#### Best way to train when normal traffic varies

The best approach is not to learn a hard threshold from a single raw anomaly score. Normal Zeek directories vary naturally because of:

- Different traffic volumes
- Different protocol mix
- Different scanning and discovery noise
- Different host inventories
- Different capture durations

So the tool learns thresholds from the directory-summary components instead of per-row raw scores.

It computes the normal baseline on:

- `score`
- `weighted_top`
- `weighted_fraction`
- `uid_corr_score`
- `weird_notice_bonus`
- `fuid_bonus`
- cross-log overlap counts

When multiple normal directories are provided, the threshold for each metric is learned with robust statistics:

- median
- MAD-based upper bound

When only one or two normal directories are provided, the tool falls back to a conservative margin above the observed normal values.

This is not as strong as training on many normal directories, but it is still better than using one global fixed threshold.

#### Output

When `--normal-dir` is used, the final output includes a `Baseline Comparison` section that says whether the current directory is:

- `WITHIN NORMAL BASELINE`
- `SUSPICIOUS VS BASELINE`
- `ABOVE NORMAL BASELINE`

It also prints which summary metrics exceeded the learned normal thresholds.

When `--summary-line` is used, the normal terminal output is suppressed and replaced by one final tab-separated line with:

- Input path
- Final directory score, colorized in terminals that support ANSI colors
- Severity, colorized in terminals that support ANSI colors
- Baseline verdict, if `--normal-dir` was used, also colorized in ANSI-capable terminals
- Number of normal directories used for the baseline, if any

## Techniques By Log Type

### `conn.log`

Technique: `IsolationForest`

Why:

- `conn.log` is the closest thing to classic flow anomaly detection.
- Attacks often appear as unusual combinations of bytes, packets, ports, service, connection state, and duration.
- Multivariate detection is more appropriate than per-feature thresholding.

Main features include:

- Destination port
- Duration
- Total bytes
- Total packets
- Originator/responder byte ratio
- Originator/responder packet ratio
- Bytes per second
- Bytes per packet
- Port rarity
- Service rarity
- Connection-state rarity
- History rarity
- Destination-host popularity
- Related `uid` context from HTTP, files, SSH, and weird logs

This is the best log for finding scan activity, strange connection fan-out, failed probes, weird size ratios, or traffic that does not match the rest of the environment.

### `http.log`

Technique: `IsolationForest`

Why:

- Malicious HTTP behavior is usually a combination of method, URI, status, body sizes, host rarity, and user-agent weirdness.
- Single-value thresholds are weak here.
- Cross-log correlation matters because the delivered file can be more suspicious than the HTTP line itself.

Main features include:

- Destination port
- Transaction depth
- Request and response body length
- Status code
- URI length
- Host length
- User-agent length
- Method rarity
- Status rarity
- Host rarity
- URI rarity
- User-agent rarity
- Count of linked response and originator file IDs
- Linked file counts, linked file bytes, and linked file MIME rarity through `fuid`
- Related `uid` connection and weird-event context

This helps surface scanning, unusual methods, suspicious paths, odd user agents, and HTTP transactions associated with rare or suspicious files.

### `dns.log`

Technique: DNS-specific hybrid score

Why:

- DNS abuse often shows up as lexical anomalies, response-pattern anomalies, or repeated bursts of algorithmic-looking domains from the same source host.
- DGA traffic is rarely visible from a single field only. It is usually a combination of domain randomness, TLD choice, no-answer behavior, and repeated source-side querying patterns.
- Generic outlier detection tends to over-rank benign mDNS and reverse-lookup traffic, so the DNS detector uses a custom score instead.

Main features include:

- Destination port
- Query length
- Label count
- First-label length
- Query entropy
- Unique-character ratio
- Vowel ratio
- Consonant ratio
- Digit ratio
- Query rarity
- TLD rarity
- Query-type rarity
- Response-code rarity
- Answer count
- TTL count
- No-answer flag
- Rejected flag
- `dga_like` lexical heuristic
- `dga_pattern_count` for repeated DGA-like patterns
- `src_dga_like_count` for repeated DGA-like queries from the same source host
- `is_mdns`
- `is_local_tld`
- `is_reverse_lookup`
- `is_service_discovery`
- Related conn/weird context by `uid`

#### DGA-related behavior

The DNS detector explicitly tries to capture DGA-like behavior. It does not rely on a signature list. Instead, it uses lexical and repetition features such as:

- Long first labels
- High character entropy
- High unique-character ratio
- Low vowel ratio or noticeable digit presence
- Repeated queries of similarly structured random-looking domains from the same source host

This means domains such as:

- `kvcjsnsd.ru`
- `afajgvcnm.ru`
- `wtkfidatyhc.ru`

will not only look suspicious individually, but repeated appearances of the same DGA-like pattern from the same source host will increase the anomaly score further.

The detector also explicitly downweights benign local-resolution traffic such as:

- mDNS on port `5353`
- `.local` names
- `in-addr.arpa`
- `ip6.arpa`
- service-discovery names such as `_googlecast._tcp.local`

That is intentional, so DGA-like domains rank above local multicast noise.

### `files.log`

Technique: `IsolationForest`

Why:

- File transfers are often suspicious because of size, MIME type, source, timeout behavior, or mismatch with related activity.
- File metadata is rich enough for multivariate outlier detection.

Main features include:

- Destination port
- Depth
- Duration
- Seen bytes
- Total bytes
- Missing bytes
- Overflow bytes
- `local_orig`
- `is_orig`
- `timedout`
- MIME rarity
- Source rarity
- Analyzer count
- Byte gap between seen and total
- Related HTTP, conn, and weird context by `uid`

This is useful for surfacing rare files, unusual transfer sizes, suspicious extracted content, and file transfers linked to strange HTTP sessions.

### `ssh.log`

Technique: `IsolationForest`

Why:

- SSH logs are relatively sparse, but still useful for detecting unusual client banners, server banners, auth behavior, and correlation with suspicious connection context.

Main features include:

- Destination port
- Auth attempts
- Client string length
- Server string length
- Client rarity
- Server rarity
- Related connection, weird, and HTTP/file context by `uid`

This helps highlight scans, banner anomalies, and behavior linked to other suspicious events.

### `tls.log`

Technique: `IsolationForest`

Why:

- TLS metadata is usually best handled as multivariate fingerprint-style anomaly detection.

Main features include:

- Destination port
- TLS version
- Cipher count
- Server-name length
- JA3 rarity
- JA3S rarity
- SNI rarity
- Related connection and weird context by `uid`

Note: if your `tls.log` does not contain JA3, JA3S, or SNI-like fields, the detector will use whatever TLS metadata exists. If there is no `tls.log` in the directory, nothing special happens.

### `weird.log`

Technique: rarity scoring

Why:

- `weird.log` already records unusual protocol or parser behavior.
- The right question is not “is this vector an outlier?” but “how rare and how correlated is this weird event?”

Main features include:

- Destination port
- Notice flag
- Weird-name rarity
- Source-module rarity
- Peer rarity
- Related conn/http/files/ssh context by `uid`

This is useful for surfacing weird events that are both rare and tied to suspicious sessions.

### `notice.log`

Technique: rarity scoring

Why:

- `notice.log` is already a higher-level detection stream.
- It should be prioritized, not modeled like raw traffic.

Main features include:

- `n`
- `suppress_for`
- Notice-type rarity
- Source rarity
- Message length

This helps rank notices rather than replace Zeek’s own detection logic.

### `known_services.log`

Technique: rarity scoring

Why:

- This log is inventory-like.
- It is useful for novelty detection such as unusual service/port exposure.

Main features include:

- Port number
- Service rarity
- Host rarity
- Transport rarity

This can surface unusual service exposure or drift in observed services.

### `known_hosts.log`

Technique: rarity scoring

Why:

- This is host inventory, not flow telemetry.
- The meaningful signal is host novelty and timing irregularity.

Main features include:

- Host rarity
- Time-gap deviation between observations

This is useful for new host discovery, churn, or unusual host appearance timing.

### `software.log`

Technique: rarity scoring

Why:

- This log describes discovered software and versions, which is mostly inventory.
- Rare software/version combinations are often more useful than geometric outlier detection.

Main features include:

- Host port
- Major/minor version
- Software-type rarity
- Product-name rarity
- Additional-version rarity
- Unparsed version length

This helps surface unusual software/version fingerprints.

### `arp.log`

Technique: rarity scoring

Why:

- ARP activity is short, structured, and often better handled with novelty-style scoring.
- Suspicion often comes from unusual request/reply patterns or MAC/IP rarity.

Main features include:

- Operation rarity
- Source-MAC rarity
- Destination-MAC rarity
- Broadcast-request flag
- Originator-IP rarity
- Responder-IP rarity

This is useful for flagging strange ARP activity, especially in lab or small networks.

### `stats.log`

Technique: time-series deviation scoring

Why:

- `stats.log` is telemetry about Zeek itself and overall traffic processing.
- These are time-evolving counters and gauges, not flow records.
- Raw counters by themselves are not enough. The more meaningful signal is in workload ratios, queue pressure, protocol mix, file-extraction intensity, and growth rates.

Main features now include operational ratios and rates such as:

- Memory
- Events queued
- Active connections
- Active files
- Active DNS requests
- Total reassembly size
- Bytes per packet
- Events per packet
- Queue-to-processed ratio
- Active-to-total connection ratio
- TCP, UDP, and ICMP share
- Files per connection
- Active files per connection
- DNS requests per UDP connection
- Active DNS pressure
- Reassembly per TCP connection
- Timer pressure
- Memory per packet
- Packet, byte, event, queue, connection, file, and DNS growth rates
- Memory delta
- Queue delta
- Connection-mix delta

The score is still time-series based, but it now operates on these derived operational features. That makes `stats.log` anomalies more meaningful in Zeek terms: queue buildup, workload-shape changes, abnormal protocol mix shifts, unusual file or DNS intensity, and abrupt processing-pressure changes.

### `capture_loss.log`

Technique: time-series deviation scoring

Why:

- Packet loss and capture gaps are time-dependent monitoring signals.

Main features include:

- `ts_delta`
- `gaps`
- `acks`
- `percent_lost`

### `packet_filter.log`

Technique: rarity scoring

Why:

- This is configuration/state metadata, not traffic flow data.

Main features include:

- `init`
- `success`
- Filter rarity
- Node rarity

### Ignored Logs

`loaded_scripts.log` is ignored completely.

Why:

- It reflects Zeek runtime configuration, not network behavior.
- In practice it tends to add noise to directory summaries and plots without helping attack detection.
- If you keep it in a Zeek directory, it is skipped before loading, so it does not affect anomalies, JSON output, plots, or the final directory score.

## Output Semantics

Default output is intentionally minimal:

- Only anomaly blocks are printed
- One block per log file that produced anomalies
- Each block is labeled with the file name
- Every printed anomaly row includes a numeric `score`
- In directory mode, a final `Directory Summary` is printed at the end

Verbose and debug output add:

- Detector name
- Used feature columns
- Feature samples in debug mode

Important: every detector produces a numeric score, but the meaning depends on the detector family:

- `IsolationForest`: higher score means the row is more isolated from the rest of that log's feature distribution
- Rarity scoring: higher score means the row contains rarer values or combinations in that log
- Time-series scoring: higher score means the row deviates more strongly from the time-series level and/or change pattern

These are ranking scores inside each log type, not calibrated probabilities, and they should not be compared numerically across different Zeek logs. A score from `conn.log` should not be compared directly to a score from `http.log`.

### Reading the directory summary

At the end of a directory run, the tool prints:

- A severity label: `LOW`, `MEDIUM`, or `HIGH`
- A directory maliciousness score on a `0-100` scale
- The normalized component values used to build the score
- The number of anomalous `uid` values shared across multiple logs
- The number of anomalous HTTP/file `fuid` overlaps
- The top contributing logs and their weighted contribution

This final block is the best place to compare one Zeek directory against another. It is more reliable than summing raw row scores because it includes normalization and cross-log correlation.

## Installation

### Source

Clone the repository:

```bash
git clone --recurse-submodules --remote-submodules https://github.com/stratosphereips/zeek_anomaly_detector
cd zeek_anomaly_detector
```

Install the dependencies:

```bash
pip install -r requirements.txt
pip install scikit-learn
```

Notes:

- `pandas` and `numpy` are required.
- `scikit-learn` is strongly recommended because `IsolationForest` is used for the richer multivariate logs.
- If `scikit-learn` is missing, the script falls back to a simpler distance-based score for those logs.

### Docker

If you use Docker, make sure the image includes `scikit-learn` in addition to the Python dependencies.

Example:

```bash
docker run --rm -it \
  -v /full/path/to/logs:/logs \
  stratosphereips/zeek_anomaly_detector:latest \
  python3 zeek-anomaly-detector.py -d /logs
```

## Usage

### Single Log

Run on one Zeek log:

```bash
python3 zeek-anomaly-detector.py -f dataset/001-zeek-scenario-malicious/conn.log
```

Show the top 20 anomalies:

```bash
python3 zeek-anomaly-detector.py -f dataset/001-zeek-scenario-malicious/conn.log -a 20
```

### Directory Of Logs

Run on a whole Zeek directory and score each log independently:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs
```

This is the recommended mode when you have multiple Zeek logs from the same capture, because the tool can build `uid` and `fuid` context across files before scoring.

### Verbose And Debug Output

Show detector names and feature columns:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs -v 1
```

Show feature samples too:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs -e 1
```

### Dump Processed Dataframes

Dump enriched per-log dataframes to CSV:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs -D output_csvs
```

For a single output file:

```bash
python3 zeek-anomaly-detector.py -f dataset/001-zeek-scenario-malicious/conn.log -D conn.csv
```

### Export JSON Summary

Write a machine-readable summary of the run:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs -J summary.json
```

The JSON export includes:

- `input_path`
- `directory_summary`
- `files`

Each file entry contains:

- Log name
- Total rows
- Number and fraction of anomalous rows
- Top anomaly score statistics
- Detector method
- Feature columns used
- Related anomalous `uid` and `fuid` values
- Top anomalous rows as JSON records

This is the recommended output if you want to compare many Zeek directories programmatically or feed the results into another analysis stage.

### Export Score Plots

Write a multi-page PDF with flow-by-flow score plots for each log plus a final summary page:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs -P scores.pdf
```

The PDF contains:

- One summary page with the final directory score and the main score components
- One combined flow-by-flow page across all log files
- One score plot per Zeek log file

If you also use `-N` or `--normal-dir`, the summary page overlays:

- Blue bars for the suspect directory
- A green line for the learned normal median of each directory-summary metric
- A red dashed line for the learned normal threshold of each metric

Each per-file plot shows:

- A blue line for the score of every flow or row, in file order
- Red markers for the rows flagged as anomalous
- An orange dashed cutoff line for the last displayed anomaly score

The combined page shows:

- All rows from all files on one shared timeline
- Within-file normalized score percentiles on the y-axis, so different log types can be compared fairly
- File boundaries and labels on the x-axis
- Red markers for anomalous rows across the whole run

This is useful when you want to see whether anomalies are isolated spikes, repeated bursts, or broad campaigns across a file.

## Practical Guidance

### Best Logs For Attack-Focused Detection

If your goal is to find malicious flows or attack activity first, focus on:

- `conn.log`
- `http.log`
- `files.log`
- `ssh.log`
- `tls.log` if available
- `weird.log`
- `notice.log`

### Inventory And Telemetry Logs

These logs are still processed, but the interpretation is different:

- `known_hosts.log`
- `known_services.log`
- `software.log`
- `packet_filter.log`
- `stats.log`
- `capture_loss.log`

They are useful for novelty, drift, and operating-context anomalies, not just for direct malicious-flow detection.

### Read The Results Per Log Type

Do not assume every anomaly means the same thing:

- In `conn.log`, an anomaly usually means a strange flow pattern.
- In `http.log`, it often means a strange application transaction or a request tied to unusual content.
- In `files.log`, it often means suspicious content transfer behavior.
- In `weird.log` or `notice.log`, it usually means high-priority events or rare protocol/parser observations.
- In inventory logs, it usually means novelty or environmental drift.

## Current Limits

- Scores are per-log rankings, not globally calibrated risk scores.
- This is unsupervised detection. It surfaces unusual behavior, not guaranteed malicious behavior.
- Inventory logs can produce valid novelty detections that are operationally interesting but not necessarily attacks.
- The current implementation relies on the fields present in each Zeek log. Sparse logs naturally produce simpler detectors.

## Contribute

Create an issue or PR and we will process it.

## Authors

This project was created by Sebastian Garcia and Veronica Valeros at the Stratosphere Research Laboratory, AIC, FEE, Czech Technical University in Prague.
