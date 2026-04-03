# zeek_anomaly_detector
[![Docker Image CI](https://github.com/stratosphereips/zeek_anomaly_detector/actions/workflows/docker-image.yml/badge.svg)](https://github.com/stratosphereips/zeek_anomaly_detector/actions/workflows/docker-image.yml)
[![Python Checks](https://github.com/stratosphereips/zeek_anomaly_detector/actions/workflows/python-checks.yml/badge.svg)](https://github.com/stratosphereips/zeek_anomaly_detector/actions/workflows/python-checks.yml)
![GitHub last commit (branch)](https://img.shields.io/github/last-commit/stratosphereips/zeek_anomaly_detector/main?color=green)
![Docker Pulls](https://img.shields.io/docker/pulls/stratosphereips/zeek_anomaly_detector?color=green)

An anomaly detector for Zeek logs. It supports both classic Zeek TSV logs and line-delimited Zeek JSON logs and can process either a single log file or a directory of Zeek logs.

## What Changed

The tool is no longer limited to one TSV `conn.log` file.

It now:

- Auto-detects Zeek TSV and Zeek JSON
- Reads Zeek `#fields` headers when present
- Accepts `-f` for one file or `-d` for a directory of `.log` files
- Keeps default output quiet so normal runs only print anomalies
- Falls back to a stable score when PCA is not appropriate for a log's numeric shape

## Usage

Run one file:

```bash
python3 zeek-anomaly-detector.py -f dataset/001-zeek-scenario-malicious/conn.log
```

Run a directory of Zeek logs:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs
```

Show more anomalies:

```bash
python3 zeek-anomaly-detector.py -f dataset/001-zeek-scenario-malicious/conn.log -a 20
```

Verbose mode:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs -v 1
```

Dump the processed dataframe(s) to CSV:

```bash
python3 zeek-anomaly-detector.py -d /path/to/zeek/logs -D output_csvs
```

## Output

By default, the tool prints only anomaly rows.

Each anomaly table includes:

- The original Zeek fields
- A numeric `score`

Important: scores are ranking scores inside a file. They are useful for sorting anomalies in that file, but they are not calibrated probabilities.

## Installation

Clone the repository:

```bash
git clone --recurse-submodules --remote-submodules https://github.com/stratosphereips/zeek_anomaly_detector
cd zeek_anomaly_detector
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Current Scope

This first step generalizes input handling and CLI behavior. It still uses a generic numeric anomaly detector per file. More specialized log-type detectors and cross-log correlation are added in later changes.

## Contribute

Create an issue or PR and we will process it.

## Authors

This project was created by Sebastian Garcia and Veronica Valeros at the Stratosphere Research Laboratory, AIC, FEE, Czech Technical University in Prague.
