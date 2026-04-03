#!/usr/bin/env python3
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Authors:
# - Sebastian Garcia, eldraco@gmail.com,
#   sebastian.garcia@agents.fel.cvut.cz
# - Veronica Valeros, vero.valeros@gmail.com
"""
Zeek Anomaly Detector by the Stratosphere Laboratory
"""

import argparse
from pathlib import Path

import pandas as pd
from pyod.models.pca import PCA


DEFAULT_CONN_COLUMNS = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p',
    'id.resp_h', 'id.resp_p', 'proto', 'service',
    'duration', 'orig_bytes', 'resp_bytes',
    'conn_state', 'local_orig', 'local_resp',
    'missed_bytes', 'history', 'orig_pkts',
    'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
    'tunnel_parents', 'ip_proto'
]


def detect_log_format(file):
    """Return the log format based on the first non-empty line."""
    with open(file, encoding='utf-8') as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith('{') or stripped.startswith('['):
                return 'json'
            return 'tsv'
    raise ValueError(f'Input file {file} is empty.')



def get_tsv_columns(file):
    """Read Zeek #fields header when available."""
    with open(file, encoding='utf-8') as handle:
        for line in handle:
            if line.startswith('#fields\t'):
                return line.strip().split('\t')[1:]
    return DEFAULT_CONN_COLUMNS



def load_conn_log(file):
    """Load Zeek conn.log from either TSV or line-delimited JSON."""
    log_format = detect_log_format(file)

    if log_format == 'json':
        bro_df = pd.read_json(file, lines=True)
    else:
        bro_df = pd.read_csv(
            file,
            sep='\t',
            comment='#',
            names=get_tsv_columns(file)
        )

    for col in DEFAULT_CONN_COLUMNS:
        if col not in bro_df.columns:
            bro_df[col] = pd.NA

    return bro_df



def get_numeric_feature_columns(bro_df):
    """Infer numeric feature columns for the current Zeek log schema."""
    excluded = {'ts', 'uid', 'fuid', 'id.orig_h', 'id.resp_h'}
    numeric_cols = []

    for col in bro_df.columns:
        if col in excluded:
            continue

        cleaned = bro_df[col].replace(['-', '(empty)'], 0)
        numeric_series = pd.to_numeric(cleaned, errors='coerce')
        if numeric_series.notna().sum() == 0:
            continue

        bro_df[col] = numeric_series.fillna(0)
        numeric_cols.append(col)

    return numeric_cols



def score_with_fallback(x_train, amountanom):
    """Use PCA when possible, otherwise a stable fallback."""
    varying_cols = [
        col for col in x_train.columns
        if x_train[col].nunique(dropna=False) > 1 and x_train[col].std(ddof=0) > 0
    ]

    x_used = x_train[varying_cols]
    if x_used.empty:
        return pd.Series(dtype=float), pd.Series(dtype=int), [], 'none'

    if len(x_used.columns) >= 2 and len(x_used) >= 3:
        clf = PCA()
        x_values = x_used.values
        clf.fit(x_values)
        scores = pd.Series(clf.decision_function(x_values), index=x_used.index)
        preds = pd.Series(clf.predict(x_values), index=x_used.index)
        return scores, preds, varying_cols, 'pca'

    standardized = (x_used - x_used.mean()) / x_used.std(ddof=0)
    standardized = standardized.replace([float('inf'), float('-inf')], 0).fillna(0)
    scores = standardized.abs().sum(axis=1)
    top_n = min(amountanom, len(scores))
    pred_index = scores.nlargest(top_n).index
    preds = pd.Series(0, index=x_used.index, dtype=int)
    preds.loc[pred_index] = 1
    return scores, preds, varying_cols, 'fallback'



def iter_log_files(path):
    """Yield one or more Zeek log files from a file or directory path."""
    input_path = Path(path)

    if input_path.is_file():
        return [input_path]

    if input_path.is_dir():
        return sorted(
            child for child in input_path.iterdir()
            if child.is_file() and child.suffix == '.log'
        )

    raise FileNotFoundError(f'Input path not found: {path}')



def detect(file, amountanom, dumptocsv, verbosity=0, debug=0):
    """Apply a simple anomaly detector to one Zeek log."""
    bro_df = load_conn_log(file)
    bro_df['label'] = 'normal'
    numeric_cols = get_numeric_feature_columns(bro_df)

    if not numeric_cols:
        if verbosity or debug:
            print(f"Skipping {file}: no numeric columns available for analysis.")
        return False

    for col in numeric_cols:
        bro_df[col] = pd.to_numeric(bro_df[col], errors='coerce').fillna(0)

    numeric_only = bro_df[numeric_cols]
    all_zero_rows = (numeric_only == 0).all(axis=1)
    removed = all_zero_rows.sum()
    bro_df = bro_df[~all_zero_rows]

    if bro_df.empty:
        if verbosity or debug:
            print(f"No data left after cleaning for {file}.")
        return False

    if dumptocsv and dumptocsv != 'None':
        output_path = Path(dumptocsv)
        if output_path.suffix.lower() == '.csv':
            target = output_path
        else:
            output_path.mkdir(parents=True, exist_ok=True)
            target = output_path / f'{Path(file).stem}.csv'
        bro_df.to_csv(target, index=False)

    x_train = bro_df[numeric_cols]
    scores_series, pred_series, used_cols, scoring_method = score_with_fallback(
        x_train,
        amountanom
    )

    if verbosity or debug:
        print(f'Detector for {Path(file).name}: {scoring_method}')
        print('Used numeric columns:', used_cols)
        if removed > 0:
            print(f'Removed {removed} all-zero rows.')

    if len(x_train) < 2 or not used_cols or scoring_method == 'none':
        if verbosity or debug:
            print(f"Skipping {file}: insufficient varying numeric data.")
        return False

    x_test = x_train.copy()
    x_test['score'] = scores_series
    x_test['pred'] = pred_series
    bro_df['score'] = x_test['score']

    anomalous = x_test[x_test.pred == 1].sort_values(by='score', ascending=False).iloc[:amountanom]
    if anomalous.empty:
        return False

    df_to_print = bro_df.loc[anomalous.index]
    print(f'\nTop anomalies in {Path(file).name}')

    drop_cols = ['conn_state', 'history', 'local_orig',
                 'local_resp', 'missed_bytes', 'ts',
                 'tunnel_parents', 'uid', 'label']
    keep_cols = [col for col in df_to_print.columns if col not in drop_cols]
    if 'score' in keep_cols:
        keep_cols = [col for col in keep_cols if col != 'score'] + ['score']
    print(df_to_print[keep_cols])
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose',
                        help='Amount of verbosity.',
                        action='store',
                        required=False,
                        type=int)
    parser.add_argument('-e', '--debug',
                        help='Amount of debugging.',
                        action='store',
                        required=False,
                        type=int)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('-f', '--file',
                              help='Zeek log path.',
                              required=False)
    source_group.add_argument('-d', '--directory',
                              help='Directory with Zeek .log files to analyze individually.',
                              required=False)
    parser.add_argument('-a', '--amountanom',
                        help='Amount of anomalies to show.',
                        required=False,
                        default=10,
                        type=int)
    parser.add_argument('-D', '--dumptocsv',
                        help='Dump the processed DataFrame(s) to CSV.',
                        required=False)
    args = parser.parse_args()

    if args.verbose or args.debug:
        print('Zeek Anomaly Detector: a simple anomaly detector for Zeek logs.')
        print('Author: Sebastian Garcia (eldraco@gmail.com)')
        print('        Veronica Valeros (vero.valeros@gmail.com)')

    input_path = args.file or args.directory
    found_any_anomalies = False
    for log_file in iter_log_files(input_path):
        found_any_anomalies = detect(
            log_file,
            args.amountanom,
            args.dumptocsv,
            args.verbose or 0,
            args.debug or 0
        ) or found_any_anomalies

    if (args.verbose or args.debug) and not found_any_anomalies:
        print('No anomalies detected.')
