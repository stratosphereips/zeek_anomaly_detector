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
import json
import os
from pathlib import Path

import numpy as np
import pandas as pd

os.environ.setdefault('MPLCONFIGDIR', '/tmp/zeek-anomaly-detector-mpl')
os.makedirs(os.environ['MPLCONFIGDIR'], exist_ok=True)

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_pdf import PdfPages
except ImportError:  # pragma: no cover - optional dependency at runtime
    matplotlib = None
    plt = None
    PdfPages = None

try:
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover - optional dependency at runtime
    IsolationForest = None


DEFAULT_CONN_COLUMNS = [
    'ts', 'uid', 'id.orig_h', 'id.orig_p',
    'id.resp_h', 'id.resp_p', 'proto', 'service',
    'duration', 'orig_bytes', 'resp_bytes',
    'conn_state', 'local_orig', 'local_resp',
    'missed_bytes', 'history', 'orig_pkts',
    'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
    'tunnel_parents', 'ip_proto'
]

COMMON_DROP_COLUMNS = {
    'ts', 'uid', 'fuid', 'label'
}

LOG_WEIGHTS = {
    'conn': 1.00,
    'http': 0.95,
    'files': 0.95,
    'ssh': 0.75,
    'tls': 0.90,
    'ssl': 0.90,
    'dns': 0.75,
    'weird': 0.90,
    'notice': 1.00,
    'arp': 0.50,
    'stats': 0.30,
    'capture_loss': 0.30,
    'known_services': 0.35,
    'known_hosts': 0.25,
    'software': 0.30,
    'packet_filter': 0.10,
    'loaded_scripts': 0.10,
}

ANSI = {
    'red': '\033[91m',
    'yellow': '\033[93m',
    'green': '\033[92m',
    'cyan': '\033[96m',
    'bold': '\033[1m',
    'reset': '\033[0m',
}


class EmptyLogError(ValueError):
    """Raised when a Zeek log has no content rows to analyze."""


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
    raise EmptyLogError(f'Input file {file} is empty.')


def get_tsv_columns(file):
    """Read Zeek #fields header when available."""
    with open(file, encoding='utf-8') as handle:
        for line in handle:
            if line.startswith('#fields\t'):
                return line.strip().split('\t')[1:]
    return DEFAULT_CONN_COLUMNS


def load_zeek_log(file):
    """Load a Zeek log from either TSV or line-delimited JSON."""
    log_format = detect_log_format(file)

    if log_format == 'json':
        return pd.read_json(file, lines=True)

    return pd.read_csv(
        file,
        sep='\t',
        comment='#',
        names=get_tsv_columns(file)
    )


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


def normalize_scalar(value):
    """Normalize values for frequency and rarity calculations."""
    if isinstance(value, list):
        return '|'.join(sorted(str(item) for item in value))
    if pd.isna(value):
        return ''
    return str(value)


def style(text, color=None, bold=False):
    if not os.isatty(1):
        return text
    prefix = ''
    if bold:
        prefix += ANSI['bold']
    if color:
        prefix += ANSI[color]
    return f'{prefix}{text}{ANSI["reset"]}'


def to_serializable(value):
    if isinstance(value, dict):
        return {str(key): to_serializable(item) for key, item in value.items()}
    if isinstance(value, set):
        return sorted(to_serializable(item) for item in value)
    if isinstance(value, (np.floating, float)):
        return None if pd.isna(value) else float(value)
    if isinstance(value, (np.integer, int)):
        return int(value)
    if isinstance(value, (np.bool_, bool)):
        return bool(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [to_serializable(item) for item in value]
    if pd.isna(value):
        return None
    return value


def text_series(df, column, default=''):
    if column not in df.columns:
        return pd.Series([default] * len(df), index=df.index, dtype='object')
    return df[column].apply(normalize_scalar)


def numeric_series(df, column, default=0.0):
    if column not in df.columns:
        return pd.Series(default, index=df.index, dtype=float)
    return pd.to_numeric(df[column].replace(['-', '(empty)'], 0), errors='coerce').fillna(default)


def bool_series(df, column):
    if column not in df.columns:
        return pd.Series(0.0, index=df.index, dtype=float)
    return df[column].fillna(False).astype(float)


def list_length_series(df, column):
    if column not in df.columns:
        return pd.Series(0.0, index=df.index, dtype=float)

    def _length(value):
        if isinstance(value, list):
            return float(len(value))
        if pd.isna(value) or value == '':
            return 0.0
        return 1.0

    return df[column].apply(_length).astype(float)


def string_length_series(df, column):
    return text_series(df, column).str.len().astype(float)


def shannon_entropy(value):
    text = normalize_scalar(value)
    if not text:
        return 0.0
    counts = pd.Series(list(text)).value_counts(normalize=True)
    return float(-(counts * np.log2(counts)).sum())


def dns_query_base_series(df):
    query = text_series(df, 'query').str.lower()
    return query.str.rstrip('.')


def rarity_series(values):
    normalized = values.apply(normalize_scalar)
    frequencies = normalized.value_counts(dropna=False, normalize=True)
    return normalized.map(lambda value: -np.log(frequencies.get(value, 1e-9))).astype(float)


def safe_divide(numerator, denominator):
    numerator = numerator.astype(float)
    denominator = denominator.astype(float)
    return numerator.divide(denominator.replace(0, np.nan)).replace([np.inf, -np.inf], np.nan).fillna(0.0)


def zscore_series(values):
    values = values.astype(float)
    std = values.std(ddof=0)
    if pd.isna(std) or std == 0:
        return pd.Series(0.0, index=values.index, dtype=float)
    return ((values - values.mean()) / std).abs().fillna(0.0)


def add_uid_context(features, df, context, columns):
    if 'uid' not in df.columns:
        return

    uid_metrics = context.get('uid_metrics', pd.DataFrame())
    if uid_metrics.empty:
        return

    uid_series = text_series(df, 'uid')
    for column in columns:
        if column in uid_metrics.columns:
            features[column] = uid_series.map(uid_metrics[column]).fillna(0.0).astype(float)


def build_fuid_lookup(frame):
    if frame.empty or 'fuid' not in frame.columns:
        return {}

    lookup = {}
    bytes_series = numeric_series(frame, 'total_bytes', 0.0)
    if not bytes_series.any():
        bytes_series = numeric_series(frame, 'seen_bytes', 0.0)

    mime_rarity = rarity_series(text_series(frame, 'mime_type'))
    source_rarity = rarity_series(text_series(frame, 'source'))

    for row_index, fuid in text_series(frame, 'fuid').items():
        if not fuid:
            continue
        lookup[fuid] = {
            'file_total_bytes': float(bytes_series.loc[row_index]),
            'file_mime_rarity': float(mime_rarity.loc[row_index]),
            'file_source_rarity': float(source_rarity.loc[row_index]),
        }

    return lookup


def sum_linked_fuid_metric(series, lookup, metric):
    values = []
    for item in series:
        total = 0.0
        if isinstance(item, list):
            for fuid in item:
                total += lookup.get(str(fuid), {}).get(metric, 0.0)
        values.append(total)
    return pd.Series(values, index=series.index, dtype=float)


def count_linked_fuids(series, lookup):
    values = []
    for item in series:
        count = 0.0
        if isinstance(item, list):
            count = sum(1 for fuid in item if str(fuid) in lookup)
        values.append(float(count))
    return pd.Series(values, index=series.index, dtype=float)


def build_context(log_frames):
    context = {}

    uid_parts = []
    for log_name, frame in log_frames.items():
        if 'uid' not in frame.columns or frame.empty:
            continue
        uid_frame = pd.DataFrame({
            'uid': text_series(frame, 'uid'),
            f'{log_name}_count': 1.0,
        })
        uid_parts.append(uid_frame.groupby('uid', dropna=False).sum())

    uid_metrics = pd.concat(uid_parts, axis=1).fillna(0.0) if uid_parts else pd.DataFrame()
    if not uid_metrics.empty:
        count_cols = [col for col in uid_metrics.columns if col.endswith('_count')]
        uid_metrics['uid_log_types'] = (uid_metrics[count_cols] > 0).sum(axis=1).astype(float)

    conn = log_frames.get('conn', pd.DataFrame())
    if not conn.empty and 'uid' in conn.columns:
        conn_metrics = pd.DataFrame(index=text_series(conn, 'uid'))
        conn_metrics['uid_conn_bytes'] = (
            numeric_series(conn, 'orig_bytes') + numeric_series(conn, 'resp_bytes')
        ).values
        conn_metrics['uid_conn_pkts'] = (
            numeric_series(conn, 'orig_pkts') + numeric_series(conn, 'resp_pkts')
        ).values
        conn_metrics['uid_conn_duration'] = numeric_series(conn, 'duration').values
        conn_metrics['uid_resp_port'] = numeric_series(conn, 'id.resp_p').values
        conn_metrics['uid_conn_state_rarity'] = rarity_series(text_series(conn, 'conn_state')).values
        conn_metrics = conn_metrics.groupby(level=0).max()
        uid_metrics = uid_metrics.join(conn_metrics, how='outer') if not uid_metrics.empty else conn_metrics

    src_conn_metrics = pd.DataFrame()
    if not conn.empty and 'id.orig_h' in conn.columns:
        conn_src = pd.DataFrame({
            'src': text_series(conn, 'id.orig_h'),
            'dst_host': text_series(conn, 'id.resp_h'),
            'dst_port': text_series(conn, 'id.resp_p'),
            'conn_state': text_series(conn, 'conn_state'),
            'service': text_series(conn, 'service'),
            'duration': numeric_series(conn, 'duration'),
            'total_bytes': numeric_series(conn, 'orig_bytes') + numeric_series(conn, 'resp_bytes'),
        })
        conn_src['is_failed_scan_state'] = conn_src['conn_state'].isin({
            'S0', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'RSTRH', 'SH', 'SHR'
        }).astype(float)
        conn_src['is_short'] = (conn_src['duration'] <= 0.05).astype(float)
        conn_src['is_zero_payload'] = (conn_src['total_bytes'] <= 0).astype(float)
        conn_src['is_service_missing'] = conn_src['service'].isin({'', '-', '(empty)'}).astype(float)

        per_src = conn_src.groupby('src').agg(
            src_flow_count=('src', 'size'),
            src_unique_resp_hosts=('dst_host', 'nunique'),
            src_unique_resp_ports=('dst_port', 'nunique'),
            src_failed_state_fraction=('is_failed_scan_state', 'mean'),
            src_short_fraction=('is_short', 'mean'),
            src_zero_payload_fraction=('is_zero_payload', 'mean'),
            src_missing_service_fraction=('is_service_missing', 'mean'),
        )

        per_src_dst = conn_src.groupby(['src', 'dst_host']).agg(
            dst_port_sweep=('dst_port', 'nunique'),
            dst_failed_fraction=('is_failed_scan_state', 'mean'),
        ).reset_index()
        sweep_summary = per_src_dst.groupby('src').agg(
            src_max_dst_port_sweep=('dst_port_sweep', 'max'),
            src_mean_dst_port_sweep=('dst_port_sweep', 'mean'),
            src_max_dst_failed_fraction=('dst_failed_fraction', 'max'),
        )
        src_conn_metrics = per_src.join(sweep_summary, how='left').fillna(0.0)

    context['src_conn_metrics'] = src_conn_metrics

    weird = log_frames.get('weird', pd.DataFrame())
    if not weird.empty and 'uid' in weird.columns:
        weird_metrics = pd.DataFrame({
            'uid': text_series(weird, 'uid'),
            'uid_weird_notice_count': bool_series(weird, 'notice'),
            'uid_weird_name_rarity': rarity_series(text_series(weird, 'name')),
        })
        weird_metrics['uid_weird_count'] = 1.0
        weird_metrics = weird_metrics.groupby('uid').agg({
            'uid_weird_count': 'sum',
            'uid_weird_notice_count': 'sum',
            'uid_weird_name_rarity': 'sum',
        })
        uid_metrics = uid_metrics.join(weird_metrics, how='outer') if not uid_metrics.empty else weird_metrics

    http = log_frames.get('http', pd.DataFrame())
    if not http.empty and 'uid' in http.columns:
        http_metrics = pd.DataFrame({
            'uid': text_series(http, 'uid'),
            'uid_http_count': 1.0,
            'uid_http_body_sum': (
                numeric_series(http, 'request_body_len') + numeric_series(http, 'response_body_len')
            ),
            'uid_http_status_rarity': rarity_series(text_series(http, 'status_code')),
        })
        http_metrics = http_metrics.groupby('uid').agg({
            'uid_http_count': 'sum',
            'uid_http_body_sum': 'sum',
            'uid_http_status_rarity': 'sum',
        })
        uid_metrics = uid_metrics.join(http_metrics, how='outer') if not uid_metrics.empty else http_metrics

    files = log_frames.get('files', pd.DataFrame())
    if not files.empty and 'uid' in files.columns:
        file_metrics = pd.DataFrame({
            'uid': text_series(files, 'uid'),
            'uid_files_count': 1.0,
            'uid_file_total_bytes': numeric_series(files, 'total_bytes'),
            'uid_file_mime_rarity': rarity_series(text_series(files, 'mime_type')),
        })
        file_metrics = file_metrics.groupby('uid').agg({
            'uid_files_count': 'sum',
            'uid_file_total_bytes': 'sum',
            'uid_file_mime_rarity': 'sum',
        })
        uid_metrics = uid_metrics.join(file_metrics, how='outer') if not uid_metrics.empty else file_metrics

    ssh = log_frames.get('ssh', pd.DataFrame())
    if not ssh.empty and 'uid' in ssh.columns:
        ssh_metrics = pd.DataFrame({
            'uid': text_series(ssh, 'uid'),
            'uid_ssh_count': 1.0,
            'uid_ssh_auth_attempts': numeric_series(ssh, 'auth_attempts'),
        })
        ssh_metrics = ssh_metrics.groupby('uid').agg({
            'uid_ssh_count': 'sum',
            'uid_ssh_auth_attempts': 'sum',
        })
        uid_metrics = uid_metrics.join(ssh_metrics, how='outer') if not uid_metrics.empty else ssh_metrics

    context['uid_metrics'] = uid_metrics.fillna(0.0) if not uid_metrics.empty else pd.DataFrame()
    context['fuid_lookup'] = build_fuid_lookup(files)
    return context


def build_conn_features(df, context):
    features = pd.DataFrame(index=df.index)
    orig_bytes = numeric_series(df, 'orig_bytes')
    resp_bytes = numeric_series(df, 'resp_bytes')
    orig_pkts = numeric_series(df, 'orig_pkts')
    resp_pkts = numeric_series(df, 'resp_pkts')
    duration = numeric_series(df, 'duration')

    features['id.resp_p'] = numeric_series(df, 'id.resp_p')
    features['duration'] = duration
    features['total_bytes'] = orig_bytes + resp_bytes
    features['total_pkts'] = orig_pkts + resp_pkts
    features['orig_resp_bytes_ratio'] = safe_divide(orig_bytes + 1, resp_bytes + 1)
    features['orig_resp_pkts_ratio'] = safe_divide(orig_pkts + 1, resp_pkts + 1)
    features['bytes_per_second'] = safe_divide(features['total_bytes'], duration + 1e-6)
    features['bytes_per_packet'] = safe_divide(features['total_bytes'], features['total_pkts'] + 1)
    features['resp_port_rarity'] = rarity_series(text_series(df, 'id.resp_p'))
    features['service_rarity'] = rarity_series(text_series(df, 'service'))
    features['state_rarity'] = rarity_series(text_series(df, 'conn_state'))
    features['history_rarity'] = rarity_series(text_series(df, 'history'))
    features['dst_host_popularity'] = zscore_series(text_series(df, 'id.resp_h').map(
        text_series(df, 'id.resp_h').value_counts()
    ).fillna(0))
    features['is_failed_scan_state'] = text_series(df, 'conn_state').isin({
        'S0', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'RSTRH', 'SH', 'SHR'
    }).astype(float)
    features['is_scan_history'] = text_series(df, 'history').isin({
        'S', 'Sr', 'Ar', 'A', 'R', 'Sh', 'ShR'
    }).astype(float)
    features['is_short_conn'] = (duration <= 0.05).astype(float)
    features['is_zero_payload'] = ((orig_bytes + resp_bytes) <= 0).astype(float)
    features['is_service_missing'] = text_series(df, 'service').isin({'', '-', '(empty)'}).astype(float)
    features['is_established_session'] = text_series(df, 'conn_state').isin({'SF', 'S1'}).astype(float)

    src_conn_metrics = context.get('src_conn_metrics', pd.DataFrame())
    if not src_conn_metrics.empty and 'id.orig_h' in df.columns:
        src_series = text_series(df, 'id.orig_h')
        for column in [
            'src_flow_count', 'src_unique_resp_hosts', 'src_unique_resp_ports',
            'src_failed_state_fraction', 'src_short_fraction',
            'src_zero_payload_fraction', 'src_missing_service_fraction',
            'src_max_dst_port_sweep', 'src_mean_dst_port_sweep',
            'src_max_dst_failed_fraction',
        ]:
            if column in src_conn_metrics.columns:
                features[column] = src_series.map(src_conn_metrics[column]).fillna(0.0).astype(float)

    add_uid_context(features, df, context, [
        'uid_log_types', 'uid_http_count', 'uid_files_count',
        'uid_ssh_count', 'uid_weird_count', 'uid_file_total_bytes',
        'uid_weird_name_rarity'
    ])
    return features, 'conn_hybrid'


def build_http_features(df, context):
    features = pd.DataFrame(index=df.index)
    fuid_lookup = context.get('fuid_lookup', {})
    request_len = numeric_series(df, 'request_body_len')
    response_len = numeric_series(df, 'response_body_len')

    features['id.resp_p'] = numeric_series(df, 'id.resp_p')
    features['trans_depth'] = numeric_series(df, 'trans_depth')
    features['request_body_len'] = request_len
    features['response_body_len'] = response_len
    features['status_code'] = numeric_series(df, 'status_code')
    features['uri_len'] = string_length_series(df, 'uri')
    features['host_len'] = string_length_series(df, 'host')
    features['user_agent_len'] = string_length_series(df, 'user_agent')
    features['method_rarity'] = rarity_series(text_series(df, 'method'))
    features['status_rarity'] = rarity_series(text_series(df, 'status_code'))
    features['host_rarity'] = rarity_series(text_series(df, 'host'))
    features['uri_rarity'] = rarity_series(text_series(df, 'uri'))
    features['user_agent_rarity'] = rarity_series(text_series(df, 'user_agent'))
    features['resp_fuid_count'] = list_length_series(df, 'resp_fuids')
    features['orig_fuid_count'] = list_length_series(df, 'orig_fuids')
    features['linked_file_count'] = count_linked_fuids(df.get('resp_fuids', pd.Series(index=df.index, dtype='object')), fuid_lookup)
    features['linked_file_bytes'] = sum_linked_fuid_metric(
        df.get('resp_fuids', pd.Series(index=df.index, dtype='object')),
        fuid_lookup,
        'file_total_bytes'
    )
    features['linked_file_mime_rarity'] = sum_linked_fuid_metric(
        df.get('resp_fuids', pd.Series(index=df.index, dtype='object')),
        fuid_lookup,
        'file_mime_rarity'
    )
    add_uid_context(features, df, context, [
        'uid_conn_bytes', 'uid_conn_duration', 'uid_weird_count',
        'uid_weird_name_rarity', 'uid_files_count', 'uid_file_total_bytes'
    ])
    return features, 'isolation_forest'


def build_files_features(df, context):
    features = pd.DataFrame(index=df.index)
    seen_bytes = numeric_series(df, 'seen_bytes')
    total_bytes = numeric_series(df, 'total_bytes')
    features['id.resp_p'] = numeric_series(df, 'id.resp_p')
    features['depth'] = numeric_series(df, 'depth')
    features['duration'] = numeric_series(df, 'duration')
    features['seen_bytes'] = seen_bytes
    features['total_bytes'] = total_bytes
    features['missing_bytes'] = numeric_series(df, 'missing_bytes')
    features['overflow_bytes'] = numeric_series(df, 'overflow_bytes')
    features['local_orig'] = bool_series(df, 'local_orig')
    features['is_orig'] = bool_series(df, 'is_orig')
    features['timedout'] = bool_series(df, 'timedout')
    features['mime_rarity'] = rarity_series(text_series(df, 'mime_type'))
    features['source_rarity'] = rarity_series(text_series(df, 'source'))
    features['analyzer_count'] = list_length_series(df, 'analyzers')
    features['bytes_gap'] = (total_bytes - seen_bytes).abs()
    add_uid_context(features, df, context, [
        'uid_http_count', 'uid_http_body_sum', 'uid_http_status_rarity',
        'uid_weird_count', 'uid_conn_bytes'
    ])
    return features, 'isolation_forest'


def build_ssh_features(df, context):
    features = pd.DataFrame(index=df.index)
    features['id.resp_p'] = numeric_series(df, 'id.resp_p')
    features['auth_attempts'] = numeric_series(df, 'auth_attempts')
    features['client_len'] = string_length_series(df, 'client')
    features['server_len'] = string_length_series(df, 'server')
    features['client_rarity'] = rarity_series(text_series(df, 'client'))
    features['server_rarity'] = rarity_series(text_series(df, 'server'))
    add_uid_context(features, df, context, [
        'uid_conn_bytes', 'uid_conn_duration', 'uid_weird_count',
        'uid_weird_name_rarity'
    ])
    return features, 'isolation_forest'


def build_tls_features(df, context):
    features = pd.DataFrame(index=df.index)
    features['id.resp_p'] = numeric_series(df, 'id.resp_p')
    features['version_num'] = numeric_series(df, 'version')
    features['cipher_count'] = list_length_series(df, 'cipher')
    features['server_name_len'] = string_length_series(df, 'server_name')
    features['ja3_rarity'] = rarity_series(text_series(df, 'ja3'))
    features['ja3s_rarity'] = rarity_series(text_series(df, 'ja3s'))
    features['sni_rarity'] = rarity_series(text_series(df, 'server_name'))
    add_uid_context(features, df, context, [
        'uid_conn_bytes', 'uid_conn_duration', 'uid_weird_count'
    ])
    return features, 'isolation_forest'


def build_dns_features(df, context):
    features = pd.DataFrame(index=df.index)
    query = dns_query_base_series(df)
    labels = query.str.split('.')
    first_label = labels.apply(lambda parts: parts[0] if parts and parts[0] else '')
    tld = labels.apply(lambda parts: parts[-1] if parts and parts[-1] else '')

    alpha_count = first_label.str.count(r'[a-z]')
    digit_count = first_label.str.count(r'[0-9]')
    vowels = first_label.str.count(r'[aeiou]')
    consonants = alpha_count - vowels
    label_len = first_label.str.len().astype(float)
    full_len = query.str.len().astype(float)
    unique_char_ratio = safe_divide(
        first_label.apply(lambda value: len(set(value))).astype(float),
        label_len.replace(0, np.nan)
    )
    vowel_ratio = safe_divide(vowels.astype(float), alpha_count.replace(0, np.nan))
    consonant_ratio = safe_divide(consonants.astype(float), alpha_count.replace(0, np.nan))
    digit_ratio = safe_divide(digit_count.astype(float), label_len.replace(0, np.nan))
    entropy = first_label.apply(shannon_entropy).astype(float)
    answer_count = list_length_series(df, 'answers')
    ttl_count = list_length_series(df, 'TTLs')
    resp_port = numeric_series(df, 'id.resp_p')
    qtype_name = text_series(df, 'qtype_name').str.upper()
    rcode_name = text_series(df, 'rcode_name').str.upper()

    dga_like = (
        (label_len >= 8) &
        (entropy >= 2.8) &
        (unique_char_ratio >= 0.55) &
        ((vowel_ratio <= 0.45) | (digit_ratio >= 0.10))
    ).astype(float)

    entropy_bucket = (entropy * 2).round().astype(int).astype(str)
    length_bucket = (label_len // 4).astype(int).astype(str)
    dga_pattern = (
        text_series(df, 'id.orig_h') + '|' + tld + '|' + length_bucket + '|' +
        entropy_bucket + '|' + dga_like.astype(int).astype(str)
    )
    dga_pattern_counts = dga_pattern.map(dga_pattern.value_counts()).astype(float)
    src_dga_like_count = text_series(df, 'id.orig_h').map(
        pd.Series(dga_like.values, index=df.index).groupby(text_series(df, 'id.orig_h')).sum()
    ).fillna(0.0)
    is_local_tld = tld.eq('local').astype(float)
    is_reverse_lookup = query.str.endswith('.in-addr.arpa') | query.str.endswith('.ip6.arpa')
    is_reverse_lookup = is_reverse_lookup.astype(float)
    is_service_discovery = (
        query.str.startswith('_') |
        query.str.contains('._tcp.local', regex=False) |
        query.str.contains('._udp.local', regex=False)
    ).astype(float)
    is_mdns = ((resp_port == 5353) | is_local_tld.astype(bool)).astype(float)
    no_error_no_answer = ((rcode_name == 'NOERROR') & (answer_count == 0)).astype(float)

    features['id.resp_p'] = resp_port
    features['query_len'] = full_len
    features['label_count'] = labels.apply(len).astype(float)
    features['first_label_len'] = label_len
    features['query_entropy'] = entropy
    features['unique_char_ratio'] = unique_char_ratio
    features['vowel_ratio'] = vowel_ratio
    features['consonant_ratio'] = consonant_ratio
    features['digit_ratio'] = digit_ratio
    features['query_rarity'] = rarity_series(query)
    features['tld_rarity'] = rarity_series(tld)
    features['qtype_rarity'] = rarity_series(qtype_name)
    features['rcode_rarity'] = rarity_series(rcode_name)
    features['answer_count'] = answer_count
    features['ttl_count'] = ttl_count
    features['no_answer'] = (answer_count == 0).astype(float)
    features['rejected'] = bool_series(df, 'rejected')
    features['dga_like'] = dga_like
    features['dga_pattern_count'] = dga_pattern_counts
    features['src_dga_like_count'] = src_dga_like_count
    features['is_local_tld'] = is_local_tld
    features['is_reverse_lookup'] = is_reverse_lookup
    features['is_service_discovery'] = is_service_discovery
    features['is_mdns'] = is_mdns
    features['noerror_noanswer'] = no_error_no_answer
    add_uid_context(features, df, context, [
        'uid_conn_bytes', 'uid_conn_duration', 'uid_weird_count',
        'uid_weird_name_rarity'
    ])
    return features, 'dns_hybrid'


def build_weird_features(df, context):
    features = pd.DataFrame(index=df.index)
    features['id.resp_p'] = numeric_series(df, 'id.resp_p')
    features['notice'] = bool_series(df, 'notice')
    features['name_rarity'] = rarity_series(text_series(df, 'name'))
    features['source_rarity'] = rarity_series(text_series(df, 'source'))
    features['peer_rarity'] = rarity_series(text_series(df, 'peer'))
    add_uid_context(features, df, context, [
        'uid_conn_bytes', 'uid_conn_duration', 'uid_http_count',
        'uid_files_count', 'uid_ssh_count'
    ])
    return features, 'rarity'


def build_notice_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    features['n'] = numeric_series(df, 'n')
    features['suppress_for'] = numeric_series(df, 'suppress_for')
    features['note_rarity'] = rarity_series(text_series(df, 'note'))
    features['src_rarity'] = rarity_series(text_series(df, 'src'))
    features['msg_len'] = string_length_series(df, 'msg')
    return features, 'rarity'


def build_known_services_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    features['port_num'] = numeric_series(df, 'port_num')
    features['service_rarity'] = rarity_series(text_series(df, 'service'))
    features['host_rarity'] = rarity_series(text_series(df, 'host'))
    features['proto_rarity'] = rarity_series(text_series(df, 'port_proto'))
    return features, 'rarity'


def build_known_hosts_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    ts = numeric_series(df, 'ts')
    features['host_rarity'] = rarity_series(text_series(df, 'host'))
    features['time_gap_z'] = zscore_series(ts.diff().fillna(0))
    features['ts'] = ts
    return features, 'rarity'


def build_software_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    features['host_p'] = numeric_series(df, 'host_p')
    features['version.major'] = numeric_series(df, 'version.major')
    features['version.minor'] = numeric_series(df, 'version.minor')
    features['software_type_rarity'] = rarity_series(text_series(df, 'software_type'))
    features['name_rarity'] = rarity_series(text_series(df, 'name'))
    features['version_addl_rarity'] = rarity_series(text_series(df, 'version.addl'))
    features['unparsed_version_len'] = string_length_series(df, 'unparsed_version')
    return features, 'rarity'


def build_arp_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    features['operation_rarity'] = rarity_series(text_series(df, 'operation'))
    features['src_mac_rarity'] = rarity_series(text_series(df, 'src_mac'))
    features['dst_mac_rarity'] = rarity_series(text_series(df, 'dst_mac'))
    features['broadcast_request'] = text_series(df, 'dst_mac').eq('ff:ff:ff:ff:ff:ff').astype(float)
    features['orig_h_rarity'] = rarity_series(text_series(df, 'orig_h'))
    features['resp_h_rarity'] = rarity_series(text_series(df, 'resp_h'))
    return features, 'rarity'


def build_stats_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    ts = numeric_series(df, 'ts')
    mem = numeric_series(df, 'mem')
    pkts_proc = numeric_series(df, 'pkts_proc')
    bytes_recv = numeric_series(df, 'bytes_recv')
    events_proc = numeric_series(df, 'events_proc')
    events_queued = numeric_series(df, 'events_queued')
    active_tcp = numeric_series(df, 'active_tcp_conns')
    active_udp = numeric_series(df, 'active_udp_conns')
    active_icmp = numeric_series(df, 'active_icmp_conns')
    tcp_conns = numeric_series(df, 'tcp_conns')
    udp_conns = numeric_series(df, 'udp_conns')
    icmp_conns = numeric_series(df, 'icmp_conns')
    timers = numeric_series(df, 'timers')
    active_timers = numeric_series(df, 'active_timers')
    files = numeric_series(df, 'files')
    active_files = numeric_series(df, 'active_files')
    dns_requests = numeric_series(df, 'dns_requests')
    active_dns_requests = numeric_series(df, 'active_dns_requests')
    reassem_tcp = numeric_series(df, 'reassem_tcp_size')
    reassem_file = numeric_series(df, 'reassem_file_size')
    reassem_frag = numeric_series(df, 'reassem_frag_size')
    reassem_unknown = numeric_series(df, 'reassem_unknown_size')

    total_active_conns = active_tcp + active_udp + active_icmp
    total_conns = tcp_conns + udp_conns + icmp_conns
    total_reassembly = reassem_tcp + reassem_file + reassem_frag + reassem_unknown
    ts_delta = ts.diff().fillna(0.0)

    # Absolute workload size still matters, but ratios and growth are more meaningful.
    features['mem'] = mem
    features['events_queued'] = events_queued
    features['active_conns'] = total_active_conns
    features['active_files'] = active_files
    features['active_dns_requests'] = active_dns_requests
    features['total_reassembly'] = total_reassembly

    # Workload shape ratios
    features['bytes_per_packet'] = safe_divide(bytes_recv, pkts_proc)
    features['events_per_packet'] = safe_divide(events_proc, pkts_proc)
    features['queued_to_processed_ratio'] = safe_divide(events_queued, events_proc + 1)
    features['active_to_total_conn_ratio'] = safe_divide(total_active_conns, total_conns + 1)
    features['tcp_share'] = safe_divide(tcp_conns, total_conns + 1)
    features['udp_share'] = safe_divide(udp_conns, total_conns + 1)
    features['icmp_share'] = safe_divide(icmp_conns, total_conns + 1)
    features['files_per_conn'] = safe_divide(files, tcp_conns + 1)
    features['active_files_per_conn'] = safe_divide(active_files, total_active_conns + 1)
    features['dns_per_udp_conn'] = safe_divide(dns_requests, udp_conns + 1)
    features['active_dns_pressure'] = safe_divide(active_dns_requests, dns_requests + 1)
    features['reassembly_per_tcp_conn'] = safe_divide(total_reassembly, tcp_conns + 1)
    features['timer_pressure'] = safe_divide(active_timers, timers + 1)
    features['mem_per_packet'] = safe_divide(mem, pkts_proc + 1)

    # Growth and rate features
    features['ts_delta'] = ts_delta
    features['pkts_rate'] = safe_divide(pkts_proc.diff().fillna(0.0), ts_delta.replace(0, np.nan))
    features['bytes_rate'] = safe_divide(bytes_recv.diff().fillna(0.0), ts_delta.replace(0, np.nan))
    features['events_rate'] = safe_divide(events_proc.diff().fillna(0.0), ts_delta.replace(0, np.nan))
    features['queue_growth_rate'] = safe_divide(events_queued.diff().fillna(0.0), ts_delta.replace(0, np.nan))
    features['conn_growth_rate'] = safe_divide(total_conns.diff().fillna(0.0), ts_delta.replace(0, np.nan))
    features['file_growth_rate'] = safe_divide(files.diff().fillna(0.0), ts_delta.replace(0, np.nan))
    features['dns_growth_rate'] = safe_divide(dns_requests.diff().fillna(0.0), ts_delta.replace(0, np.nan))

    # Abrupt operational changes
    features['mem_delta'] = mem.diff().fillna(0.0).abs()
    features['queue_delta'] = events_queued.diff().fillna(0.0).abs()
    features['conn_mix_delta'] = (
        features['tcp_share'].diff().fillna(0.0).abs() +
        features['udp_share'].diff().fillna(0.0).abs() +
        features['icmp_share'].diff().fillna(0.0).abs()
    )
    return features, 'timeseries'


def build_capture_loss_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    for column in ['ts_delta', 'gaps', 'acks', 'percent_lost']:
        if column in df.columns:
            features[column] = numeric_series(df, column)
    return features, 'timeseries'


def build_packet_filter_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    features['init'] = bool_series(df, 'init')
    features['success'] = bool_series(df, 'success')
    features['filter_rarity'] = rarity_series(text_series(df, 'filter'))
    features['node_rarity'] = rarity_series(text_series(df, 'node'))
    return features, 'rarity'


def build_loaded_scripts_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    features['path_rarity'] = rarity_series(text_series(df, 'name'))
    features['path_len'] = string_length_series(df, 'name')
    return features, 'rarity'


def build_generic_features(df, context):
    del context
    features = pd.DataFrame(index=df.index)
    for column in df.columns:
        if column in {'ts', 'uid', 'fuid'}:
            continue
        numeric = pd.to_numeric(df[column].replace(['-', '(empty)'], 0), errors='coerce')
        if numeric.notna().sum() > 0:
            features[column] = numeric.fillna(0).astype(float)
        else:
            features[f'{column}_rarity'] = rarity_series(text_series(df, column))
    return features, 'rarity'


FEATURE_BUILDERS = {
    'conn': build_conn_features,
    'dns': build_dns_features,
    'http': build_http_features,
    'files': build_files_features,
    'ssh': build_ssh_features,
    'tls': build_tls_features,
    'weird': build_weird_features,
    'notice': build_notice_features,
    'known_services': build_known_services_features,
    'known_hosts': build_known_hosts_features,
    'software': build_software_features,
    'arp': build_arp_features,
    'stats': build_stats_features,
    'capture_loss': build_capture_loss_features,
    'packet_filter': build_packet_filter_features,
    'loaded_scripts': build_loaded_scripts_features,
}


def prepare_feature_matrix(features):
    prepared = features.copy()
    for column in prepared.columns:
        prepared[column] = pd.to_numeric(prepared[column], errors='coerce').fillna(0.0)

    varying_cols = [
        column for column in prepared.columns
        if prepared[column].nunique(dropna=False) > 1 and prepared[column].std(ddof=0) > 0
    ]
    return prepared[varying_cols], varying_cols


def standardized_distance_scores(matrix):
    standardized = matrix.copy()
    for column in standardized.columns:
        std = standardized[column].std(ddof=0)
        if std == 0 or pd.isna(std):
            standardized[column] = 0.0
        else:
            standardized[column] = (standardized[column] - standardized[column].mean()) / std
    return standardized.abs().sum(axis=1)


def score_isolation_forest(features, amountanom):
    matrix, used_cols = prepare_feature_matrix(features)
    if matrix.empty:
        return pd.Series(dtype=float), pd.Series(dtype=int), used_cols, 'none'

    if IsolationForest is None or len(matrix.columns) < 2 or len(matrix) < 8:
        scores = standardized_distance_scores(matrix)
        pred_index = scores.nlargest(min(amountanom, len(scores))).index
        preds = pd.Series(0, index=matrix.index, dtype=int)
        preds.loc[pred_index] = 1
        return scores, preds, used_cols, 'fallback_distance'

    contamination = min(0.2, max(0.01, amountanom / max(len(matrix), 1)))
    model = IsolationForest(
        random_state=42,
        contamination=contamination,
        n_estimators=200,
    )
    predictions = model.fit_predict(matrix)
    scores = pd.Series(-model.score_samples(matrix), index=matrix.index)
    preds = pd.Series((predictions == -1).astype(int), index=matrix.index)
    return scores, preds, used_cols, 'isolation_forest'


def score_rarity(features, amountanom):
    matrix, used_cols = prepare_feature_matrix(features)
    if matrix.empty:
        return pd.Series(dtype=float), pd.Series(dtype=int), used_cols, 'none'

    scores = matrix.sum(axis=1)
    pred_index = scores.nlargest(min(amountanom, len(scores))).index
    preds = pd.Series(0, index=matrix.index, dtype=int)
    preds.loc[pred_index] = 1
    return scores, preds, used_cols, 'rarity'


def score_timeseries(features, amountanom):
    matrix, used_cols = prepare_feature_matrix(features)
    if matrix.empty:
        return pd.Series(dtype=float), pd.Series(dtype=int), used_cols, 'none'

    scores = pd.Series(0.0, index=matrix.index)
    for column in matrix.columns:
        scores += zscore_series(matrix[column])
        scores += zscore_series(matrix[column].diff().fillna(0))

    pred_index = scores.nlargest(min(amountanom, len(scores))).index
    preds = pd.Series(0, index=matrix.index, dtype=int)
    preds.loc[pred_index] = 1
    return scores, preds, used_cols, 'timeseries_zscore'


def score_dns_hybrid(features, amountanom):
    matrix, used_cols = prepare_feature_matrix(features)
    if matrix.empty:
        return pd.Series(dtype=float), pd.Series(dtype=int), used_cols, 'none'

    positive = pd.Series(0.0, index=matrix.index)
    for column, weight in [
        ('dga_like', 6.0),
        ('src_dga_like_count', 3.5),
        ('dga_pattern_count', 3.0),
        ('query_entropy', 2.0),
        ('unique_char_ratio', 1.5),
        ('digit_ratio', 1.2),
        ('query_rarity', 1.5),
        ('tld_rarity', 1.5),
        ('qtype_rarity', 0.6),
        ('rcode_rarity', 0.8),
        ('no_answer', 1.0),
        ('noerror_noanswer', 1.0),
        ('rejected', 1.0),
        ('uid_weird_count', 0.8),
    ]:
        if column in matrix.columns:
            positive += weight * zscore_series(matrix[column])

    raw_bonus = pd.Series(0.0, index=matrix.index)
    for column, weight in [
        ('dga_like', 8.0),
        ('src_dga_like_count', 4.0),
        ('dga_pattern_count', 3.0),
    ]:
        if column in matrix.columns:
            raw_bonus += weight * matrix[column]

    benign_penalty = pd.Series(0.0, index=matrix.index)
    for column, weight in [
        ('is_mdns', 6.0),
        ('is_local_tld', 6.0),
        ('is_reverse_lookup', 5.0),
        ('is_service_discovery', 5.0),
    ]:
        if column in matrix.columns:
            benign_penalty += weight * matrix[column]

    scores = (positive + raw_bonus - benign_penalty).clip(lower=0.0)
    pred_index = scores.nlargest(min(amountanom, len(scores))).index
    preds = pd.Series(0, index=matrix.index, dtype=int)
    preds.loc[pred_index] = 1
    return scores, preds, used_cols, 'dns_hybrid'


def score_conn_hybrid(features, amountanom):
    matrix, used_cols = prepare_feature_matrix(features)
    if matrix.empty:
        return pd.Series(dtype=float), pd.Series(dtype=int), used_cols, 'none'

    base_scores, _, _, base_method = score_isolation_forest(features, amountanom)
    if base_scores.empty:
        return base_scores, pd.Series(dtype=int), used_cols, base_method

    positive = pd.Series(0.0, index=matrix.index)
    for column, weight in [
        ('src_flow_count', 1.2),
        ('src_unique_resp_hosts', 1.4),
        ('src_unique_resp_ports', 2.8),
        ('src_failed_state_fraction', 2.5),
        ('src_short_fraction', 1.8),
        ('src_zero_payload_fraction', 2.4),
        ('src_missing_service_fraction', 1.8),
        ('src_max_dst_port_sweep', 3.4),
        ('src_mean_dst_port_sweep', 1.5),
        ('src_max_dst_failed_fraction', 1.8),
        ('is_failed_scan_state', 1.6),
        ('is_scan_history', 1.2),
        ('is_short_conn', 1.0),
        ('is_zero_payload', 1.5),
        ('is_service_missing', 1.0),
        ('state_rarity', 0.5),
        ('history_rarity', 0.4),
        ('resp_port_rarity', 0.4),
    ]:
        if column in matrix.columns:
            positive += weight * zscore_series(matrix[column])

    row_scan_intensity = pd.Series(0.0, index=matrix.index)
    for column, weight in [
        ('is_failed_scan_state', 1.6),
        ('is_scan_history', 1.1),
        ('is_short_conn', 0.9),
        ('is_zero_payload', 1.4),
        ('is_service_missing', 0.8),
    ]:
        if column in matrix.columns:
            row_scan_intensity += weight * matrix[column]

    source_scan_scale = pd.Series(0.0, index=matrix.index)
    for column, weight in [
        ('src_unique_resp_ports', 0.05),
        ('src_max_dst_port_sweep', 0.08),
        ('src_flow_count', 0.003),
        ('src_failed_state_fraction', 8.0),
        ('src_short_fraction', 5.0),
        ('src_zero_payload_fraction', 7.0),
        ('src_missing_service_fraction', 4.0),
        ('src_max_dst_failed_fraction', 5.0),
    ]:
        if column in matrix.columns:
            source_scan_scale += weight * matrix[column]

    raw_bonus = pd.Series(0.0, index=matrix.index)
    for column, weight in [
        ('is_failed_scan_state', 2.5),
        ('is_scan_history', 1.5),
        ('is_short_conn', 1.0),
        ('is_zero_payload', 2.0),
        ('is_service_missing', 1.0),
    ]:
        if column in matrix.columns:
            raw_bonus += weight * matrix[column]

    raw_bonus += source_scan_scale * row_scan_intensity

    benign_penalty = pd.Series(0.0, index=matrix.index)
    for column, weight in [
        ('is_established_session', 1.2),
    ]:
        if column in matrix.columns:
            benign_penalty += weight * matrix[column]

    if 'total_bytes' in matrix.columns:
        benign_penalty += 0.3 * zscore_series(matrix['total_bytes']).clip(lower=0.0)
    if 'total_pkts' in matrix.columns:
        benign_penalty += 0.2 * zscore_series(matrix['total_pkts']).clip(lower=0.0)
    if 'is_established_session' in matrix.columns:
        benign_penalty += 0.8 * matrix['is_established_session'] * (row_scan_intensity <= 0).astype(float)

    scores = (base_scores + positive + raw_bonus - benign_penalty).clip(lower=0.0)
    pred_index = scores.nlargest(min(amountanom, len(scores))).index
    preds = pd.Series(0, index=matrix.index, dtype=int)
    preds.loc[pred_index] = 1
    return scores, preds, used_cols, f'conn_hybrid+{base_method}'


SCORERS = {
    'isolation_forest': score_isolation_forest,
    'rarity': score_rarity,
    'timeseries': score_timeseries,
    'dns_hybrid': score_dns_hybrid,
    'conn_hybrid': score_conn_hybrid,
}


def save_dataframe(df, file, output):
    output_path = Path(output)
    if output_path.suffix.lower() == '.csv':
        target = output_path
    else:
        output_path.mkdir(parents=True, exist_ok=True)
        target = output_path / f'{Path(file).stem}.csv'
    df.to_csv(target, index=False)


def select_print_columns(df):
    keep_cols = []
    for column in df.columns:
        if column in COMMON_DROP_COLUMNS:
            continue
        if isinstance(df[column].iloc[0], list) if not df.empty else False:
            continue
        keep_cols.append(column)

    # Keep ranking columns visible and stable at the end of the output.
    ordered = [column for column in keep_cols if column not in {'score', 'pred'}]
    for column in ['score', 'pred']:
        if column in keep_cols:
            ordered.append(column)
    return ordered


def score_percentiles(scores):
    if scores.empty:
        return pd.Series(dtype=float)
    return scores.rank(method='average', pct=True)


def summarize_file_result(log_name, enriched, anomalous, amountanom, used_cols, method):
    percentiles = score_percentiles(enriched['score'])
    anomaly_fraction = float(enriched['pred'].mean()) if len(enriched) else 0.0
    top_percentile_mean = float(percentiles.loc[anomalous.index].mean()) if not anomalous.empty else 0.0
    top_score_mean = float(anomalous['score'].mean()) if not anomalous.empty else 0.0
    top_score_max = float(anomalous['score'].max()) if not anomalous.empty else 0.0

    uid_values = set()
    if 'uid' in anomalous.columns:
        uid_values = {
            value for value in anomalous['uid'].apply(normalize_scalar)
            if value
        }

    fuid_values = set()
    if 'fuid' in anomalous.columns:
        fuid_values = {
            value for value in anomalous['fuid'].apply(normalize_scalar)
            if value
        }

    linked_fuid_values = set()
    for column in ['resp_fuids', 'orig_fuids']:
        if column in anomalous.columns:
            for item in anomalous[column]:
                if isinstance(item, list):
                    linked_fuid_values.update(str(value) for value in item if str(value))

    top_records = []
    if not anomalous.empty:
        printable = anomalous[select_print_columns(anomalous)].copy()
        printable = printable.where(printable.notna(), None)
        top_records = [
            {key: to_serializable(value) for key, value in row.items()}
            for row in printable.to_dict(orient='records')
        ]

    return {
        'log_name': log_name,
        'rows': len(enriched),
        'anomaly_rows': int(enriched['pred'].sum()),
        'anomaly_fraction': anomaly_fraction,
        'top_percentile_mean': top_percentile_mean,
        'top_score_mean': top_score_mean,
        'top_score_max': top_score_max,
        'top_rows_shown': min(amountanom, len(anomalous)),
        'method': method,
        'used_cols': used_cols,
        'uid_values': uid_values,
        'fuid_values': fuid_values,
        'linked_fuid_values': linked_fuid_values,
        'top_anomalies': top_records,
        'score_values': [float(value) for value in enriched['score'].fillna(0.0).tolist()],
        'score_percentiles': [float(value) for value in percentiles.fillna(0.0).tolist()],
        'pred_values': [int(value) for value in enriched['pred'].fillna(0).astype(int).tolist()],
        'score_cutoff': (
            float(anomalous['score'].min()) if not anomalous.empty else 0.0
        ),
        'percentile_cutoff': (
            float(percentiles.loc[anomalous.index].min()) if not anomalous.empty else 0.0
        ),
    }


def get_log_weight(log_name):
    return LOG_WEIGHTS.get(log_name, 0.40)


def robust_upper_bound(values, default_margin, bounded_max=None):
    numeric = pd.Series(values, dtype=float).dropna()
    if numeric.empty:
        upper = default_margin
    elif len(numeric) == 1:
        upper = numeric.iloc[0] + default_margin
    elif len(numeric) == 2:
        upper = numeric.max() + default_margin
    else:
        median = numeric.median()
        mad = (numeric - median).abs().median() * 1.4826
        upper = median + max(default_margin, 3.5 * mad)

    if bounded_max is not None:
        upper = min(bounded_max, upper)
    return float(upper)


def build_behavior_profile(log_frames):
    profile = {
        'behavior_score': 0.0,
        'conn_scan_score': 0.0,
        'conn_scan_sources': [],
    }

    conn = log_frames.get('conn', pd.DataFrame())
    if conn.empty or 'id.orig_h' not in conn.columns:
        return profile

    frame = pd.DataFrame({
        'src': text_series(conn, 'id.orig_h'),
        'dst_host': text_series(conn, 'id.resp_h'),
        'dst_port': numeric_series(conn, 'id.resp_p'),
        'conn_state': text_series(conn, 'conn_state'),
        'history': text_series(conn, 'history'),
        'service': text_series(conn, 'service'),
        'duration': numeric_series(conn, 'duration'),
        'total_bytes': numeric_series(conn, 'orig_bytes') + numeric_series(conn, 'resp_bytes'),
    })
    frame['failed_state'] = frame['conn_state'].isin({
        'S0', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'RSTRH', 'SH', 'SHR'
    }).astype(float)
    frame['scan_history'] = frame['history'].isin({'S', 'Sr', 'Ar', 'A', 'R', 'Sh', 'ShR'}).astype(float)
    frame['short_conn'] = (frame['duration'] <= 0.05).astype(float)
    frame['zero_payload'] = (frame['total_bytes'] <= 0).astype(float)
    frame['missing_service'] = frame['service'].isin({'', '-', '(empty)'}).astype(float)
    frame['scan_like'] = (
        (frame['failed_state'] > 0) |
        (frame['scan_history'] > 0) |
        ((frame['short_conn'] > 0) & (frame['zero_payload'] > 0) & (frame['missing_service'] > 0))
    ).astype(float)

    per_src = frame.groupby('src').agg(
        flow_count=('src', 'size'),
        unique_resp_hosts=('dst_host', 'nunique'),
        unique_resp_ports=('dst_port', 'nunique'),
        failed_fraction=('failed_state', 'mean'),
        short_fraction=('short_conn', 'mean'),
        zero_payload_fraction=('zero_payload', 'mean'),
        missing_service_fraction=('missing_service', 'mean'),
        scan_like_fraction=('scan_like', 'mean'),
    )
    per_src_dst = frame.groupby(['src', 'dst_host']).agg(
        max_dst_port_sweep=('dst_port', 'nunique')
    ).reset_index()
    per_src = per_src.join(
        per_src_dst.groupby('src').agg(
            max_dst_port_sweep=('max_dst_port_sweep', 'max'),
        ),
        how='left'
    ).fillna(0.0)

    per_src['scan_score'] = (
        per_src['unique_resp_ports'].clip(upper=200) / 200.0 * 0.30 +
        per_src['max_dst_port_sweep'].clip(upper=200) / 200.0 * 0.25 +
        per_src['flow_count'].clip(upper=1000) / 1000.0 * 0.10 +
        per_src['unique_resp_hosts'].clip(upper=25) / 25.0 * 0.10 +
        per_src['failed_fraction'] * 0.10 +
        per_src['short_fraction'] * 0.05 +
        per_src['zero_payload_fraction'] * 0.07 +
        per_src['scan_like_fraction'] * 0.03
    ).clip(lower=0.0, upper=1.0)

    profile['conn_scan_score'] = float(per_src['scan_score'].max()) if not per_src.empty else 0.0
    profile['behavior_score'] = profile['conn_scan_score']
    profile['conn_scan_sources'] = [
        {
            'src': src,
            'scan_score': float(row['scan_score']),
            'flow_count': int(row['flow_count']),
            'unique_resp_hosts': int(row['unique_resp_hosts']),
            'unique_resp_ports': int(row['unique_resp_ports']),
            'max_dst_port_sweep': int(row['max_dst_port_sweep']),
            'failed_fraction': float(row['failed_fraction']),
            'scan_like_fraction': float(row['scan_like_fraction']),
        }
        for src, row in per_src.sort_values(by='scan_score', ascending=False).head(3).iterrows()
    ]
    return profile


def build_directory_summary(file_results, behavior_profile=None):
    if not file_results:
        return None
    behavior_profile = behavior_profile or {}

    total_weight = sum(get_log_weight(result['log_name']) for result in file_results) or 1.0
    weighted_top = sum(
        get_log_weight(result['log_name']) * result['top_percentile_mean']
        for result in file_results
    ) / total_weight
    weighted_fraction = sum(
        get_log_weight(result['log_name']) * min(1.0, result['anomaly_fraction'] * 5.0)
        for result in file_results
    ) / total_weight

    uid_presence = {}
    for result in file_results:
        for uid in result['uid_values']:
            uid_presence.setdefault(uid, set()).add(result['log_name'])

    crosslog_uid_two_plus = sum(1 for logs in uid_presence.values() if len(logs) >= 2)
    crosslog_uid_three_plus = sum(1 for logs in uid_presence.values() if len(logs) >= 3)
    uid_corr_score = min(1.0, (crosslog_uid_two_plus + 2 * crosslog_uid_three_plus) / 10.0)

    weird_notice_bonus = min(
        1.0,
        sum(
            min(1.0, result['anomaly_rows'] / max(result['rows'], 1))
            for result in file_results
            if result['log_name'] in {'weird', 'notice'}
        )
    )

    anomalous_file_fuids = set().union(*[
        result['fuid_values']
        for result in file_results
        if result['log_name'] == 'files'
    ]) if file_results else set()

    linked_http_fuids = set().union(*[
        result['linked_fuid_values']
        for result in file_results
        if result['log_name'] == 'http'
    ]) if file_results else set()

    fuid_overlap = len(anomalous_file_fuids & linked_http_fuids)
    fuid_bonus = min(1.0, fuid_overlap / 5.0)

    behavior_score = float(behavior_profile.get('behavior_score', 0.0))
    conn_scan_score = float(behavior_profile.get('conn_scan_score', 0.0))

    core_score = (
        0.35 * weighted_top +
        0.25 * uid_corr_score +
        0.20 * weighted_fraction +
        0.15 * weird_notice_bonus +
        0.05 * fuid_bonus
    ) * 100.0
    directory_score = min(100.0, core_score + 45.0 * behavior_score)

    if directory_score >= 70:
        severity = 'HIGH'
        color = 'red'
    elif directory_score >= 40:
        severity = 'MEDIUM'
        color = 'yellow'
    else:
        severity = 'LOW'
        color = 'green'

    top_logs = sorted(
        file_results,
        key=lambda result: (get_log_weight(result['log_name']) * result['top_percentile_mean']),
        reverse=True
    )[:5]

    return {
        'score': directory_score,
        'severity': severity,
        'color': color,
        'weighted_top': weighted_top,
        'weighted_fraction': weighted_fraction,
        'uid_corr_score': uid_corr_score,
        'weird_notice_bonus': weird_notice_bonus,
        'fuid_bonus': fuid_bonus,
        'behavior_score': behavior_score,
        'conn_scan_score': conn_scan_score,
        'conn_scan_sources': behavior_profile.get('conn_scan_sources', []),
        'crosslog_uid_two_plus': crosslog_uid_two_plus,
        'crosslog_uid_three_plus': crosslog_uid_three_plus,
        'fuid_overlap': fuid_overlap,
        'top_logs': top_logs,
    }


def build_normal_baseline(normal_summaries):
    if not normal_summaries:
        return None

    metrics = {
        'score': [summary['score'] for summary in normal_summaries],
        'weighted_top': [summary['weighted_top'] for summary in normal_summaries],
        'weighted_fraction': [summary['weighted_fraction'] for summary in normal_summaries],
        'uid_corr_score': [summary['uid_corr_score'] for summary in normal_summaries],
        'weird_notice_bonus': [summary['weird_notice_bonus'] for summary in normal_summaries],
        'fuid_bonus': [summary['fuid_bonus'] for summary in normal_summaries],
        'behavior_score': [summary.get('behavior_score', 0.0) for summary in normal_summaries],
        'conn_scan_score': [summary.get('conn_scan_score', 0.0) for summary in normal_summaries],
        'crosslog_uid_two_plus': [summary['crosslog_uid_two_plus'] for summary in normal_summaries],
        'crosslog_uid_three_plus': [summary['crosslog_uid_three_plus'] for summary in normal_summaries],
        'fuid_overlap': [summary['fuid_overlap'] for summary in normal_summaries],
    }

    thresholds = {
        'score': robust_upper_bound(metrics['score'], 10.0, 100.0),
        'weighted_top': robust_upper_bound(metrics['weighted_top'], 0.08, 1.0),
        'weighted_fraction': robust_upper_bound(metrics['weighted_fraction'], 0.08, 1.0),
        'uid_corr_score': robust_upper_bound(metrics['uid_corr_score'], 0.10, 1.0),
        'weird_notice_bonus': robust_upper_bound(metrics['weird_notice_bonus'], 0.10, 1.0),
        'fuid_bonus': robust_upper_bound(metrics['fuid_bonus'], 0.10, 1.0),
        'behavior_score': robust_upper_bound(metrics['behavior_score'], 0.08, 1.0),
        'conn_scan_score': robust_upper_bound(metrics['conn_scan_score'], 0.08, 1.0),
        'crosslog_uid_two_plus': robust_upper_bound(metrics['crosslog_uid_two_plus'], 2.0),
        'crosslog_uid_three_plus': robust_upper_bound(metrics['crosslog_uid_three_plus'], 1.0),
        'fuid_overlap': robust_upper_bound(metrics['fuid_overlap'], 1.0),
    }

    medians = {
        key: float(pd.Series(values, dtype=float).median()) if values else 0.0
        for key, values in metrics.items()
    }

    return {
        'normal_directories': len(normal_summaries),
        'thresholds': thresholds,
        'medians': medians,
    }


def compare_against_baseline(directory_summary, baseline):
    if directory_summary is None or baseline is None:
        return None

    exceeded = []
    for metric, threshold in baseline['thresholds'].items():
        value = float(directory_summary.get(metric, 0.0))
        if value > threshold:
            exceeded.append({
                'metric': metric,
                'value': value,
                'threshold': threshold,
                'delta': value - threshold,
            })

    exceeded = sorted(exceeded, key=lambda item: item['delta'], reverse=True)

    if directory_summary['score'] > baseline['thresholds']['score'] or len(exceeded) >= 4:
        verdict = 'ABOVE NORMAL BASELINE'
        color = 'red'
    elif len(exceeded) >= 2:
        verdict = 'SUSPICIOUS VS BASELINE'
        color = 'yellow'
    else:
        verdict = 'WITHIN NORMAL BASELINE'
        color = 'green'

    return {
        'verdict': verdict,
        'color': color,
        'exceeded_metrics': exceeded,
        'baseline_thresholds': baseline['thresholds'],
        'baseline_medians': baseline['medians'],
        'normal_directories': baseline['normal_directories'],
    }


def print_directory_summary(summary, directory_path):
    print(f'\n{style("Directory Summary", "cyan", bold=True)}')
    header = f'{summary["severity"]} MALICIOUSNESS'
    print(style(f'{header}: {summary["score"]:.1f}/100', summary['color'], bold=True))
    print(f'Path: {directory_path}')
    print(
        'Components: '
        f'weighted_top={summary["weighted_top"]:.3f}, '
        f'uid_correlation={summary["uid_corr_score"]:.3f}, '
        f'anomaly_fraction={summary["weighted_fraction"]:.3f}, '
        f'weird_notice={summary["weird_notice_bonus"]:.3f}, '
        f'fuid_overlap={summary["fuid_bonus"]:.3f}, '
        f'behavior={summary["behavior_score"]:.3f}'
    )
    print(
        'Cross-log ties: '
        f'uid_in_2plus_logs={summary["crosslog_uid_two_plus"]}, '
        f'uid_in_3plus_logs={summary["crosslog_uid_three_plus"]}, '
        f'http_files_fuid_overlap={summary["fuid_overlap"]}'
    )
    if summary['conn_scan_sources']:
        print('Behavioral outliers:')
        for source in summary['conn_scan_sources']:
            print(
                f'  - conn source {source["src"]}: '
                f'scan_score={source["scan_score"]:.3f}, '
                f'flows={source["flow_count"]}, '
                f'dst_hosts={source["unique_resp_hosts"]}, '
                f'dst_ports={source["unique_resp_ports"]}, '
                f'max_dst_port_sweep={source["max_dst_port_sweep"]}, '
                f'failed_fraction={source["failed_fraction"]:.3f}'
            )
    print('Top contributing logs:')
    for result in summary['top_logs']:
        contribution = get_log_weight(result['log_name']) * result['top_percentile_mean']
        print(
            f'  - {result["log_name"]}: '
            f'rows={result["rows"]}, '
            f'anomalies={result["anomaly_rows"]}, '
            f'top_mean_percentile={result["top_percentile_mean"]:.3f}, '
            f'contribution={contribution:.3f}, '
            f'method={result["method"]}'
        )


def print_baseline_comparison(comparison):
    print(f'\n{style("Baseline Comparison", "cyan", bold=True)}')
    print(style(
        f'{comparison["verdict"]} using {comparison["normal_directories"]} normal director'
        f'{"y" if comparison["normal_directories"] == 1 else "ies"}',
        comparison['color'],
        bold=True
    ))
    if not comparison['exceeded_metrics']:
        print('No summary metrics exceeded the learned normal thresholds.')
        return

    print('Exceeded metrics:')
    for item in comparison['exceeded_metrics'][:8]:
        print(
            f'  - {item["metric"]}: '
            f'value={item["value"]:.3f}, '
            f'threshold={item["threshold"]:.3f}, '
            f'delta=+{item["delta"]:.3f}'
        )


def _plot_file_scores(axis, result):
    scores = np.asarray(result.get('score_values', []), dtype=float)
    preds = np.asarray(result.get('pred_values', []), dtype=int)
    if scores.size == 0:
        axis.text(0.5, 0.5, 'No scores available', ha='center', va='center')
        axis.set_axis_off()
        return

    x = np.arange(scores.size)
    axis.plot(x, scores, color='#1f77b4', linewidth=1.0, label='Score')

    anomaly_idx = x[preds == 1]
    anomaly_scores = scores[preds == 1]
    if anomaly_idx.size:
        axis.scatter(
            anomaly_idx,
            anomaly_scores,
            color='#d62728',
            s=18,
            zorder=3,
            label='Anomalous flow'
        )
        axis.axhline(
            result.get('score_cutoff', 0.0),
            color='#ff7f0e',
            linestyle='--',
            linewidth=1.0,
            label='Cutoff'
        )

    axis.set_title(
        f'{result["log_name"]}.log  '
        f'({result["method"]}, rows={result["rows"]}, anomalies={result["anomaly_rows"]})',
        fontsize=11
    )
    axis.set_xlabel('Flow index')
    axis.set_ylabel('Score')
    axis.grid(True, alpha=0.25)
    axis.legend(loc='upper right', fontsize=8)


def _plot_combined_scores(axis, file_results, directory_summary):
    offset = 0
    boundary_positions = []
    boundary_labels = []
    any_points = False

    for index, result in enumerate(file_results):
        percentiles = np.asarray(result.get('score_percentiles', []), dtype=float)
        preds = np.asarray(result.get('pred_values', []), dtype=int)
        if percentiles.size == 0:
            continue

        x = np.arange(offset, offset + percentiles.size)
        color = '#1f77b4' if index % 2 == 0 else '#4c78a8'
        axis.plot(x, percentiles, color=color, linewidth=0.9, alpha=0.8)

        anomaly_idx = x[preds == 1]
        anomaly_scores = percentiles[preds == 1]
        if anomaly_idx.size:
            axis.scatter(
                anomaly_idx,
                anomaly_scores,
                color='#d62728',
                s=14,
                zorder=3
            )
            any_points = True

        cutoff = result.get('percentile_cutoff', 0.0)
        if cutoff > 0:
            axis.hlines(
                cutoff,
                x[0],
                x[-1],
                colors='#ff7f0e',
                linestyles='--',
                linewidth=0.8,
                alpha=0.5
            )

        boundary_positions.append(offset + percentiles.size / 2.0)
        boundary_labels.append(f'{result["log_name"]}\n(n={result["rows"]})')
        offset += percentiles.size
        axis.axvline(offset, color='#bbbbbb', linewidth=0.5, alpha=0.5)

    if offset == 0:
        axis.text(0.5, 0.5, 'No combined score data available', ha='center', va='center')
        axis.set_axis_off()
        return

    if directory_summary is not None:
        title = (
            f'Combined Flow-by-Flow Normalized Scores  '
            f'(directory score={directory_summary["score"]:.1f}/100, '
            f'severity={directory_summary["severity"]})'
        )
    else:
        title = 'Combined Flow-by-Flow Normalized Scores'

    axis.set_title(title, fontsize=12)
    axis.set_xlabel('Combined flow index across all files')
    axis.set_ylabel('Within-file score percentile')
    axis.set_ylim(0, 1.02)
    axis.grid(True, alpha=0.25)
    axis.set_xticks(boundary_positions)
    axis.set_xticklabels(boundary_labels, rotation=35, ha='right', fontsize=8)

    legend_items = [
        plt.Line2D([0], [0], color='#1f77b4', linewidth=1.2, label='Normalized score line'),
        plt.Line2D([0], [0], color='#ff7f0e', linestyle='--', linewidth=1.0, label='Per-file cutoff'),
    ]
    if any_points:
        legend_items.append(
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='#d62728', markersize=6, label='Anomalous flow')
        )
    axis.legend(handles=legend_items, loc='upper right', fontsize=8)


def export_score_plots(path, input_path, file_results, directory_summary, baseline_comparison=None):
    if plt is None or PdfPages is None:
        raise ImportError(
            'matplotlib is required for plot export. Install it and retry.'
        )

    output_path = Path(path)
    if output_path.suffix.lower() != '.pdf':
        raise ValueError('Plot export currently requires a .pdf output path.')

    with PdfPages(output_path) as pdf:
        summary_fig, axes = plt.subplots(2, 1, figsize=(12, 10))
        summary_fig.suptitle(f'Zeek Anomaly Score Summary\n{input_path}', fontsize=14)

        component_names = ['weighted_top', 'weighted_fraction', 'uid_corr_score', 'weird_notice_bonus', 'fuid_bonus']
        component_values = [directory_summary.get(name, 0.0) if directory_summary else 0.0 for name in component_names]
        if directory_summary and 'behavior_score' in directory_summary:
            component_names.append('behavior_score')
            component_values.append(directory_summary.get('behavior_score', 0.0))

        axes[0].bar(component_names, component_values, color='#4c78a8')
        axes[0].set_ylim(0, max(1.0, max(component_values) * 1.15 if component_values else 1.0))
        axes[0].set_ylabel('Normalized component value')
        axes[0].set_title(
            f'Directory score={directory_summary["score"]:.1f}/100, severity={directory_summary["severity"]}'
            if directory_summary else 'Directory summary unavailable'
        )
        axes[0].tick_params(axis='x', rotation=20)
        axes[0].grid(True, axis='y', alpha=0.25)

        top_logs = directory_summary.get('top_logs', []) if directory_summary else []
        labels = [result['log_name'] for result in top_logs]
        contributions = [
            get_log_weight(result['log_name']) * result['top_percentile_mean']
            for result in top_logs
        ]
        axes[1].bar(labels, contributions, color='#59a14f')
        axes[1].set_ylabel('Contribution')
        axes[1].set_title('Top contributing log files')
        axes[1].grid(True, axis='y', alpha=0.25)

        summary_text = []
        if baseline_comparison is not None:
            summary_text.append(
                f'Baseline verdict: {baseline_comparison["verdict"]} '
                f'({baseline_comparison["normal_directories"]} normal directories)'
            )
            exceeded = baseline_comparison.get('exceeded_metrics', [])[:5]
            if exceeded:
                summary_text.extend(
                    f'{item["metric"]}: {item["value"]:.3f} > {item["threshold"]:.3f}'
                    for item in exceeded
                )
        if directory_summary and directory_summary.get('conn_scan_sources'):
            summary_text.append('Behavioral outliers:')
            summary_text.extend(
                f'{item["src"]}: scan_score={item["scan_score"]:.3f}, '
                f'dst_ports={item["unique_resp_ports"]}, '
                f'max_sweep={item["max_dst_port_sweep"]}'
                for item in directory_summary['conn_scan_sources'][:3]
            )
        if summary_text:
            summary_fig.text(0.02, 0.02, '\n'.join(summary_text), fontsize=9, va='bottom')

        summary_fig.tight_layout(rect=(0, 0.06, 1, 0.95))
        pdf.savefig(summary_fig)
        plt.close(summary_fig)

        combined_fig, combined_axis = plt.subplots(figsize=(14, 6))
        _plot_combined_scores(combined_axis, file_results, directory_summary)
        combined_fig.tight_layout()
        pdf.savefig(combined_fig)
        plt.close(combined_fig)

        for result in file_results:
            fig, axis = plt.subplots(figsize=(12, 5))
            _plot_file_scores(axis, result)
            fig.tight_layout()
            pdf.savefig(fig)
            plt.close(fig)


def export_json_summary(path, input_path, file_results, directory_summary, baseline_comparison=None):
    payload = {
        'input_path': input_path,
        'directory_summary': directory_summary,
        'baseline_comparison': baseline_comparison,
        'files': [],
    }

    for result in file_results:
        payload['files'].append({
            'log_name': result['log_name'],
            'rows': result['rows'],
            'anomaly_rows': result['anomaly_rows'],
            'anomaly_fraction': result['anomaly_fraction'],
            'top_percentile_mean': result['top_percentile_mean'],
            'top_score_mean': result['top_score_mean'],
            'top_score_max': result['top_score_max'],
            'top_rows_shown': result['top_rows_shown'],
            'method': result['method'],
            'used_cols': result['used_cols'],
            'uid_values': sorted(result['uid_values']),
            'fuid_values': sorted(result['fuid_values']),
            'linked_fuid_values': sorted(result['linked_fuid_values']),
            'top_anomalies': result['top_anomalies'],
        })

    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(to_serializable(payload), handle, indent=2)


def analyze_directory(input_path, amountanom, dumptocsv, verbosity=0, debug=0, print_output=True):
    log_files = iter_log_files(input_path)
    log_frames = {}
    skipped_empty_logs = []
    for log_file in log_files:
        try:
            log_frames[log_file.stem] = load_zeek_log(log_file)
        except EmptyLogError:
            skipped_empty_logs.append(log_file)

    if skipped_empty_logs and print_output:
        for log_file in skipped_empty_logs:
            print(f"Skipping {log_file.name}: empty file.")

    if not log_frames:
        return [], None, False

    context = build_context(log_frames)
    behavior_profile = build_behavior_profile(log_frames)

    file_results = []
    found_any_anomalies = False
    for log_file in log_files:
        if log_file.stem not in log_frames:
            continue
        result = detect(
            log_file.stem,
            log_file,
            log_frames[log_file.stem],
            context,
            amountanom,
            dumptocsv if print_output else None,
            verbosity if print_output else 0,
            debug if print_output else 0,
            print_output=print_output,
        )
        if result is not None:
            file_results.append(result)
            found_any_anomalies = found_any_anomalies or result['anomaly_rows'] > 0

    directory_summary = (
        build_directory_summary(file_results, behavior_profile)
        if Path(input_path).is_dir() and file_results else None
    )
    return file_results, directory_summary, found_any_anomalies


def detect(log_name, file, df, context, amountanom, dumptocsv, verbosity=0, debug=0, print_output=True):
    builder = FEATURE_BUILDERS.get(log_name, build_generic_features)
    features, scorer_name = builder(df.copy(), context)
    scores, preds, used_cols, method = SCORERS[scorer_name](features, amountanom)

    if scores.empty or not used_cols:
        if verbosity or debug:
            print(f"Skipping {Path(file).name}: insufficient features for anomaly detection.")
        return None

    enriched = df.copy()
    enriched['score'] = scores.reindex(enriched.index).fillna(0.0)
    enriched['pred'] = preds.reindex(enriched.index).fillna(0).astype(int)

    if dumptocsv and dumptocsv != "None":
        save_dataframe(enriched, file, dumptocsv)

    if verbosity or debug:
        print(f"Detector for {Path(file).name}: {method}")
        print("Used feature columns:", used_cols)
        if debug:
            print("Feature sample:\n", features[used_cols].head(10))

    anomalous = enriched[enriched['pred'] == 1].sort_values(by='score', ascending=False).iloc[:amountanom]
    if anomalous.empty:
        return summarize_file_result(log_name, enriched, anomalous, amountanom, used_cols, method)

    if print_output:
        print(f'\nTop anomalies in {Path(file).name}')
        print(anomalous[select_print_columns(anomalous)])
    return summarize_file_result(log_name, enriched, anomalous, amountanom, used_cols, method)


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
    parser.add_argument('-J', '--jsonsummary',
                        help='Write a JSON summary with per-file results and the directory score.',
                        required=False)
    parser.add_argument('-P', '--plotfile',
                        help='Write a multi-page PDF with flow-by-flow score plots for each log and a final summary page.',
                        required=False)
    parser.add_argument('-N', '--normal-dir',
                        help='Known-normal Zeek directory used to train baseline thresholds. Repeat for multiple directories.',
                        action='append',
                        required=False)
    args = parser.parse_args()

    if args.verbose or args.debug:
        print('Zeek Anomaly Detector: per-log anomaly detection for Zeek logs.')
        print('Author: Sebastian Garcia (eldraco@gmail.com)')
        print('        Veronica Valeros (vero.valeros@gmail.com)')

    input_path = args.file or args.directory
    file_results, directory_summary, found_any_anomalies = analyze_directory(
        input_path,
        args.amountanom,
        args.dumptocsv,
        args.verbose or 0,
        args.debug or 0,
        print_output=True
    )

    baseline_comparison = None
    if args.directory and file_results:
        print_directory_summary(directory_summary, args.directory)
        if args.normal_dir:
            normal_summaries = []
            for normal_dir in args.normal_dir:
                _, normal_summary, _ = analyze_directory(
                    normal_dir,
                    args.amountanom,
                    None,
                    0,
                    0,
                    print_output=False
                )
                if normal_summary is not None:
                    normal_summaries.append(normal_summary)

            baseline = build_normal_baseline(normal_summaries)
            baseline_comparison = compare_against_baseline(directory_summary, baseline)
            if baseline_comparison is not None:
                print_baseline_comparison(baseline_comparison)

    if args.jsonsummary:
        export_json_summary(
            args.jsonsummary,
            input_path,
            file_results,
            directory_summary,
            baseline_comparison
        )

    if args.plotfile:
        export_score_plots(
            args.plotfile,
            input_path,
            file_results,
            directory_summary,
            baseline_comparison
        )

    if (args.verbose or args.debug) and not found_any_anomalies:
        print('No anomalies detected.')
