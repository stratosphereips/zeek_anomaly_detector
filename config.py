columns = {
    "conn": ['ts', 'uid', 'id.orig_h', 'id.orig_p',
            'id.resp_h', 'id.resp_p', 'proto', 'service',
            'duration',  'orig_bytes', 'resp_bytes',
            'conn_state', 'local_orig', 'local_resp',
            'missed_bytes',  'history', 'orig_pkts',
            'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
            'tunnel_parents']
}

## define parameters for live monitoring
# events per second that the simulator will emit events
eps=10
# max time to create cache dataframe
max_cache_time=600
# batch size to proces
batch_size = 1000