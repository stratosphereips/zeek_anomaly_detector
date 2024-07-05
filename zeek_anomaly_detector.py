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
import sys
from pathlib import Path
sys.path.insert(0, Path(sys.path[0]).parent.as_posix())
import config
from zat.log_to_dataframe import LogToDataFrame
from zat import live_simulator, dataframe_cache
import argparse
import pandas as pd
from pyod.models.pca import PCA
from io import StringIO
from tqdm import tqdm
import time

# from sklearn.model_selection import train_test_split
# from pyod.models import lof
# from pyod.models.abod import ABOD
# from pyod.models.cblof import CBLOF
# from pyod.models.lof import LOF
# from pyod.models.loci import LOCI
# from pyod.models.lscp import LSCP
# from pyod.models.mcd import MCD
# from pyod.models.ocsvm import OCSVM
# from pyod.models.sod import SOD
# from pyod.models.so_gaal import SO_GAAL # Needs keras
# from pyod.models.sos import SOS  # Needs keras
# from pyod.models.xgbod import XGBOD # Needs keras
# from pyod.models.knn import KNN   # kNN detector

def data_conv(bro_df):
    columns_to_conv = ["orig_bytes", "resp_bytes", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes"]
    for column in tqdm(columns_to_conv, total=len(columns_to_conv), desc="replace - and change data type"):
        bro_df[column].replace('-', '0', inplace=True)
        bro_df[column] = bro_df[column].fillna(0).astype("int32") 

    bro_df['duration'].replace('-', '0', inplace=True)
    bro_df['duration'] = bro_df['duration'].apply(lambda x:x.total_seconds()).fillna(0).astype('float64')

    return bro_df

def train(bro_df, dumptocsv):
    ''' specify classifier
    
    '''
    # Replace the rows without data (with '-') with 0.
    # Even though this may add a bias in the algorithms,
    # is better than not using the lines.
    # Also fill the no values with 0
    # Finally put a type to each column

    # Save dataframe to disk as CSV
    if dumptocsv != "None":
        bro_df.to_csv(dumptocsv)

    # Add the columns from the log file that we know are numbers.
    # This is only for conn.log files.
    x_train = bro_df[['duration', 'orig_bytes', 'id.resp_p',
                    'resp_bytes', 'orig_ip_bytes', 'resp_pkts',
                    'resp_ip_bytes']]

    
    # Our y is the label. But we are not using it now.
    # y = bro_df.label

    # The x_test is where we are going to search for anomalies.
    # In our case, its the same set of data than x_train.
    x_test = x_train

    #################
    # Select a model from below

    # ABOD class for Angle-base Outlier Detection. For an observation, the
    # variance of its weighted cosine scores to all neighbors could be
    # viewed as the outlying score.
    # clf = ABOD()

    # LOF
    # clf = LOF()

    # CBLOF
    # clf = CBLOF()

    # LOCI
    # clf = LOCI()

    # LSCP
    # clf = LSCP()

    # MCD
    # clf = MCD()

    # OCSVM
    # clf = OCSVM()

    # PCA. Good and fast!
    clf = PCA()

    # SOD
    # clf = SOD()

    # SO_GAAL
    # clf = SO_GALL()

    # SOS
    # clf = SOS()

    # XGBOD
    # clf = XGBOD()

    # KNN
    # Good results but slow
    # clf = KNN()
    # clf = KNN(n_neighbors=10)
    #################
    # extract the value of dataframe to matrix
    x_train = x_train.values
    # Fit the model to the train data
    clf.fit(x_train)

    # get the prediction on the test data
    y_test_pred = clf.predict(x_test)  # outlier labels (0 or 1)

    y_test_scores = clf.decision_function(x_test)  # outlier scores

    # Convert the ndarrays of scores and predictions to  pandas series
    scores_series = pd.Series(y_test_scores)
    pred_series = pd.Series(y_test_pred)

    # Now use the series to add a new column to the X test
    x_test.insert(loc=len(x_test.columns),column='score', value=scores_series.values)
    x_test.insert(loc=len(x_test.columns),column='pred', value=pred_series.values)

    return x_test
    
def res_print(bro_df, amountanom, x_test):
    # Add the score to the bro_df also. So we can show it at the end
    bro_df['score'] = x_test['score']

    # Keep the positive predictions only.
    # That is, keep only what we predict is an anomaly.
    x_test_predicted = x_test[x_test.pred == 1]

    # Keep the top X amount of anomalies
    top10 = x_test_predicted.sort_values(by='score',
                                         ascending=False).iloc[:amountanom]

    # Print the results
    # Find the predicted anomalies in the original bro dataframe,
    # where the rest of the data is
    df_to_print = bro_df.iloc[top10.index]
    print('\nFlows of the top anomalies')

    # Only print some columns, not all, so its easier to read.
    df_to_print = df_to_print.drop(['conn_state', 'history', 'local_orig',
                                    'local_resp', 'missed_bytes', 'ts',
                                    'tunnel_parents', 'uid', 'label'], axis=1)
    print(df_to_print)



def detect(file, amountanom, dumptocsv, realtime:bool):
    """
    Function to apply a very simple anomaly detector
    :param amountanom: the top number of anomalies we want to print
    :param dumptocsw: whether to save csv to disk
    :param realtime: whether in real-time processing mode
    """
    if not realtime:
        file = Path.cwd().joinpath(file)
        log_to_df = LogToDataFrame()
        # Create a Pandas dataframe from the conn.log
        bro_df = log_to_df.create_dataframe(file, ts_index=False)
        names = config.columns["conn"]
        bro_df = bro_df[names]
        # In case you need a label, due to some models being able to work in a
        # semisupervized mode, then put it here. For now everything is
        # 'normal', but we are not using this for detection
        # bro_df['label'] = 'normal'
        bro_df['label'] = "normal"

        bro_df = data_conv(bro_df)
        x_test  = train(bro_df, dumptocsv)
        res_print(bro_df, amountanom, x_test)

    else:
        # define the Events Per Second to emit events
        data_stream = live_simulator.LiveSimulator(file, eps=config.eps)
        # create cache dataframe within certain max time period 
        df_cache = dataframe_cache.DataFrameCache(max_cache_time=config.max_cache_time)
        time_delta = 10
        timer = time.time() + time_delta                                   
        for line in data_stream.rows():
            df_cache.add_row(line)
            if time.time() > timer:
                bro_df = df_cache.dataframe()
                bro_df = data_conv(bro_df)
                bro_df['label'] = "normal"
                x_test  = train(bro_df, dumptocsv)
                res_print(bro_df, amountanom, x_test)


if __name__ == '__main__':
    print('Zeek Anomaly Detector: a simple anomaly detector \
for Zeek conn.log files.')
    print('Author: Sebastian Garcia (eldraco@gmail.com)')
    print('        Veronica Valeros (vero.valeros@gmail.com)')

    # Parse the parameters
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
    parser.add_argument('-f', '--file',
                        help='Zeek conn.log path.',
                        required=True)
    parser.add_argument('-a', '--amountanom',
                        help='Amount of anomalies to show.',
                        required=False,
                        default=10,
                        type=int)
    parser.add_argument('-D', '--dumptocsv',
                        help='Dump the conn.log DataFrame to a csv file',
                        required=False)
    
    parser.add_argument('-R', '--realtime',
                        help='Read the conn.log in real time.',
                        required=False,
                        type=bool,
                        default=False)
    
    args = parser.parse_args()

    detect(args.file, args.amountanom, args.dumptocsv, args.realtime)
