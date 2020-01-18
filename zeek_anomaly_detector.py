#!/usr/bin/env python3
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import pandas as pd
from zat import bro_log_reader
from zat.log_to_dataframe import LogToDataFrame
from sklearn.model_selection import train_test_split
from pyod.models import lof
from pyod.models.abod import ABOD
from pyod.models.cblof import CBLOF
from pyod.models.lof import LOF
from pyod.models.loci import LOCI
from pyod.models.lscp import LSCP
from pyod.models.mcd import MCD
from pyod.models.ocsvm import OCSVM
from pyod.models.pca import PCA
from pyod.models.sod import SOD
#from pyod.models.so_gaal import SO_GAAL # Needs keras
from pyod.models.sos import SOS  # Needs keras
#from pyod.models.xgbod import XGBOD # Needs keras
from pyod.models.knn import KNN   # kNN detector
import argparse
import warnings

# This horrible hack is only to stop sklearn from printing those warnings
def warn(*args, **kwargs):
    pass
warnings.warn = warn

def detect(file, amountanom, realtime,dumptocsv):
    """
    Function to apply a very simple anomaly detector
    amountanom: The top number of anomalies we want to print
    realtime: If we want to read the conn.log file in real time (not working)
    """

    # Create a Pandas dataframe from the conn.log
    log_to_df = LogToDataFrame()
    bro_df = log_to_df.create_dataframe(file,ts_index=False)
    
    # In case you need a label, due to some models being able to work in a semisupervized mode, then put it here. For now everything is 'normal', but we are not using this for detection
    bro_df['label'] = 'normal'

    # Change the datetime delta value to seconds. Scikit does not now how to work with timedeltas
    bro_df['durationsec'] = bro_df.duration.apply(lambda x: x.total_seconds())

    # Replace the rows without data (with '-') with -1. Even though this may add a bias in the algorithms, is better than not using the lines.
    bro_df['orig_bytes'] = bro_df['orig_bytes'].fillna(0)
    bro_df['resp_bytes'] = bro_df['resp_bytes'].fillna(0)
    bro_df['resp_pkts'] = bro_df['resp_pkts'].fillna(0)
    bro_df['orig_ip_bytes'] = bro_df['orig_ip_bytes'].fillna(0)
    bro_df['resp_ip_bytes'] = bro_df['resp_ip_bytes'].fillna(0)
    bro_df['durationsec'] = bro_df['durationsec'].fillna(0)

    # Save dataframe to disk as CSV
    if dumptocsv != "None":
        bro_df.to_csv(dumptocsv)

    # Add the columns from the log file that we know are numbers. This is only for conn.log files.
    X_train = bro_df[['durationsec', 'orig_bytes', 'id.resp_p', 'resp_bytes', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']]

    # Our y is the label. But we are not using it now.
    y = bro_df.label

    # The X_test is where we are going to search for anomalies. In our case, its the same set of data than X_train. 
    X_test = X_train

    #################
    # Select a model from below

    # ABOD class for Angle-base Outlier Detection. For an observation, the variance of its weighted cosine scores to all neighbors could be viewed as the outlying score.
    #clf = ABOD()

    # LOF
    #clf = LOF()

    # CBLOF
    #clf = CBLOF()

    # LOCI
    #clf = LOCI()
    
    # LSCP
    #clf = LSCP()

    # MCD
    #clf = MCD()

    # OCSVM
    #clf = OCSVM()

    # PCA. Good and fast!
    clf = PCA()

    # SOD 
    #clf = SOD()

    # SO_GAAL
    #clf = SO_GALL()

    # SOS
    #clf = SOS()

    # XGBOD
    #clf = XGBOD()



    # KNN
    # Good results but slow
    #clf = KNN()
    #clf = KNN(n_neighbors=10)
    #################

    # Fit the model to the train data
    clf.fit(X_train)

    # get the prediction on the test data
    y_test_pred = clf.predict(X_test)  # outlier labels (0 or 1)

    y_test_scores = clf.decision_function(X_test)  # outlier scores

    # Convert the ndarrays of scores and predictions to  pandas series
    scores_series = pd.Series(y_test_scores)
    pred_series = pd.Series(y_test_pred)

    # Now use the series to add a new column to the X test
    X_test['score'] = scores_series.values
    X_test['pred'] = pred_series.values

    # Add the score to the bro_df also. So we can show it at the end
    bro_df['score'] = X_test['score']

    # Keep the positive predictions only. That is, keep only what we predict is an anomaly.
    X_test_predicted = X_test[X_test.pred == 1]

    # Keep the top X amount of anomalies
    top10 = X_test_predicted.sort_values(by='score', ascending=False).iloc[:amountanom]

    ## Print the results
    # Find the predicted anomalies in the original bro dataframe, where the rest of the data is
    #df_to_print = bro_df.iloc[top10.index]
    df_to_print = bro_df.iloc[top10.index]
    print('\nFlows of the top anomalies')

    # Only print some columns, not all, so its easier to read.
    df_to_print = df_to_print.drop(['conn_state','history','local_orig' ,'local_resp' ,'missed_bytes' ,'ts', 'tunnel_parents' ,'uid' ,'label' ], axis=1)
    print(df_to_print)



if __name__ == '__main__':
    print('Simple Anomaly Detector for Zeek conn.log files.')
    print('Sebastian Garcia. eldraco@gmail.com.')

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the program.', action='store', required=False, type=int)
    parser.add_argument('-f', '--file', help='Path to the conn.log input file to read.', required=True)
    parser.add_argument('-a', '--amountanom', help='Amount of anomalies to show.', required=False, default=10, type=int)
    parser.add_argument('-R', '--realtime', help='Read the conn.log in real time.', required=False, type=bool, default=False)
    parser.add_argument('-D', '--dumptocsv', help='Dump the conn.log DataFrame to a csv file', required=False)
    args = parser.parse_args()

    detect(args.file, args.amountanom, args.realtime, args.dumptocsv)


