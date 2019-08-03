#!/usr/bin/env python

import pandas as pd
from brothon import bro_log_reader
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



def detect(file, amountanom, realtime):
    """
    Simple anomaly detector
    """
    # Create a bro reader on a given log file
    reader = bro_log_reader.BroLogReader(file, tail=realtime)
    # Create a Pandas dataframe from reader
    bro_df = pd.DataFrame(reader.readrows())


    #X = bro_df.drop('label', axis=1)
    bro_df['label'] = 'normal'
    # Change the datetime delta value to seconds
    bro_df['durationsec'] = bro_df.duration.apply(lambda x: x.total_seconds())
    # Replace the rows without orig_bytes with -1
    bro_df['orig_bytes'] = bro_df['orig_bytes'].replace(to_replace='-',value=-1)
    bro_df['resp_bytes'] = bro_df['resp_bytes'].replace(to_replace='-',value=-1)
    bro_df['resp_pkts'] = bro_df['resp_pkts'].replace(to_replace='-',value=-1)
    bro_df['orig_ip_bytes'] = bro_df['orig_ip_bytes'].replace(to_replace='-',value=-1)
    bro_df['resp_ip_bytes'] = bro_df['resp_ip_bytes'].replace(to_replace='-',value=-1)

    # Our X now
    #X = bro_df[['durationsec', 'orig_bytes']]
    X = bro_df[['durationsec', 'orig_bytes', 'id.resp_p', 'resp_bytes', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']]
    # Our y now
    y = bro_df.label

    # split in train/test
    # X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.05, random_state=42)

    # Train in X and test X
    X_train = X
    X_test = X

    #################
    # Select the model
    # Try ABOD
    #outlier_fraction = 0.00001
    #clf = ABOD(contamination=0.1)
    #clf = ABOD()

    # Try LOF
    #clf = LOF()

    # Try CBLOF
    #clf = CBLOF()

    # Try LOCI
    #clf = LOCI()
    
    # Try LSCP
    #clf = LSCP()

    # Try MCD
    #clf = MCD()

    # Try OCSVM
    #clf = OCSVM()

    # Try PCA. Good and fast!
    clf = PCA()

    # Try SOD. 
    #clf = SOD()

    # Try SO_GAAL. 
    #clf = SO_GALL()

    # Try SOS. 
    #clf = SOS()

    # Try XGBOD. 
    #clf = XGBOD()



    # Try KNN
    #clf = KNN()
    # contamination=0.1, "method='largest'", 'radius=1.0', "algorithm='auto'", 'leaf_size=30', "metric='minkowski'", 'p=2', 'metric_params=None'
    #clf = KNN(contamination=0.5, n_neighbors=10)
    #clf = KNN(n_neighbors=10)
    #################

    # Fit the model to the train data
    clf.fit(X_train)

    # get the prediction label and outlier scores of the training data
    #y_train_pred = clf.labels_  # binary labels (0: inliers, 1: outliers)
    #y_train_scores = clf.decision_scores_  # raw outlier scores

    # get the prediction on the test data
    y_test_pred = clf.predict(X_test)  # outlier labels (0 or 1)
    y_test_scores = clf.decision_function(X_test)  # outlier scores

    # Convert to series
    scores_series = pd.Series(y_test_scores)
    pred_series = pd.Series(y_test_pred)

    # Add as new columns to the X test
    X_test['score'] = scores_series.values
    X_test['pred'] = pred_series.values

    # Add the score the bro_df
    bro_df['score'] = X_test['score']

    # Keep the positive predicions only
    X_test_predicted = X_test[X_test.pred == 1]

    # Keep the top 
    top10 = X_test_predicted.sort_values(by='score', ascending=False).iloc[:amountanom]


    print('\nFlows of the top anomalies')
    df_to_print = bro_df.iloc[top10.index]
    df_to_print = df_to_print.drop(['conn_state','history','local_orig' ,'local_resp' ,'missed_bytes' ,'ts' ,'tunnel_parents' ,'uid' ,'label' ], axis=1)
    print(df_to_print)



if __name__ == '__main__':
    print('Simple Anomaly Detector.')

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the program.', action='store', required=False, type=int)
    parser.add_argument('-f', '--file', help='Path to the conn.log input file to read.', required=True)
    parser.add_argument('-a', '--amountanom', help='Amount of anomalies to show.', required=False, default=10, type=int)
    parser.add_argument('-R', '--realtime', help='Read the conn.log in real time.', required=False, type=bool, default=False)
    args = parser.parse_args()

    detect(args.file, args.amountanom, args.realtime)


