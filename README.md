# zeek_anomaly_detector

An anomaly detector for conn.log files of zeek/bro. It uses Zeek Analysis Tools (ZAT) to load the file, and pyod models. It is completely automated, so you can just give the file and will ouput the anomalous flows. By default uses the PCA model.

## Dependencies

Please install the following dependencies:
- zat: The ZAT Python package supports the processing and analysis of Zeek data with Pandas, scikit-learn, and Spark.
- pyod: PyOD is a comprehensive and scalable Python toolkit for detecting outlying objects in multivariate data. 

Install with pip: `pip install zat pyod`

## Usage
```
$ time ./zeek_anomaly_detector.py -a 20 -f sample-logs/conn.log
Simple Anomaly Detector for Zeek conn.log files.
Sebastian Garcia. eldraco@gmail.com.
Successfully monitoring sample-logs/conn.log...

Flows of the top anomalies
             duration      id.orig_h  id.orig_p       id.resp_h  id.resp_p  orig_bytes  orig_ip_bytes  orig_pkts proto  resp_bytes  resp_ip_bytes  resp_pkts service  durationsec         score
24482 00:05:33.102728  192.168.1.125      53510   87.236.19.168         80         108          23852        593   tcp     2455407        2524319       1686    http   333.102728  3.091146e+07
109   00:02:08.617586  192.168.1.125      49188  201.232.32.124        443       79809          84351         78   tcp        2544           4828         55     ssl   128.617586  2.377827e+07
35031 00:01:06.384740  192.168.1.125      62788  192.157.238.15        447         522          16506        295   tcp      611151         655203        444     ssl    66.384740  8.334935e+06
28096 00:02:45.920620  192.168.1.125      56689    5.172.34.138        447         506          16309        336   tcp      608558         639202        446     ssl   165.920620  8.262824e+06
28460 00:02:23.709549  192.168.1.125      57002    5.172.34.138        447         469          16359        328   tcp      608336         631468        436     ssl   143.709549  8.180496e+06
26385 00:01:08.363216  192.168.1.125      55173  217.31.111.153        447         783          11475        239   tcp      630568         648260        442     ssl    68.363216  8.095118e+06
29848 00:01:05.301758  192.168.1.125      58222    91.219.28.14        447         506           6598        152   tcp      611151         628643        437     ssl    65.301758  7.728217e+06
33329 00:01:05.182020  192.168.1.125      61298     151.80.84.3        447         506           5918        135   tcp      611151         628283        428     ssl    65.182020  7.658842e+06
31604 00:01:05.181878  192.168.1.125      59773     151.80.84.3        447         506           5638        128   tcp      611151         628283        428     ssl    65.181878  7.652505e+06
819   00:01:57.329889  192.168.1.125      49417   84.42.159.138        443       24618          26454         45   tcp        4215           5691         31     ssl   117.329889  7.260951e+06
1307  00:02:05.574474  192.168.1.125      49574  200.116.206.58        443       24618          26350         43   tcp        4199           5891         42     ssl   125.574474  7.252607e+06
318   00:02:09.694961  192.168.1.125      49258   36.66.107.162        443       24602          26294         42   tcp        4199           6251         51     ssl   129.694961  7.247904e+06
563   00:01:58.684675  192.168.1.125      49336  200.116.206.58        443       24597          26209         40   tcp        4162           5694         38     ssl   118.684675  7.229727e+06
1058  00:01:58.581551  192.168.1.125      49496    203.92.62.46        443       24565          26177         40   tcp        4162           5734         39     ssl   118.581551  7.220770e+06
57    00:02:12.193263  192.168.1.125      49170  190.138.249.45        443       23903          26391         62   tcp       73195          76923         93     ssl   132.193263  7.216881e+06
24688 00:01:08.831043  192.168.1.125      53673  217.31.111.153        447         783           9131        197   tcp      553108         570140        389     ssl    68.831043  7.058565e+06
2591  00:01:14.004751  192.168.1.125      50637    203.92.62.46        447         751           8639        184   tcp      548447         563859        385     ssl    74.004751  6.971373e+06
9436  00:01:10.099220  192.168.1.125      56618    203.92.62.46        447         751           6803        151   tcp      553092         568664        389     ssl    70.099220  6.969538e+06
7799  00:01:12.834688  192.168.1.125      55150    203.92.62.46        447         751           8439        182   tcp      548447         563859        385     ssl    72.834688  6.963646e+06
4557  00:01:12.101060  192.168.1.125      52200    203.92.62.46        447         751           7875        167   tcp      548447         563859        385     ssl    72.101060  6.942838e+06

real	0m9.205s
user	0m4.336s
sys	0m0.915s

```

# Performace
Using the PCA model, ```zeek_anomaly_detector.py``` is capable of training and testing 6.3Million flow lines in 11minutes.




# TODO
- Add categorical data
- filter flows that we don't want to treat
