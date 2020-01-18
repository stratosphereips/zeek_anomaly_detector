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
Simple Anomaly Detector for Zeek conn.log files. Version: 0.2
Author: Sebastian Garcia (eldraco@gmail.com), Veronica Valeros (vero.valeros@gmail.com)

Flows of the top anomalies
           id.orig_h  id.orig_p       id.resp_h  id.resp_p proto service        duration  orig_bytes  resp_bytes  orig_pkts  orig_ip_bytes  resp_pkts  resp_ip_bytes  durationsec         score
24482  192.168.1.125      53510   87.236.19.168         80   tcp    http 00:05:33.102728         108     2455407        593          23852       1686        2524319   333.102728  3.091147e+07
109    192.168.1.125      49188  201.232.32.124        443   tcp     ssl 00:02:08.617586       79809        2544         78          84351         55           4828   128.617586  2.377891e+07
35031  192.168.1.125      62788  192.157.238.15        447   tcp     ssl 00:01:06.384740         522      611151        295          16506        444         655203    66.384740  8.334937e+06
28096  192.168.1.125      56689    5.172.34.138        447   tcp     ssl 00:02:45.920620         506      608558        336          16309        446         639202   165.920620  8.262826e+06
28460  192.168.1.125      57002    5.172.34.138        447   tcp     ssl 00:02:23.709549         469      608336        328          16359        436         631468   143.709549  8.180498e+06
26385  192.168.1.125      55173  217.31.111.153        447   tcp     ssl 00:01:08.363216         783      630568        239          11475        442         648260    68.363216  8.095119e+06
29848  192.168.1.125      58222    91.219.28.14        447   tcp     ssl 00:01:05.301758         506      611151        152           6598        437         628643    65.301758  7.728219e+06
33329  192.168.1.125      61298     151.80.84.3        447   tcp     ssl 00:01:05.182020         506      611151        135           5918        428         628283    65.182020  7.658844e+06
31604  192.168.1.125      59773     151.80.84.3        447   tcp     ssl 00:01:05.181878         506      611151        128           5638        428         628283    65.181878  7.652506e+06
819    192.168.1.125      49417   84.42.159.138        443   tcp     ssl 00:01:57.329889       24618        4215         45          26454         31           5691   117.329889  7.261139e+06
1307   192.168.1.125      49574  200.116.206.58        443   tcp     ssl 00:02:05.574474       24618        4199         43          26350         42           5891   125.574474  7.252795e+06
318    192.168.1.125      49258   36.66.107.162        443   tcp     ssl 00:02:09.694961       24602        4199         42          26294         51           6251   129.694961  7.248093e+06
563    192.168.1.125      49336  200.116.206.58        443   tcp     ssl 00:01:58.684675       24597        4162         40          26209         38           5694   118.684675  7.229915e+06
1058   192.168.1.125      49496    203.92.62.46        443   tcp     ssl 00:01:58.581551       24565        4162         40          26177         39           5734   118.581551  7.220959e+06
57     192.168.1.125      49170  190.138.249.45        443   tcp     ssl 00:02:12.193263       23903       73195         62          26391         93          76923   132.193263  7.217059e+06
24688  192.168.1.125      53673  217.31.111.153        447   tcp     ssl 00:01:08.831043         783      553108        197           9131        389         570140    68.831043  7.058567e+06
2591   192.168.1.125      50637    203.92.62.46        447   tcp     ssl 00:01:14.004751         751      548447        184           8639        385         563859    74.004751  6.971375e+06
9436   192.168.1.125      56618    203.92.62.46        447   tcp     ssl 00:01:10.099220         751      553092        151           6803        389         568664    70.099220  6.969540e+06
7799   192.168.1.125      55150    203.92.62.46        447   tcp     ssl 00:01:12.834688         751      548447        182           8439        385         563859    72.834688  6.963647e+06
4557   192.168.1.125      52200    203.92.62.46        447   tcp     ssl 00:01:12.101060         751      548447        167           7875        385         563859    72.101060  6.942839e+06

real	0m4.972s
user	0m3.540s
sys	0m0.581s
```

# Performace
Using the PCA model, ```zeek_anomaly_detector.py``` is capable of training and testing 6.3Million flow lines in 11minutes.




# TODO
- Add categorical data
- filter flows that we don't want to treat
