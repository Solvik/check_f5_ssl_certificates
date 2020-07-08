# check_f5_ssl_monitoring


This script lets you monitor the expiration date of all certificates in a F5 BigIP appliance


# Usage

```
$ CHECK_F5_SSL_MONITORING_F5__IP=<host> CHECK_F5_SSL_MONITORING_F5__USER=<user> CHECK_F5_SSL_MONITORING_F5__PASSWORD=<password> ./check_f5_ssl_monitoring.py -w <warning threshold in days> -c <critical threshold in days>
```

You can also pass the following variable `LOGLEVEL=debug` to have more details
