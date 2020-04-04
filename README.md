# Couchbase Nagios Plugin
A plugin to monitor Couchbase REST APIs and be used as active probe for Nagios/Centreon.

It is intended to be a standalone Nagios/Centreon active probe plugin as well as a reference for how to interact with the Couchbase REST APIs when building plugins for other systems.

## Requirements
* Python requests module
* Python json module
* Python logging module

## Configuration
This plugin is configured to act as active check to Nagios/Centreon via console output Nagios/Centreon pattern. 
The metric to monitor with associated threshold has to be pass as argument.

### Minimum configuration
Make sure the following properties match your environment:
* cb_host
* cb_user
* cb_password
* service
* metric
* bucket (if needed by service)

### Nagios/Centreon services
You must deploy this script onto your poller and create active check with correct parameters for each metric you want to monitor.

## Usage
``` 
usage: check_couchbase.py [options] -U user -P password -s service -m metric

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable debug logging to console
  -S, --ssl             Activate SSL
  -C COUCHBASE_HOST, --cb-host COUCHBASE_HOST
                        Couchbase host (default : locahost)
  -u COUCHBASE_USER, --cb-user COUCHBASE_USER
                        Couchbase ReadOnlyAdmin username
  -p COUCHBASE_PASSWORD, --cb-password COUCHBASE_PASSWORD
                        Couchbase ReadOnlyAdmin password
  -s SERVICE, --service SERVICE
                        Service to analyse (data, query, node, fts, xdcr)
  -m METRIC, --metric METRIC
                        Metric to analyse
  -b BUCKET, --bucket BUCKET
                        Bucket to analyse (for data service)
  -d DESC, --desc DESC  Optionnal human readable description for metric output
  -w WARN, --warn WARN  Warning threshold for metric analysis
  -c CRIT, --crit CRIT  Critical threshold for metric analysis
  -o OPERATOR, --operator OPERATOR
                        Operator for warn/crit comparaison (default >=)
```

This script may be exectuted in local or directly on distant Nagios/Centreon poller.

### Couchbase metrics
Here is a set of best-practice metrics.
It will be necessary to update the metric thresholds to reflect your Couchbase environment.

```
# Global Node Stats
node:
  - metric: status
    description: health status
    warn: warmup
    crit: unhealthy
    op: "="
  - metric: clusterMembership
    description: cluster membership
    warn: inactiveAdded
    crit: inactiveFailed
    op: "="

# Data service
#  Metrics are configurable by bucket.
#  The bucket name is specified by the "bucket" parameter.
#  Metric names are documented here:
#  https://github.com/couchbase/ep-engine/blob/master/docs/stats.org
#
#  The following calculated metrics have been added:
#    percent_quota_utilization: mem_used / ep_mem_high_wat
#    percent_metadata_utilization: ep_meta_data_memory / ep_mem_high_wat
#    disk_write_queue: ep_queue_size + ep_flusher_todo
#    total_ops: cmd_get + cmd_set + incr_misses + incr_hits + decr_misses + decr_hits + delete_misses + delete_hits
data:
    - metric: percent_quota_utilization
      description: percent bucket quota used
      warn: 80
      crit: 90 
    - metric: percent_metadata_utilization
      description: percent bucket quota used by metadata
      warn: 10
      crit: 20
    - metric: disk_write_queue
      description: items in disk write queue
      warn: 10000
      crit: 50000
    - metric: total_ops
      description: total ops per second
      warn: 10000
      crit: 20000
    - metric: cmd_get
      description: gets per second
      warn: 5000
      crit: 10000
    - metric: cmd_set
      description: sets per second
      warn: 5000
      crit: 10000
    - metric: delete_hits
      description: deletes per second
      warn: 500
      crit: 1000
    - metric: ep_cache_miss_rate
      description: cache miss ratio 
      warn: 1
      crit: 10
    - metric: couch_docs_fragmentation
      description: percent data fragmentation
      warn: 35
      crit: 50
    - metric: couch_views_fragmentation
      description: percent views fragmentation
      warn: 35
      crit: 50
    - metric: curr_connections
      description: client connections
      warn: 500
      crit: 1000  # Backoffs are sent at 10,0000 
    - metric: ep_dcp_replica_items_remaining
      description: items in internal replication queue
      warn: 2500
      crit: 5000
    - metric: ep_dcp_2i_items_remaining
      description: items in 2i indexer queue
      warn: 5000
      crit: 10000
    - metric: ep_dcp_views_items_remaining
      description: items in views indexer queue
      warn: 5000
      crit: 10000
    - metric: ep_dcp_replica_backoff
      description: internal replication backoffs
      crit: 1
    - metric: ep_dcp_xdcr_backoff
      description: XDCR backoffs
      crit: 1
    - metric: vb_avg_total_queue_age
      description: disk write queue average age
      warn: 5
      crit: 10
    - metric: ep_oom_errors
      description: out of memory errors
      crit: 1
    - metric: ep_tmp_oom_errors
      description: temporary out of memory errors
      crit: 1
    - metric: vb_active_resident_items_ratio
      description: percent active items in memory
      warn: 50
      crit: 15  # Should never be less than 15%
      op: "<"
    - metric: vb_replica_resident_items_ratio
      description: percent replica items in memory
      warn: 50
      crit: 15  # Should never be less than 15%
      op: "<"

# Query service
#  All metric names documented here (under Vitals):
#  https://developer.couchbase.com/documentation/server/current/tools/query-monitoring.html
query:
  - metric: request_timer.75%
    description: 75th percentile query response time
    warn: 100  # Milliseconds
    crit: 200  # Milliseconds
  - metric: request_timer.95%
    description: 95th percentile query response time
    warn: 200  # Milliseconds
    crit: 300  # Milliseconds
  - metric: request_timer.99%
    description: 99th percentile query response time
    warn: 400  # Milliseconds
    crit: 500  # Milliseconds
  - metric: active_requests.count
    description: active N1QL requests
    warn: 1000
    crit: 1500
  - metric: request_rate.1m.rate
    description: query throughput 1 minute
    warn: 900
    crit: 950
  - metric: request_rate.5m.rate
    description: query throughput 5 minute
    warn: 800
    crit: 850
  - metric: request_rate.15m.rate
    description: query throughput 15 minute
    warn: 700
    crit: 750

# Full Text Search (FTS) service
#  All metric names documented here (under Vitals):
#  https://developer.couchbase.com/documentation/server/current/rest-api/rest-fts-indexing.html#topic_hpd_2y4_1v__g-api-stats
#
#  Note that these metrics will be applied to each FTS index independently
fts:
  - metric: num_mutations_to_index
    description: items in FTS indexer queue
    warn: 2000
    crit: 5000
#  - metric: total_queries_slow  # commented until a rate metric is available
#    description: FTS slow searches  # queries that take longer than 5 seconds 
#    warn: 100
#    crit: 1000
#  - metric: total_queries_timeout
#    description: FTS search timeouts # commented until a rate metric is available
#    warn: 100
#    crit: 1000
#  - metric: total_queries_error # commented until a rate metric is available
#    description: FTS search errors 
#    warn: 100
#    crit: 1000

# XDCR
#  All metric names documented here:
#  https://developer.couchbase.com/documentation/server/current/rest-api/rest-xdcr-statistics.html
#
#  Note that these metrics will be applied to each XDCR replication independently
xdcr:
  - metric: status
    description: replication status
    warn: paused
    crit: notRunning
    op: "="
  - metric: changes_left
    description: documents pending replication
    warn: 2500
    crit: 5000
  - metric: bandwidth_usage
    description: bytes replicated per second
    warn: 12500000  # 100 Mbps
    crit: 25000000  # 200 Mbps

```
