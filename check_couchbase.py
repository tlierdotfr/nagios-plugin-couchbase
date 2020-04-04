#!/usr/bin/env python

"""
Collects statistics from the Couchbase REST API and forwards them to a 3rd party
  monitoring server.

Dependencies
 * python-requests

"""

import argparse
import json
import logging as log
import logging.config
import numbers
import operator
import os
import requests
import sys


# Basic setup
parser = argparse.ArgumentParser(usage="%(prog)s [options] -U user -P password -s service -m metric")
parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", help="Enable debug logging to console")
parser.add_argument("-S", "--ssl",  dest="couchbase_ssl", action="store_true", help="Activate SSL")
parser.add_argument("-C", "--cb-host",  dest="couchbase_host", action="store", help="Couchbase host")
parser.add_argument("-u", "--cb-user", dest="couchbase_user", action="store", help="Couchbase admin username")
parser.add_argument("-p", "--cb-password", dest="couchbase_password", action="store", help="Couchbase admin password")
#parser.add_argument("-P", "--cb-port",  dest="couchbase_port", action="store", help="Couchbase port (default 8091)")
parser.add_argument("-s", "--service", dest="service", action="store", help="Service to analyse (data, query, node, fts, xdcr)")
parser.add_argument("-m", "--metric", dest="metric", action="store", help="Metric to analyse")
parser.add_argument("-b", "--bucket", dest="bucket", action="store", help="Bucket to analyse (for data service)")
parser.add_argument("-d", "--desc", dest="desc", action="store", help="Optionnal human readable description for metric")
parser.add_argument("-w", "--warn", dest="warn", action="store", help="Warning threshold for metric analysis")
parser.add_argument("-c", "--crit", dest="crit", action="store", help="Critical threshold for metric analysis")
parser.add_argument("-o", "--operator", dest="operator", action="store", help="Operator for warn/crit comparaison (default >=)")
args = parser.parse_args()


def main():
    config = load_config()
    results = []

    tasks = couchbase_request(config["couchbase_host"], config["couchbase_admin_port"], "/pools/default/tasks", config)
    pools_default = couchbase_request(config["couchbase_host"], config["couchbase_admin_port"], "/pools/default", config)

    nodes = pools_default["nodes"]

    for node in nodes:
        if "thisNode" not in node:
            continue

        # node is formatted a hostname:port
        host = node["hostname"].split(":")[0]
        services = node["services"]

        # According to service to test
        if config["service"] == "data":
            if "kv" not in services:
                print("Service not available on this node")
                sys.exit(2)
            else:
                results = process_data_stats(host, config["bucket"], config["metric"], config, results)

        elif config["service"] == "xdcr":
            if "kv" not in services:
                print("Service not available on this node")
                sys.exit(2)
            else:
                results = process_xdcr_stats(host, tasks, config["metric"], config, results)

        elif config["service"] == "node":  
            results = process_node_stats(host, node, config["metric"], results)

        elif config["service"] == "n1ql":  
            if "n1ql" not in services:
                print("Service not available on this node")
                sys.exit(2)
            else:
                results = process_query_stats(host, config["metric"], config, results)

        elif config["service"] == "fts":
            if "fts" not in services:
                print("Service not available on this node")
                sys.exit(2)
            else:
                results = process_fts_stats(host, config["metric"], config, results)

        else: 
            print("Service unknown")
            sys.exit(2)

    send_centreon(results, config)


# Attempts to load the configuration file and apply argument overrides
def load_config():

    # Init default conf
    config = {
        "logging": {
            "version": 1,
            "formatters": {
                "simple": {
                    "format": "%(asctime)s %(levelname)s %(message)s"
                }
            } ,
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "ERROR",
                    "formatter": "simple",
                    "stream": "ext://sys.stdout"
                }
            },
            "root": {
                "level": "DEBUG",
                "handlers": ["console"]
            }
        },
        "couchbase_host": "localhost",
        "couchbase_admin_port": 8091,
        "couchbase_admin_port_ssl": 18091,
        "couchbase_query_port": 8093,
        "couchbase_query_port_ssl": 18093,
        "couchbase_fts_port": 8094,
        "couchbase_fts_port_ssl": 18094,
        "couchbase_ssl": False,
        "service": "data",
        "desc": None,
        "crit": None,
        "warn": None,
        "operator": ">="
    }

    if args.couchbase_ssl:
        config["couchbase_ssl"] = args.couchbase_ssl

    if args.couchbase_host:
        config["couchbase_host"] = args.couchbase_host

    if args.couchbase_user:
        config["couchbase_user"] = args.couchbase_user

    if args.couchbase_password:
        config["couchbase_password"] = args.couchbase_password

    if args.bucket:
        config["bucket"] = args.bucket

    if args.service:
        config["service"] = args.service

    if args.metric:
        config["metric"] = args.metric

    if args.desc:
        config["desc"] = args.desc

    if args.warn:
        config["warn"] = args.warn

    if args.crit:
        config["crit"] = args.crit

    if args.operator:
        config["operator"] = args.operator

    if args.verbose:
        config["logging"]["handlers"]["console"]["level"] = "DEBUG"

    # Init logging
    logging.config.dictConfig(config["logging"])

    # Overload default port if SSL enabled
    if config["couchbase_ssl"] is True:
        config["couchbase_admin_port"] = config["couchbase_admin_port_ssl"]
        config["couchbase_query_port"] = config["couchbase_query_port_ssl"]
        config["couchbase_fts_port"] = config["couchbase_fts_port_ssl"]

    # Unrecoverable errors
    for item in ["couchbase_user", "couchbase_password", "metric", "service"]:
        if item not in config:
            log.error("{0} is not set".format(item))
            sys.exit(2)

    # Check that bucket name is set if service is "data"
    if config["service"] == "data":
        for item in ["bucket"]:
            if item not in config:
                log.error("Bucket name is not set")
                sys.exit(2)

    return config


# Validates metric config
def validate_metric(metric, samples):
    if metric is None:
        log.error("Metric name not set")
        return False

    if metric not in samples:
        log.error("Metric does not exist: {0}".format(metric))
        return False


# Formats numbers with a max precision 2 and removes trailing zeros
def pretty_number(f):
    value = str(round(f, 2)).rstrip("0").rstrip(".")

    if "." in value:
        return float(value)
    elif value == "":
        return 0
    else:
        return int(value)


# Averages multiple metric samples to smooth out values
def avg(samples):
    return sum(samples, 0) / len(samples)


# For dynamic comparisons
# Thanks to https://stackoverflow.com/a/18591880
def compare(inp, relate, cut):
    ops = {">": operator.gt,
           "<": operator.lt,
           ">=": operator.ge,
           "<=": operator.le,
           "=": operator.eq}
    return ops[relate](inp, cut)


# Determines metric status based on value and thresholds
def eval_status(value, critical, warning, op):
    try:
        warning = int(warning)
    except:
        warning = warning
    try:
        critical = int(critical)
    except:
        critical = critical

    if isinstance(critical, numbers.Number) and compare(value, op, critical):
        return 2, "CRITICAL"
    elif isinstance(critical, str) and compare(value, op, critical):
        return 2, "CRITICAL"
    elif isinstance(warning, numbers.Number) and compare(value, op, warning):
        return 1, "WARNING"
    elif isinstance(warning, str) and compare(value, op, warning):
        return 1, "WARNING"
    else:
        return 0, "OK"


# Evalutes data service stats and sends check results
def process_data_stats(host, bucket, metric, config, results):
    try:
        s = couchbase_request(host, config["couchbase_admin_port"],  "/pools/default/buckets/{0}/stats".format(bucket), config)
    except ValueError:
        log.error("Request error: Bucket may no exist on this node")
        sys.exit(2)
    except:
        log.error("Request error: {0}".format(sys.exc_info()[0]))
        sys.exit(2)

    stats = s["op"]["samples"]
    
    # Specific "HomeMade" metrics
    #    percent_quota_utilization: mem_used / ep_mem_high_wat
    #    percent_metadata_utilization: ep_meta_data_memory / ep_mem_high_wat
    #    disk_write_queue: ep_queue_size + ep_flusher_todo
    #    total_ops: cmd_get + cmd_set + incr_misses + incr_hits + decr_misses + decr_hits + delete_misses + delete_hits
    if metric == "percent_quota_utilization":
        value = avg(stats["mem_used"]) / (avg(stats["ep_mem_high_wat"]) * 1.0) * 100
    elif metric == "percent_metadata_utilization":
        value = avg(stats["ep_meta_data_memory"]) / (avg(stats["ep_mem_high_wat"]) * 1.0) * 100
    elif metric == "disk_write_queue":
        value = avg(stats["ep_queue_size"]) + avg(stats["ep_flusher_todo"])
    elif metric == "total_ops":
        value = 0
        for op in ["cmd_get", "cmd_set", "incr_misses", "incr_hits", "decr_misses", "decr_hits", "delete_misses", "delete_hits"]:
            value += avg(stats[op])

    # Standard "official" metrics
    else:
        if validate_metric(metric, stats) is False:
            return results
        value = avg(stats[metric])

    results.append({"host": host, "metric": metric, "value": value, "service": bucket})

    return results


# Evaluates XDCR stats and sends check results
def process_xdcr_stats(host, tasks, metric, config, results):
    for task in tasks:
        if task["type"] == "xdcr":
            
            # task["id"] looks like this: {GUID}/{source_bucket}/{destination_bucket}
            label = "xdcr {0}/{1}".format(task["id"].split("/")[1], task["id"].split("/")[2])

            if metric == "status":
                value = task["status"]
                results.append({"host": host, "metric": metric, "value": value, "service": label})
            elif task["status"] in ["running", "paused"]:
                # REST API requires the destination endpoint to be URL encoded.
                destination = requests.utils.quote("replications/{0}/{1}".format(task["id"], metric), safe="")

                uri = "/pools/default/buckets/{0}/stats/{1}".format(task["source"], destination)
                stats = couchbase_request(host, config["couchbase_admin_port"], uri, config)

                for node in stats["nodeStats"]:
                    # node is formatted as host:port
                    if host == node.split(":")[0]:
                        if len(stats["nodeStats"][node]) == 0:
                            log.error("Invalid XDCR metric: {0}".format(metric))
                            continue

                        value = avg(stats["nodeStats"][node])
                        results.append({"host": host, "metric": metric, "value": value, "service": label})

    return results


# Evaluates query service stats and sends check results
def process_query_stats(host, metric, config, results):
    stats = couchbase_request(host, config["couchbase_query_port"],  "/admin/stats", config, "query")

    if validate_metric(metric, stats) is False:
        return results

    value = stats[metric]

    # Convert nanoseconds to milliseconds
    if metric in ["request_timer.75%", "request_timer.95%", "request_timer.99%"]:
        value = value / 1000 / 1000

    results.append({"host": host, "metric": metric, "value": value, "service": "query"})

    return results


# Evaluates FTS service stats and sends check results
def process_fts_stats(host, metric, config, results):
    stats = couchbase_request(host, config["couchbase_fts_port"],  "/api/nsstats", config, "fts")

    value = 0

    # stat name is formatted "bucket:index:metric"
    # we are only concerned about totals across all indexes
    for stat in stats:
        met = stat.split(":")

        if len(metric) != 3 or metric != met[2]:
            continue

        label = "fts {0}:{1}".format(met[0], met[1])
        value = stats[stat]

        results.append({"host": host, "metric": metric, "value": value, "service": label})

    return results


# Evaluates node stats and sends check results
def process_node_stats(host, stats, metric, results):
    
    if validate_metric(metric, stats) is False:
        return results

    value = str(stats[metric])
    results.append({"host": host, "metric": metric, "value": value, "service": "node"})

    return results


# Executes a Couchbase REST API request and returns the output
def couchbase_request(host, port, uri, config, service=None):
    if config["couchbase_ssl"] is True:
        protocol = "https"
    else:
        protocol = "http"

    url = "{0}://{1}:{2}{3}".format(protocol, host, str(port), uri)
    log.info("Request : {0}".format(url))

    try:
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        f = requests.get(url, auth=(config["couchbase_user"], config["couchbase_password"]), verify=False)

        status = f.status_code

        if f.text:
            response = json.loads(f.text)

        # We can provide a helpful error message on 403
        if status == 403:
            if "permissions" in response:
                print("{0}: {1}".format(response["message"], response["permissions"]))

        # Bail if status is anything but successful
        if status != 200:
            f.raise_for_status()

        return response
    except requests.exceptions.HTTPError as e:
        log.error("Failed to complete request to Couchbase: {0}, {1}".format(url, e))
        sys.exit(2)
    except:
        raise


# Sends a centreon check result to stdout
def send_centreon(results, config):
    import subprocess

    for result in results:
        host = result["host"]
        metric = result["metric"]
        value = result["value"]
        service = result["service"]

        if config["operator"] not in [">", ">=", "=", "<=", "<"]:
            log.warning("Skipped metric: \"{0}\", invalid operator: {1}".format(metric, config["operator"]))
            continue

        if isinstance(value, numbers.Number):
            value = pretty_number(value)

        status, status_text = eval_status(value, config["crit"], config["warn"], config["operator"])

        if config["desc"] is not None:
            metric_usr = config["desc"]
        else:
            metric_usr = metric

        message     = "{0} {1}: {2}".format(status_text, metric_usr, value)
        perf_data   = "{0}={1}".format(metric, value)

        if config["warn"] is not None:
            perf_data = "{0};{1}".format(perf_data, config["warn"])
        if config["crit"] is not None:
            perf_data = "{0};{1}".format(perf_data, config["crit"])

        line = "{0} | {1}".format(message, perf_data)

        # Print line and exit according to status
        print(line)
        sys.exit(status)


if __name__ == "__main__":
    main()
