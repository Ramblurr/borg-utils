#!/usr/local/bin/python3.7
import os
import time
import subprocess
import logging
import json
import configparser
import logging
import socket
from datetime import datetime
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily
from prometheus_client import CollectorRegistry, Gauge, write_to_textfile, Counter
from prometheus_client import start_http_server

from borg_util import is_borg_repo, enumerate_repos


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s"
)


class BorgCollector(object):
    def __init__(self, gauges, registry, passphrase, path, ignorelist=[], prefix=""):
        self.registry = registry
        self.passphrase = passphrase
        self.path = path
        self.ignorelist = ignorelist
        self.do_extract = False
        self.prefix = prefix
        self.gauges = gauges

    def make_env(self):
        borg_env = os.environ.copy()
        borg_env["BORG_PASSPHRASE"] = self.passphrase
        borg_env["LANG"] = "en_US.UTF-8"
        borg_env["LC_CTYPE"] = "en_US.UTF-8"
        return borg_env

    def borg(self, args):
        args = ["borg",] + args
        return subprocess.check_output(args, env=self.make_env())

    def borg_json(self, args):
        return json.loads(self.borg(args))

    def collect_repo(self, repo):
        last_out = self.borg_json(["list", "--json", "--last", "1", repo["path"]])
        archives_out = self.borg_json(["list", "--json", repo["path"]])

        if len(last_out["archives"]) == 0:
            return [["borg_last_archive_timestamp", 0], ["borg_archives_count", 0]]
        else:
            last_archive = last_out["archives"][0]
            last_archive_date = datetime.fromisoformat(last_archive["start"])
            diff = datetime.utcnow() - last_archive_date
            repo_archive = repo["path"] + "::" + last_archive["name"]

            last_info_out = self.borg_json(["info", "--json", repo_archive])
            num_files = last_info_out["archives"][0]["stats"]["nfiles"]
            last_orig_size = last_info_out["archives"][0]["stats"]["original_size"]
            last_compressed_size = last_info_out["archives"][0]["stats"][
                "compressed_size"
            ]
            last_dedup_size = last_info_out["archives"][0]["stats"]["deduplicated_size"]
            chunks_unique = last_info_out["cache"]["stats"]["total_unique_chunks"]
            chunks_total = last_info_out["cache"]["stats"]["total_chunks"]
            total_size = last_info_out["cache"]["stats"]["total_size"]
            total_compressed_size = last_info_out["cache"]["stats"]["total_csize"]
            total_dedup_size = last_info_out["cache"]["stats"]["unique_csize"]

            if self.do_extract:
                extract_rc = subprocess.call(
                    ["borg", "extract", "--dry-run", repo_archive], env=self.make_env()
                )
            else:
                extract_rc = -1

            return [
                ["borg_last_archive_timestamp", last_archive_date.timestamp()],
                ["borg_last_archive_hours_ago", diff.total_seconds() / 3600],
                ["borg_archives_count", len(archives_out["archives"])],
                ["borg_files_count", num_files],
                ["borg_chunks_unique", chunks_unique],
                ["borg_chunks_total", chunks_total],
                ["borg_extract_exit_code", extract_rc],
                ["borg_last_size_original_bytes", last_orig_size],
                ["borg_last_size_compressed_bytes", last_compressed_size],
                ["borg_last_size_dedup_bytes", last_dedup_size],
                ["borg_total_size_bytes", total_size],
                ["borg_total_size_compressed_bytes", total_compressed_size],
                ["borg_total_size_dedup_bytes", total_dedup_size],
            ]

    def gauge(self, name):
        if name not in self.gauges:
            self.gauges[name] = Gauge(name, name, ["instance"], registry=self.registry)
        return self.gauges[name]

    def collect(self):
        local_repos = enumerate_repos(self.path, self.ignorelist)
        for repo in local_repos:
            logging.info(f"collecting {repo}")
            label_instance = self.prefix + repo["name"]
            try:
                stats = self.collect_repo(repo)
                for name, value in stats:
                    g1 = self.gauge(name)
                    g1.labels(label_instance).set(value)
            except subprocess.CalledProcessError as e:
                logging.error(f"failed collecting {repo}")
                logging.error(e)
        logging.info("collected %d", len(local_repos))


def parse_config():
    registry = CollectorRegistry()
    config = configparser.ConfigParser()
    config.read_file(
        open(
            os.environ.get(
                "BORG_REPO_EXPORTER_CONFIG_PATH",
                "/usr/local/etc/borg_repo_exporter/config.conf",
            )
        )
    )
    output_path = config.get(
        "borg_repo_exporter",
        "output_path",
        fallback="/var/tmp/node_exporter/borg_repo_exporter.prom",
    )
    instance = config.get(
        "borg_repo_exporter", "instance", fallback=socket.gethostname()
    )

    collectors = []
    gauges = {}
    for section in config.sections():
        if section == "borg_repo_exporter":
            continue
        c = config[section]
        passphrase = c["passphrase"]
        path = c["path"]
        ignorelist = c.get("ignorelist", "").split(",")
        prefix = c.get("prefix", "")
        collectors.append(
            BorgCollector(gauges, registry, passphrase, path, ignorelist, prefix)
        )
    return {
        "collectors": collectors,
        "output_path": output_path,
        "registry": registry,
        "instance": instance,
    }


def main():
    config = parse_config()
    for c in config["collectors"]:
        c.collect()
    g = Gauge(
        "borg_exporter_last_run_timestamp",
        "",
        ["instance"],
        registry=config["registry"],
    )
    g.labels(config["instance"]).set_to_current_time()
    write_to_textfile(config["output_path"], config["registry"])


if __name__ == "__main__":
    main()
