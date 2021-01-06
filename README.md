# borg-utils

A collection of python scripts and utils for working with borgbackup repositories.

## scripts

* **`borg_cloner.py`** - Clone a set of local borg repos to a remote source, like borgbase.com. Useful when you have a bunch of nodes backing up to an onsite NAS, but then you want to ship the repos offsite. Uses repo locking to prevent race conditions. Beware ransomware, use append only mode. Uses its own config file, see samples.

* **`borg_repo_exporter.py`** - A script that generates prometheus metrics about borg repos. It produces a textfile that can be consumed by the [node-exporter textfile collector](https://github.com/prometheus/node_exporter#textfile-collector). Uses its own config file, see samples.

### Disclaimer

These tools were developed for in house work and work well enough as they are.
They probably will not work out of the box for you.

# License

* (C) 2020 Casey Link. Outskirts Labs.

Made available under the GNU Affero General Public License v3 or later. See [LICENSE](./LICENSE).
