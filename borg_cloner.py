import sys
import os
import os.path
import subprocess
import logging
import configparser

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)-8s %(message)s"
)

from borgbase_api_client.client import GraphQLClient
from borgbase_api_client.mutations import *

from borg_util import is_borg_repo, enumerate_repos


def bb_list_repos(client):
    """
    Get a list of repos
    :param client: borgbase graphql client
    :returns: returns a list of repositories
    """
    query = """
    {
      repoList {
        id
        name
      }
    }
    """

    res = client.execute(query)
    return res["data"]["repoList"]


def bb_repo(client, name):
    """
    Given a repository name, see if a repository with this name already exists.
    :param client: borgbase graphql client
    :param name: the name to search for
    :returns: returns the repository info
    """
    query = """
    {
      repoList {
        id
        name
        repoPath
        id
        quota
        quotaEnabled
        lastModified
        currentUsage
        rsyncKeys
        alertDays
      }
    }
    """

    res = client.execute(query)
    for repo in res["data"]["repoList"]:
        if repo["name"] == name:
            return repo

    return None


def bb_create_repo(bb, name):
    """
    Creates and configures a repo
    :param client: borgbase graphql client
    :param name: the name of the repo to create
    :returns: returns the repository path
    """
    new_repo_vars = {
        "name": name,
        "quotaEnabled": False,
        "appendOnlyKeys": [],
        "region": "eu",
        "alertDays": bb["bb_alert_days"],
        "rsyncKeys": [bb["bb_rsync_key_id"]],
    }

    REPO_ADD2 = """
    mutation repoAdd(
      $name: String
      $quota: Int
      $quotaEnabled: Boolean
      $appendOnlyKeys: [String]
      $fullAccessKeys: [String]
      $rsyncKeys: [String]
      $alertDays: Int
      $region: String
      $borgVersion: String
      ) {
        repoAdd(
          name: $name
          quota: $quota
          quotaEnabled: $quotaEnabled
          appendOnlyKeys: $appendOnlyKeys
          fullAccessKeys: $fullAccessKeys
          rsyncKeys: $rsyncKeys
          alertDays: $alertDays
          region: $region
          borgVersion: $borgVersion
        ) {
          repoAdded {
            id
            name
            region
            repoPath
          }
        }
    }
    """

    res = bb["client"].execute(REPO_ADD2, new_repo_vars)
    new_repo_path = res["data"]["repoAdd"]["repoAdded"]["repoPath"]
    return new_repo_path


def bb_update_settings(bb, name, repo):
    """
    Updates the settings for a repo
    :param client: borgbase graphql client
    :param name: the name of the repo to create
    :param repo: the repo data
    :returns: returns the repo info
    """
    repo_id = repo["id"]
    repo_vars = {
        "id": repo_id,
        "alertDays": bb["bb_alert_days"],
        "rsyncKeys": [bb["bb_rsync_key_id"]],
    }

    REPO_EDIT = """
    mutation repoEdit(
      $id: String!
      $name: String
      $quota: Int
      $quotaEnabled: Boolean
      $appendOnlyKeys: [String]
      $rsyncKeys: [String]
      $fullAccessKeys: [String]
      $alertDays: Int
      $borgVersion: String
      $region: String
      ) {
        repoEdit(
          id: $id
          name: $name
          quota: $quota
          quotaEnabled: $quotaEnabled
          appendOnlyKeys: $appendOnlyKeys
          fullAccessKeys: $fullAccessKeys
          rsyncKeys: $rsyncKeys
          alertDays: $alertDays
          borgVersion: $borgVersion
          region: $region
        ) {
          repoEdited {
            id
            name
            region
            repoPath
          }
        }
    }
    """

    logging.debug(repo_vars)
    res = bb["client"].execute(REPO_EDIT, repo_vars)
    logging.debug(res)
    if "errors" in res and len(res["errors"]) > 0:
        logging.error(f"Failed to update settings for {name}")
        logging.error(res["errors"])
        sys.exit(1)
    return res["data"]


def ensure_remote_repos(bb, prefix, local_repos):
    remote_repos = []
    for local in local_repos:
        name = local["name"]
        remote_repo_name = f"{prefix}{name}"
        remote_repo = bb_repo(bb["client"], remote_repo_name)
        if remote_repo is None:
            logging.info(f"creating borgbase repo {remote_repo_name}")
            bb_create_repo(bb, remote_repo_name)
        else:
            logging.info(f"ensuring borgbase repo settings {remote_repo_name}")
            bb_update_settings(bb, remote_repo_name, remote_repo)

        remote_repo_path = remote_repo["repoPath"]
        if remote_repo_path is None:
            logging.error("Remote borgbase repo not found: %s", remote_repo_name)
            continue
        local["remote_name"] = remote_repo_name
        local["remote_repo_path"] = remote_repo_path
        remote_repos.append(local)
    return remote_repos


def rsync_repo(identity_file, local_repo, remote_repo_no_path):

    if local_repo is None or len(local_repo) == 0:
        logging.error("Local repo path is blank!")
        sys.exit(1)

    if not is_borg_repo(local_repo):
        logging.error("Local repo path is not a borg repo!")
        sys.exit(1)

    stat_info = os.stat(local_repo)
    uid = stat_info.st_uid
    gid = stat_info.st_gid

    rsync_local_path = f"{local_repo}/"
    args = [
        "borg",
        "--lock-wait",
        "3600",
        "with-lock",
        local_repo,
        "rsync",
        "-Paz",
        "--delete-after",
        "--stats",
        "-i",
        identity_file,
        # "--dry-run",
        rsync_local_path,
        remote_repo_no_path,
    ]
    logging.debug(f"args: {args}")
    process = subprocess.Popen(args, stdout=subprocess.PIPE, universal_newlines=True)
    logs = ""
    logging.info(f"rsyncing {local_repo} to {remote_repo_no_path}")
    while True:
        output = process.stdout.readline()
        if len(output) > 0:
            logs = logs + output
        # Do something else
        rc = process.poll()
        if rc is not None:
            for output in process.stdout.readlines():
                logs = logs + output
            if rc != 0:
                logging.error(f"rsync failed: {args}")
                logging.error("\n" + logs)
            break
    args = ["chown", "-R", f"{uid}:{gid}", local_repo]
    logging.debug(f"chowning {args}")
    subprocess.check_call(args)


def tofu_repo(host):
    bash = subprocess.check_output(["/usr/bin/which", "bash"]).strip()
    logging.debug(f"found bash at {bash}")
    script = f"""
    if ! ssh-keygen -F {host}; then
      ssh-keyscan {host}>> ~/.ssh/known_hosts
      exit 255
    fi"""
    try:
        out = subprocess.check_output(script, shell=True, executable=bash)
        logging.debug(out)
    except subprocess.CalledProcessError as err:
        if err.returncode != 255:
            raise err


def rsync_repos(ssh_key_path, repos):
    for repo in repos:
        local_repo = repo["path"]
        remote_repo_path = repo["remote_repo_path"]
        rpath = repo["remote_repo_path"]
        remote_repo_no_path = rpath[0 : rpath.rfind(":") + 1]
        host = remote_repo_no_path[remote_repo_no_path.rfind("@") + 1 : -1]
        tofu_repo(host)
        rsync_repo(ssh_key_path, local_repo, remote_repo_no_path)


def clone_repos(bb, prefix, ssh_key_path, path, ignorelist):
    local_repos = enumerate_repos(path, ignorelist)
    remote_repos = ensure_remote_repos(bb, prefix, local_repos)
    rsync_repos(ssh_key_path, remote_repos)


def parse_config():
    config = configparser.ConfigParser()
    config.read_file(
        open(
            os.environ.get(
                "BORG_CLONER_CONFIG_PATH", "/usr/local/etc/borg_cloner/config.conf",
            )
        )
    )
    namespaces = []
    borgbase = {
        "bb_token": config.get("borgbase", "bb_token"),
        "bb_rsync_key_id": config.get("borgbase", "bb_rsync_key_id"),
        "bb_alert_days": config.get("borgbase", "bb_alert_days"),
    }
    borgbase["client"] = GraphQLClient(borgbase["bb_token"])
    for section in config.sections():
        if section in ["borgbase", "borg_cloner"]:
            continue
        c = config[section]
        prefix = c["prefix"]
        path = c["path"]
        ssh_key_path = c["ssh_key_path"]
        ignorelist = c.get("ignorelist", "").split(",")
        namespaces.append(
            {
                "prefix": prefix,
                "path": path,
                "ssh_key_path": ssh_key_path,
                "ignorelist": ignorelist,
            }
        )
    return {"borgbase": borgbase, "namespaces": namespaces}


def main():
    config = parse_config()
    for c in config["namespaces"]:
        clone_repos(config["borgbase"], **c)


if __name__ == "__main__":
    main()
