import os
import os.path


def is_borg_repo(path):
    return os.path.isfile(os.path.join(path, "config")) and os.path.isdir(
        os.path.join(path, "data")
    )


def enumerate_repos(path, ignorelist):
    dirs = [f for f in os.listdir(path) if os.path.isdir(os.path.join(path, f))]
    repos = []
    for dir in dirs:
        if dir in ignorelist:
            continue
        repo_path1 = os.path.join(path, dir)
        if is_borg_repo(repo_path1):
            repos.append({"name": dir, "path": repo_path1})
            continue
        repo_path2 = os.path.join(path, dir, dir)
        if is_borg_repo(repo_path2):
            repos.append({"name": dir, "path": repo_path2})
    return repos
