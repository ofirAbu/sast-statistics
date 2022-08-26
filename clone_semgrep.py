import git


def clone_semgrep() -> None:
    git.Repo.clone_from("https://github.com/returntocorp/semgrep-rules.git", './semgrep')

if __name__ == '__main__':
    clone_semgrep()