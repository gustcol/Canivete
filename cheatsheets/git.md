# Git Cheatsheet

> Powerful but confusing.

## Archive

```sh
git archive --format=tar --prefix=foo_bar-1.0/ v1.0 | xz > foo_bar-1.1.tar.xz
```

## Branching

### Always Collapse to Single Commit
```sh
git checkout --orphan $TEMP_BRANCH
git add -A
git commit -am "Initial commit"
git branch -D master
git branch -m master
git push --force origin master
```

### Delete Remote Branch
```sh
git push origin --delete the_remote_branch
```
```sh
git push origin :the_remote_branch
```

## Changing Author Info

### Last Commit
```sh
git commit --amend --author="John Doe <john@doe.org>"
```

## Single Older Commit
This uses interactive rebase.
```sh
# Identify the commit before the one you want to change and start rebase.
git rebase -i -p 8294ad8

# In the editor window that opens, identify all commits you want to change and 
change "pick" to "edit".

# Change author name
git commit --amend --author="John Doe <john@doe.org>" --no-edit

# Continue rebase
git rebase --continue
```

### Whole Repository
Change `OLD_EMAIL`, `CORRECT_NAME` and `CORRECT_EMAIL` to desired values, afterwards run `git push --force --tags origin 'refs/heads/*'`.
```sh
git filter-branch --env-filter '
OLD_EMAIL="your-old-email@example.com"
CORRECT_NAME="Your Correct Name"
CORRECT_EMAIL="your-correct-email@example.com"
if [ "$GIT_COMMITTER_EMAIL" = "$OLD_EMAIL" ]
then
    export GIT_COMMITTER_NAME="$CORRECT_NAME"
    export GIT_COMMITTER_EMAIL="$CORRECT_EMAIL"
fi
if [ "$GIT_AUTHOR_EMAIL" = "$OLD_EMAIL" ]
then
    export GIT_AUTHOR_NAME="$CORRECT_NAME"
    export GIT_AUTHOR_EMAIL="$CORRECT_EMAIL"
fi
' --tag-name-filter cat -- --branches --tags
```

## Committing

### Commit Part of File
```sh
git add --patch /path/to/file
```

## Submodules

### Update all Submodules
```sh
git submodule update --recursive --remote
```

## Tags

```sh
git tag v1.0
git push origin v1.0
```

## Rebasing

### Squash Several Commits Into a Single Commit

```sh
git checkout squashed_feature
git rebase -i development
```

Squash all commits but the first.

```
pick fda59df commit 1
squash x536897 commit 2
squash c01a668 commit 3
```

Write a proper commit message, probably with a Jira ticket number or the like.

Checkout development branch and merge squashed feature branch.

```sh
git checkout development
git merge squashed_feature
```

Newer Git allows you to do the squash merge in one step if you use feature 
branches:

```sh
git merge --squash squashed_feature
```

## Undo Changes

### Undo Working Copy Modifications of One File
You can do it without the `--`, but if the filename looks like a branch or tag 
(or other revision identifier), it may get confused, so using -- is best.
```sh
git checkout -- file
```
([Source](https://stackoverflow.com/a/692329/1377323))

## Settings

### Show Staging Diff in Commit Message
```sh
git config --global commit.verbose true
```
