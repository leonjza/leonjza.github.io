#!/bin/bash
#
# Deploy a hugo generated site!
# @leonjza - 2016

set -e

echo -e "\033[0;32mdid you rememner to run pngcrush on new images?\033[0m"
echo -e "sleeping for 5 s"
sleep 5

# Update local source with remote
echo -e "\033[0;32mUpdating local copy of project sources..\033[0m"
git pull --no-rebase origin source

# Add local changes
echo -e "\033[0;32mStaging source update for Github...\033[0m"
git add -A
git commit -m 'Updating Blog Source'

echo -e "\033[0;32mDeploying source to Github...\033[0m"
git push origin source

# Build the project.
echo -e "\033[0;32mBuilding the project...\033[0m"
hugo

# Stage the generated site for commit
echo -e "\033[0;32mStaging updates for GitHub...\033[0m"
cd public

# Get latest (if any) and new local changes
git pull --no-rebase
git add -A

# Commit changes.
msg="Rebuilding Site: `date`"
if [ $# -eq 1 ]
    then msg="$1"
fi
git commit -m "$msg"

echo -e "\033[0;32mDeploying updates to GitHub...\033[0m"
git push origin master
