#!/bin/bash
#
# Deploy a hugo generated site!
# @leonjza - 2016

# Build the project.
echo -e "\033[0;32mBuilding the project...\033[0m"
hugo

# Stage the generated site for commit
echo -e "\033[0;32mStaging updates for GitHub...\033[0m"
cd public

# Get latest (if any)
git pull

# Add changes to git.
git add -A

# Commit changes.
msg="Rebuilding Site: `date`"
if [ $# -eq 1 ]
    then msg="$1"
fi
git commit -m "$msg"

echo -e "\033[0;32mDeploying updates to GitHub...\033[0m"
git push origin master
