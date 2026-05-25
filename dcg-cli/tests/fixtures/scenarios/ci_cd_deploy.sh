#!/usr/bin/env bash
# CI/CD deployment workflow with destructive and safe operations.
set -euo pipefail

circleci config validate .circleci/config.yml
circleci pipeline list org/my-org/project/app

# Jenkins safe reads
java -jar jenkins-cli.jar -s http://jenkins.local/ list-jobs
java -jar jenkins-cli.jar -s http://jenkins.local/ get-job deploy-prod

# GitLab CI status checks
curl -X GET 'https://gitlab.example.com/api/v4/projects/42/pipelines'

# Deployment sync (destructive if --delete)
aws s3 sync build/ s3://my-bucket/web --delete
rclone sync build/ remote:important-bucket --delete-after

# Clean up old pipelines/jobs (destructive)
curl -X DELETE 'https://gitlab.example.com/api/v4/projects/42/pipelines/1001'
java -jar jenkins-cli.jar -s http://jenkins.local/ delete-job deploy-staging
