# ci_pipeline_conftest_grace_period
Implementation of CI pipeline conftest with grace period.

## SnykCLI scan with option to generate json output.
perform SnykCLI scan with option to generate json output:
* --json-file-output
### sample
> snyk test --org=${orgId} ./nodejs-goof/ --json-file-output=./snyk-scan-nodejs-goof_20231224.json || true

## Print the details of issues that are still within "grace period".
pipe the snyk scan json output to conftest with options:
* --fail-on-warn
* --no-fail
* --policy
  * specify the policy file
### sample
> cat ./samples/snyk-scan-nodejs-goof_20231224.json | conftest test --fail-on-warn --no-fail --policy=./snyk_ci_grace_period/issues_within_grace_period.rego -

## Print the summary stats of issues that are over "grace period".
pipe the snyk scan json output to conftest with options:

* --fail-on-warn
* --policy
  * specify the policy file
## sample
> cat ./samples/snyk-scan-nodejs-goof_20231224.json | conftest test --fail-on-warn --policy=./snyk_ci_grace_period/issues_over_grace_period.rego -

***

<img width="1186" alt="Screenshot 2023-12-25 at 10 39 07" src="https://github.com/lmaeda/ci_pipeline_conftest_grace_period/assets/93645043/ac6940a0-96a3-4f89-a179-178f1e87b8c6">
