# Veraison components - contribution guidelines

Contributions to this project are welcome. We request that you read through
the guidelines before getting started.

## Contributor License Agreement

Your contribution is accepted under the [Apache 2.0 license](LICENSE).

## Community guidelines

Get acquainted with our [code of conduct](CODE_OF_CONDUCT.md) that contains our
community guidelines.

## Contribution

### Code quality

As a contributor, make sure that you follow the golang coding standards and
conventions established in:

* [Effective Go](https://golang.org/doc/effective_go.html), and
* [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

### Code reviews

All submissions will be reviewed before merging. Submissions are reviewed
using
[GitHub pull requests](https://help.github.com/articles/about-pull-requests/).

Please make sure before you submit a pull request that a corresponding
[Github issue](https://docs.github.com/en/free-pro-team@latest/github/managing-your-work-on-github/about-issues)
exists where the problem you are trying to solve and any implementation approach can be discussed.

Also, remember to
[link](https://docs.github.com/en/free-pro-team@latest/github/managing-your-work-on-github/linking-a-pull-request-to-an-issue)
your pull request to the corresponding issue.

## Source and build

### Running tests

Run the tests with:

```shell
make test
```

### Presubmit checks

Before pushing your local branch, please run the presubmit checks, making
sure that the coverage figures have not degraded and that the linter is still
happy:

```shell
make presubmit
```

## Documentation

User documentation for this project is inlined in the source files. Make sure
that any piece of functionality that is added, deleted or modified by your
contribution is reflected in the appropriate places:

* Verification package description: [`verification/doc.go`](verification/doc.go)
* Provisioning package description: [`provisioning/doc.go`](provisioning/doc.go)
* Package methods, global variables & constants: the relevant source file
