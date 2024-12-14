# Contributing to SeasideVPN

## Releasing

The script `bump-version.sh` should be used to update version everywhere.
Then, instead of doing releases manually, a new tag should be pushed instead.
It can be done with the following command:

```shell
git tag NEW_VERSON main && git push origin tag NEW_VERSION
```

The new release will be automatically built and deployed.

> NB! Version names should follow [semantic versioning](https://semver.org/) conception.
