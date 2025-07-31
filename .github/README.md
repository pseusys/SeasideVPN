# Scripts and Actions

CI/CD actions of SeasideVPN repository are described below.

## Test Server

After every release publication, the Caerulean Whirlpool server is automatically deployed to a test server.
Before publication, the server is reset using VPS API.
Currently, there are only two deployment options:

1. [Beget](https://beget.com/en), legacy.
2. [ServaOne](https://serva.one/), actual, here's a [referral link](https://serva.one/?ref=9622).

Server is deployed automatically, but no sensitive information is shown in GitHub Actions log.
In order to use the server, use SSH (it is not blocked by Whirlpool):

Run this command to connect to your server and get deployment information (without knowing the keys, generated in the environment file, it will be impossible to use the server API):

```shell
ssh [SERVER_USER]@[SERVER_IP]
...
cat ./conf.env
```

Run this command to download the certificates (without client certificates it will be impossible to use the server API):

```shell
scp -r [SERVER_USER]@[SERVER_IP]:~/certificates [LOCAL_CERTIFICATE_PATH]
```

Finally, run this command to add an admin user (for a year) to the test server (Viridian Algae should be installed with extra `client`):

```shell
export SEASIDE_CERTIFICATE_PATH=[LOCAL_CERTIFICATE_PATH]/viridian
poetry poe fixture -a [SERVER_IP] -k "[WHIRLPOOL_OWNER_KEY]" supply-viridian -i "[UNIQUE_ADMIN_ID]" -n "[ADMIN_COMMON_NAME]" -d 365
```

> These commands can be stored in a shell script in the current directory called `manage-test-server.sh`, and it will be automatically ignored bu git.
