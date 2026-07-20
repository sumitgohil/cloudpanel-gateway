# Local CloudPanel Gateway test lab

The local test lab creates a disposable full Ubuntu 24.04 VM, installs
CloudPanel, creates a generated CloudPanel administrator, builds the Gateway
from the current committed checkout, and configures a private Gateway domain.
It is for local evaluation and contributor testing, not public hosting.

## Prerequisites

- Git and Bash (Git Bash or WSL is suitable on Windows).
- Vagrant 2.4 or later.
- VirtualBox 7.x. VMware or Parallels can be selected with
  `CPGW_PROVIDER=<provider>` when their compatible Vagrant provider is
  installed.
- At least 8 GiB host memory and 25 GiB free disk space.

Vagrant uses the pinned, architecture-aware `bento/ubuntu-24.04` box. The
default VirtualBox provider supports both `amd64` and `arm64` box metadata.

## Start and access

From a clean committed checkout, run:

```bash
./scripts/test-lab up
```

The first run downloads the base VM, CloudPanel dependencies, and the pinned
Go toolchain, so it can take several minutes. The launcher prints a JSON
credential record followed by the required host entry. It never edits the host
file automatically.

Add this line to your host file with administrator rights:

```text
192.168.56.56 gateway.cpgw.test
```

- macOS and Linux: `/etc/hosts`
- Windows: `%SystemRoot%\System32\drivers\etc\hosts`

Then open CloudPanel at `https://192.168.56.56:8443`. The local CloudPanel and
Gateway certificates are not publicly trusted, so the browser warning is
expected. Use `https://gateway.cpgw.test/mcp` for the local MCP endpoint after
adding the host entry. Let’s Encrypt is intentionally not requested because
this private test domain has no public DNS.

## Lifecycle and safety

```bash
./scripts/test-lab info
./scripts/test-lab hosts
./scripts/test-lab verify
./scripts/test-lab provision
./scripts/test-lab ssh
./scripts/test-lab destroy
```

`up` and `provision` package only the checked-out Git `HEAD`; untracked files,
working-tree modifications, `.git`, and local credentials are excluded. Commit
or stash tracked changes before provisioning. Generated credentials are held
only in the VM at `/root/cloudpanel-gateway-test-lab/access.json` with mode
`0600`; `info` reads that file through Vagrant SSH and displays it locally.

Dangerous Gateway policies remain disabled. Enable an individual policy inside
the VM only when deliberately testing it.
