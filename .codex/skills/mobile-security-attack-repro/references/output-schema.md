# Attack package output schema

## Directory

Use a descriptive Chinese directory name, for example:

```text
03-客户端首页内容篡改攻击/
├── 攻击复现说明.md
├── run_<attack>_attack.sh
├── scripts/
├── artifacts/
├── evidence/
└── keys/                 # test-only material; never put passwords in files
```

`artifacts/`, `evidence/`, and `keys/` are created only when needed. Historical artifacts must be labeled as such; the report must identify one final tested artifact.

## Main script contract

The main script must support `help` and the operations relevant to the attack. A typical contract is:

```text
preflight       Check tools, device, root/debug state, network and input artifacts
build           Produce the attack artifact
install         Install while preserving test data
clean-install   Remove the exact test package and install fresh
attack          Execute the attack against the declared lab target
verify          Collect redacted evidence and fail if the success condition is absent
reopen          Reopen/restart and verify persistence where relevant
restore-original Restore the original package or test state
```

Do not include unsupported subcommands in the report. Do not make `clean-install`, `attack`, or `restore-original` the default action.

## Report fields

The report must identify:

- scope and authorization assumptions;
- input artifact name and SHA-256;
- device and required privileges;
- tools and versions where material;
- attack mechanism and data flow;
- exact script commands and arguments;
- information exposed or changed;
- observable success criteria;
- actual result and evidence paths;
- impact to users, company, app, and data;
- defensive controls and expected protected/unprotected difference;
- cleanup and restore procedure;
- limitations and untested branches.

Never include raw credentials, complete tokens, cookies, signing passwords, or private keys.
