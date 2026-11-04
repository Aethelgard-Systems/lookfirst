# Glama container preparation (not deployed)

The root Dockerfile installs this checkout and runs the **stdio** proxy as UID 10001. No HTTP port is exposed. No upstream credentials, audit keys, synthetic banking server or production configuration are included in the image.

## Build and use

```sh
docker build -t lookfirst:reviewed .
docker run --rm lookfirst:reviewed --version
docker run --rm -i \
  --mount type=bind,src=/absolute/operator/config,dst=/config,readonly \
  --mount type=bind,src=/absolute/operator/state,dst=/state \
  lookfirst:reviewed
```

The paths above are local operator choices, not committed configuration. Prepare the files before starting:

- `/config/lookfirst.yaml` must describe real, explicitly permitted upstreams and existing audit key at `/state/audit.key`, with log at `/state/audit.jsonl`.
- Allow UID 10001 to read the configuration/key and write the state directory. Keep the private key restricted; do not put it in an image or upload it as a Glama public build parameter.
- A stdio upstream command must be available **inside** this image. Add an independently reviewed image extension for that upstream rather than relying on a host executable.
- An HTTP upstream needs network access and its usual authentication. Neither access nor a token is supplied by this image.
- Without those prerequisites startup fails. A successful image build alone does not prove MCP initialization, tool discovery or a working proxy.

## Glama operator steps

1. Open https://glama.ai/mcp/servers/Aethelgard-Systems/lookfirst/admin/dockerfile.
2. Select the reviewed root Dockerfile and exact source commit in the build specification.
3. Configure the required non-public runtime files and upstream access through the maintainer UI's supported mechanisms.
4. Stop if that UI cannot supply the required configuration/key safely; do not replace real proxy tools with a synthetic demo just to pass discovery.
5. After explicit approval for the external build test, use Deploy to run Glama's build and MCP initialization check.
6. Inspect the build log and discovered tools before any release.
7. Leave Make Release / Create & Publish Release to Marco with the existing publication approval.

## Concrete discovery and quality improvements

- Complete maintainer verification if it is still missing.
- Make the Docker build **and configured stdio initialization/tool listing** succeed. Glama says failed builds can suppress directory discovery; merely committing this file does not fix a failed run.
- Inspect each finding in the listing's Score tab: purpose, when to call, side effects, parameter constraints, concise descriptions and context completeness.
- Improve the actual upstream tool descriptions where a per-tool finding warrants it; lookfirst is a proxy and should not invent tools or hide upstream behavior for a score.
- Re-run the scan after the reviewed change and record its actual score and timestamp.
- Add the badge only after Marco supplies the exact snippet from the listing's tab. No placeholder badge is committed.

The previously reported 33% discovery score is INTERNAL_REPORTED, not a new measurement. Discovery, per-tool TDQS, security checks and a Glama release are distinct signals. No numeric improvement is promised.

Local evidence 2026-11-04: Docker daemon access denied in WORK's sandbox; image build/runtime **not tested**. This remains preparation, not a released or verified Glama listing.

Sources checked 2026-11-04: [Glama release process](https://glama.ai/blog/2026-03-15-how-to-make-a-release), [Glama indexing and scoring methodology](https://glama.ai/mcp/methodology).
