# syntax=docker/dockerfile:1
ARG KERIPY_IMAGE=keripy-v2-scenarios:base
FROM ${KERIPY_IMAGE}
COPY --from=dolly-src pyproject.toml README.md LICENSE NOTICE /opt/dolly/
COPY --from=dolly-src src /opt/dolly/src
ARG KERIPY_REVISION
ARG DOLLY_REVISION
ARG KERIPY_WORKTREE_DIRTY=false
ARG DOLLY_WORKTREE_DIRTY=false
ENV SCENARIO_KERIPY_REVISION=${KERIPY_REVISION} SCENARIO_DOLLY_REVISION=${DOLLY_REVISION} SCENARIO_KERIPY_DIRTY=${KERIPY_WORKTREE_DIRTY} SCENARIO_DOLLY_DIRTY=${DOLLY_WORKTREE_DIRTY}
RUN mkdir -p /artifacts && python -m pip wheel --no-deps --no-build-isolation /workspace /opt/dolly -w /artifacts && python -m pip install --force-reinstall --no-deps --no-build-isolation /artifacts/*.whl
RUN python -c 'import os,json,hashlib,pathlib; p=pathlib.Path("/artifacts"); value={"keripy_revision":os.environ["SCENARIO_KERIPY_REVISION"],"dolly_revision":os.environ["SCENARIO_DOLLY_REVISION"],"keripy_worktree_dirty":os.environ["SCENARIO_KERIPY_DIRTY"] == "true","dolly_worktree_dirty":os.environ["SCENARIO_DOLLY_DIRTY"] == "true","wheels":{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in p.glob("*.whl")}}; (p/"manifest.json").write_text(json.dumps(value,indent=2))'
ENTRYPOINT ["bash"]
