# 僅供離線補充測試，不作正式遷移映像。 / Offline supplemental tests only; not a production migration image.
FROM python:3.12.15-trixie@sha256:0d0db5b17f11b1b7d1aafa74ceadaa64ba0944b267ff6fc22008a197acd6b9ad AS git-source
RUN mkdir /export && cp /usr/bin/git /export/git && \
    cp -L /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0 /export/libpcre2-8.so.0 && \
    cp -L /usr/lib/x86_64-linux-gnu/libz.so.1 /export/libz.so.1
FROM python:3.12.16-slim-trixie@sha256:8523d6abeb48ceae0b7240d30c5808fc26cb79c1a635bacdf19cf3baecfbec07
COPY --from=git-source /export/git /usr/local/bin/git
COPY --from=git-source /export/libpcre2-8.so.0 /usr/local/lib/libpcre2-8.so.0
COPY --from=git-source /export/libz.so.1 /usr/local/lib/libz.so.1
COPY --from=git-source /usr/share/git-core/templates /usr/local/share/git-core/templates
COPY --chmod=0755 gh-deny /usr/local/bin/gh
COPY requirements-runtime.lock requirements-build.lock native.sha256 /locks/
COPY wheels /wheels
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN sha256sum -c /locks/native.sha256 && \
    python -m pip --isolated install --no-index --find-links=/wheels --only-binary=:all: \
      --no-deps --require-hashes --no-compile --no-cache-dir --force-reinstall -r /locks/requirements-build.lock && \
    python -m pip --isolated install --no-index --find-links=/wheels --only-binary=:all: \
      --no-deps --require-hashes --no-compile --no-cache-dir -r /locks/requirements-runtime.lock && \
    python -m pip check && python -m pip --isolated uninstall --yes pip && \
    python -I -c 'import pathlib,shutil,sysconfig; shutil.rmtree(pathlib.Path(sysconfig.get_path("stdlib"))/"ensurepip")' && \
    rm -r /wheels
COPY entrypoint.py supplemental_manifest.py runtime_guard.py runtime-contract.json /opt/supplemental/
ENV LD_LIBRARY_PATH=/usr/local/lib GIT_TEMPLATE_DIR=/usr/local/share/git-core/templates
USER 10001:10001
ENTRYPOINT ["python", "-I", "/opt/supplemental/entrypoint.py"]
