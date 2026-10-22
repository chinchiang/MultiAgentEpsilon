"""受監督執行：每個子程序都從同一份基本環境出發，各角色只加上自己需要的名稱。

Supervised runs: every child process starts from one base environment, and each role adds only the names it needs."""

# 找到程式、語系、代理與 CA 所需的名稱；不含任何權杖、金鑰或改變連線目的地的設定。 / The names needed to find
# programs, locale, proxies and CAs; no token, key or setting that changes where a child connects.
BASE_ENV = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"})


def child_environment(environ, extra=()):
    """基本環境加上角色的額外名稱；名稱須完全相符，大小寫不同即丟棄。

The base environment plus the role's extra names. Names must match exactly; any
    other casing is dropped.
    """
    return {k: v for k, v in environ.items() if k in BASE_ENV or k in extra}
