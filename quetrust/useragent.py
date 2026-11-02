"""How Que Trust names itself on every outbound HTTP call (DEC-199): the products reach each other over public HTTPS
behind Cloudflare and other WAFs, which refuse Python's default user agents."""

USER_AGENT = "que-trust/1.0 (+https://trust.que.is)"
HEADERS = {"User-Agent": USER_AGENT}
