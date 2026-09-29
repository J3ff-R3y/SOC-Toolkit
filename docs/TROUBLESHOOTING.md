# Troubleshooting

## 401 from application APIs
Check that the browser received a session token from `/api/login` and sends it as `X-Jeffrey-Session`. Invalid/revoked sessions should remain 401.

## 501 after a rejected POST
A rejected POST must close the backend connection if its body was not consumed. Use the current `session_auth.py`; older compatibility code can leave unread body bytes on a reused HTTP/1.1 connection.

## RAG service active but first health probe fails
Treat systemd `active` and application readiness separately. Use a bounded readiness loop rather than a single immediate probe.

## Knowledge document is not returned
Check:

1. document domain;
2. active knowledge mode;
3. selected-document filter;
4. retrieval term coverage threshold;
5. FTS5/store self-check.

## Structured route returns 422
This usually means model generation completed but the deterministic schema/validator rejected the artifact. Inspect the machine-readable error details rather than treating it as transport failure.
