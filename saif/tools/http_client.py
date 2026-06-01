from time import perf_counter

import httpx


class HttpClientTool:
    name = "http_client"

    def get(self, url: str) -> dict:
        started = perf_counter()
        try:
            with httpx.Client(follow_redirects=True, timeout=15) as client:
                response = client.get(url)
            elapsed_ms = int((perf_counter() - started) * 1000)
            return {
                "ok": True,
                "request": {
                    "method": "GET",
                    "url": str(response.request.url),
                    "headers": dict(response.request.headers),
                    "body": None,
                },
                "response": {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body_preview": response.text[:4000],
                    "elapsed_ms": elapsed_ms,
                },
            }
        except httpx.HTTPError as exc:
            elapsed_ms = int((perf_counter() - started) * 1000)
            return {
                "ok": False,
                "error": str(exc),
                "request": {"method": "GET", "url": url, "headers": {}, "body": None},
                "response": {"status_code": None, "headers": {}, "body_preview": None, "elapsed_ms": elapsed_ms},
            }
