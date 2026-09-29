"""
sandbox/run.py  — executed INSIDE the isolated container
=========================================================
Opens the target URL in a headless Chromium browser,
captures network traffic, page title, screenshot, and process events,
then writes a structured JSON result to --out.
"""
import argparse
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone


def run(url: str, out_path: str):
    result = {
        "network_requests": [],
        "dns_queries": [],
        "file_operations": [],
        "process_events": [],
        "screenshot_b64": None,
        "page_title": None,
        "final_url": url,
        "logs": [],
        "execution_ms": 0,
    }

    def log(level: str, category: str, msg: str, raw=None):
        result["logs"].append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "category": category,
            "message": msg,
            "raw": raw,
        })

    start = time.time()

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            context = browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                java_script_enabled=True,
                ignore_https_errors=True,
            )

            # Intercept every network request
            def on_request(req):
                result["network_requests"].append({
                    "url": req.url,
                    "method": req.method,
                    "resource_type": req.resource_type,
                })
                try:
                    host = req.url.split("/")[2]
                    if host not in result["dns_queries"]:
                        result["dns_queries"].append(host)
                except IndexError:
                    pass
                log("info", "network", f"{req.method} {req.url[:120]}")

            def on_response(resp):
                ct = resp.headers.get("content-type", "")
                suspicious_types = ["application/octet-stream", "application/x-msdownload",
                                    "application/x-exe", "application/x-dosexec"]
                if any(st in ct for st in suspicious_types):
                    log("alert", "network",
                        f"Binary download detected: {resp.url[:100]} [{ct}]",
                        {"url": resp.url, "content_type": ct, "status": resp.status})

                for req_entry in result["network_requests"]:
                    if req_entry.get("url") == resp.url:
                        req_entry["status"] = resp.status
                        req_entry["content_type"] = ct

            page = context.new_page()
            page.on("request", on_request)
            page.on("response", on_response)

            log("info", "process", f"Navigating to {url}")
            result["process_events"].append({
                "pid": os.getpid(),
                "name": "chromium",
                "event": "spawn",
                "args": ["--headless", url],
            })

            try:
                page.goto(url, wait_until="networkidle", timeout=20_000)
            except PWTimeout:
                log("warn", "network", "Page load timed out — capturing partial state")

            result["page_title"] = page.title()
            result["final_url"] = page.url

            # Detect login/form patterns
            forms = page.locator("form").count()
            password_fields = page.locator("input[type='password']").count()
            if password_fields > 0:
                log("alert", "visual",
                    f"Password input detected on page (forms={forms}, pwd_inputs={password_fields})")

            # Screenshot
            try:
                screenshot_bytes = page.screenshot(full_page=False)
                result["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode()
                log("info", "visual", "Screenshot captured")
            except Exception as e:
                log("warn", "visual", f"Screenshot failed: {e}")

            browser.close()

    except ImportError:
        log("warn", "process", "Playwright not available — partial analysis only")
    except Exception as e:
        log("alert", "process", f"Sandbox execution error: {e}")

    result["execution_ms"] = int((time.time() - start) * 1000)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(result, f)

    print(f"[sandbox] Done in {result['execution_ms']}ms → {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    run(args.url, args.out)
