from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
import uvicorn
import threading
from fastmcp import FastMCP
import httpx
import os
import subprocess
import sys
import json
import shutil
import yaml
from typing import Optional, List

mcp = FastMCP("wiretap")

# Track running wiretap processes
_wiretap_processes = {}


def _find_wiretap_binary() -> Optional[str]:
    """Find the wiretap binary in PATH or common locations."""
    # Try to find wiretap in PATH
    binary = shutil.which("wiretap")
    if binary:
        return binary
    # Try npx
    npx = shutil.which("npx")
    if npx:
        return None  # Will use npx
    return None


def _build_wiretap_command(args: list) -> list:
    """Build a wiretap command using available binary."""
    binary = _find_wiretap_binary()
    if binary:
        return [binary] + args
    # Fall back to npx
    npx = shutil.which("npx")
    if npx:
        return [npx, "@pb33f/wiretap"] + args
    return ["wiretap"] + args  # Hope it's in PATH


@mcp.tool()
async def start_wiretap(
    url: str,
    spec: Optional[str] = None,
    port: int = 9090,
    monitor_port: int = 9091,
    config: Optional[str] = None,
    hard_errors: bool = False
) -> dict:
    """Start the wiretap proxy daemon to intercept and validate API traffic against an OpenAPI specification.
    Wiretap acts as a transparent proxy between a client and a target API."""
    try:
        args = ["-u", url, "-p", str(port), "-m", str(monitor_port)]

        if spec:
            args.extend(["-s", spec])
        if config:
            args.extend(["-c", config])
        if hard_errors:
            args.append("--hard-errors")

        cmd = _build_wiretap_command(args)

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Store process reference
        _wiretap_processes[port] = process

        # Wait briefly to check if it started successfully
        import time
        time.sleep(1)

        if process.poll() is not None:
            stdout, stderr = process.communicate()
            return {
                "success": False,
                "error": f"Wiretap failed to start. Exit code: {process.returncode}",
                "stdout": stdout,
                "stderr": stderr,
                "command": " ".join(cmd)
            }

        return {
            "success": True,
            "message": f"Wiretap proxy started successfully",
            "pid": process.pid,
            "proxy_url": f"http://localhost:{port}",
            "monitor_url": f"http://localhost:{monitor_port}",
            "target_url": url,
            "spec": spec,
            "hard_errors": hard_errors,
            "command": " ".join(cmd),
            "note": "Direct requests through http://localhost:{} to proxy to {}".format(port, url)
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Wiretap binary not found. Install with: npm install -g @pb33f/wiretap or brew install pb33f/taps/wiretap",
            "install_options": [
                "npm install -g @pb33f/wiretap",
                "yarn global add @pb33f/wiretap",
                "brew install pb33f/taps/wiretap",
                "curl -fsSL https://pb33f.io/wiretap/install.sh | sh"
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
async def validate_request(
    spec: str,
    method: str,
    path: str,
    headers: Optional[List[str]] = None,
    body: Optional[str] = None,
    query: Optional[str] = None
) -> dict:
    """Validate a specific HTTP request against an OpenAPI specification without proxying live traffic.
    Checks if the given request (method, path, headers, body) complies with the API contract."""
    try:
        # Build the validate request command
        args = ["validate", "request", "-s", spec, "-m", method.upper(), "-p", path]

        if headers:
            for header in headers:
                args.extend(["-H", header])
        if body:
            args.extend(["-d", body])
        if query:
            full_path = f"{path}?{query}"
            # Replace the path argument
            p_index = args.index("-p") + 1
            args[p_index] = full_path

        cmd = _build_wiretap_command(args)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        # Parse output
        output = result.stdout + result.stderr
        violations = []
        lines = output.strip().split("\n") if output.strip() else []

        for line in lines:
            if line.strip():
                violations.append(line.strip())

        is_valid = result.returncode == 0

        return {
            "success": True,
            "valid": is_valid,
            "method": method.upper(),
            "path": path,
            "spec": spec,
            "violations": violations,
            "violation_count": len([v for v in violations if v]),
            "raw_output": output,
            "exit_code": result.returncode,
            "command": " ".join(cmd)
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Validation timed out after 30 seconds"}
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Wiretap binary not found. Install with: npm install -g @pb33f/wiretap"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
async def validate_response(
    spec: str,
    method: str,
    path: str,
    status_code: int,
    headers: Optional[List[str]] = None,
    body: Optional[str] = None
) -> dict:
    """Validate a specific HTTP response against an OpenAPI specification.
    Checks if an API response (status code, headers, body) complies with the contract."""
    try:
        args = ["validate", "response", "-s", spec, "-m", method.upper(), "-p", path, "-c", str(status_code)]

        if headers:
            for header in headers:
                args.extend(["-H", header])
        if body:
            args.extend(["-d", body])

        cmd = _build_wiretap_command(args)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        output = result.stdout + result.stderr
        violations = []
        lines = output.strip().split("\n") if output.strip() else []

        for line in lines:
            if line.strip():
                violations.append(line.strip())

        is_valid = result.returncode == 0

        return {
            "success": True,
            "valid": is_valid,
            "method": method.upper(),
            "path": path,
            "status_code": status_code,
            "spec": spec,
            "violations": violations,
            "violation_count": len([v for v in violations if v]),
            "raw_output": output,
            "exit_code": result.returncode,
            "command": " ".join(cmd)
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Validation timed out after 30 seconds"}
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Wiretap binary not found. Install with: npm install -g @pb33f/wiretap"
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
async def configure_path_rewrite(
    config_file: str,
    source_path: str,
    target_path: str,
    rewrite_id: Optional[str] = None,
    target_host: Optional[str] = None
) -> dict:
    """Configure path rewriting rules in the wiretap configuration to redirect or rewrite
    incoming request paths before they are forwarded to the upstream API."""
    try:
        # Load existing config or create new one
        existing_config = {}
        try:
            with open(config_file, 'r') as f:
                existing_config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            existing_config = {}
        except Exception as e:
            return {"success": False, "error": f"Failed to read config file: {str(e)}"}

        # Build the rewrite rule entry
        rewrite_rule = {
            "pathPattern": source_path,
            "rewritePath": target_path
        }

        if rewrite_id:
            rewrite_rule["rewriteId"] = rewrite_id
        if target_host:
            rewrite_rule["target"] = target_host

        # Add to paths configuration
        if "paths" not in existing_config:
            existing_config["paths"] = []

        # Check if rule already exists and update, or append
        paths = existing_config["paths"]
        found = False
        for i, p in enumerate(paths):
            if isinstance(p, dict) and p.get("pathPattern") == source_path:
                paths[i] = rewrite_rule
                found = True
                break

        if not found:
            paths.append(rewrite_rule)

        existing_config["paths"] = paths

        # Write updated config
        with open(config_file, 'w') as f:
            yaml.dump(existing_config, f, default_flow_style=False, sort_keys=False)

        return {
            "success": True,
            "message": f"Path rewrite rule {'updated' if found else 'added'} successfully",
            "config_file": config_file,
            "rule": rewrite_rule,
            "total_rules": len(existing_config["paths"]),
            "config_preview": yaml.dump(existing_config, default_flow_style=False)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
async def get_violations(
    monitor_url: str = "http://localhost:9091",
    filter_path: Optional[str] = None,
    violation_type: Optional[str] = None,
    limit: int = 50
) -> dict:
    """Retrieve captured OpenAPI contract violations from the wiretap proxy session.
    Returns all detected compliance issues between requests/responses and the API spec."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try common wiretap monitor API endpoints
            endpoints_to_try = [
                f"{monitor_url}/api/violations",
                f"{monitor_url}/violations",
                f"{monitor_url}/api/transactions",
                f"{monitor_url}/transactions",
                f"{monitor_url}/api/report"
            ]

            last_error = None
            for endpoint in endpoints_to_try:
                try:
                    response = await client.get(endpoint)
                    if response.status_code == 200:
                        data = response.json()

                        violations = []
                        if isinstance(data, list):
                            violations = data
                        elif isinstance(data, dict):
                            violations = data.get("violations", data.get("transactions", [data]))

                        # Apply filters
                        if filter_path:
                            violations = [
                                v for v in violations
                                if isinstance(v, dict) and
                                filter_path in str(v.get("path", v.get("url", "")))
                            ]

                        if violation_type and violation_type != "both":
                            violations = [
                                v for v in violations
                                if isinstance(v, dict) and
                                v.get("type", "").lower() == violation_type.lower()
                            ]

                        # Apply limit
                        total = len(violations)
                        violations = violations[:limit]

                        return {
                            "success": True,
                            "endpoint_used": endpoint,
                            "violations": violations,
                            "count": len(violations),
                            "total_available": total,
                            "filter_path": filter_path,
                            "violation_type": violation_type,
                            "limit": limit
                        }
                except httpx.RequestError:
                    continue

            return {
                "success": False,
                "error": f"Could not connect to wiretap monitor at {monitor_url}. Is wiretap running?",
                "tried_endpoints": endpoints_to_try,
                "hint": "Start wiretap first using start_wiretap tool, then use get_violations"
            }

    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
async def mock_api(
    spec: str,
    port: int = 9090,
    static_dir: Optional[str] = None,
    use_examples: bool = True
) -> dict:
    """Start wiretap in mock mode to generate and serve mock API responses directly from
    an OpenAPI specification without needing a real backend."""
    try:
        args = ["mock", "-s", spec, "-p", str(port)]

        if static_dir:
            args.extend(["--static-dir", static_dir])
        if not use_examples:
            args.append("--no-examples")

        cmd = _build_wiretap_command(args)

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        _wiretap_processes[f"mock_{port}"] = process

        import time
        time.sleep(1)

        if process.poll() is not None:
            stdout, stderr = process.communicate()
            return {
                "success": False,
                "error": f"Wiretap mock server failed to start. Exit code: {process.returncode}",
                "stdout": stdout,
                "stderr": stderr,
                "command": " ".join(cmd)
            }

        return {
            "success": True,
            "message": "Wiretap mock server started successfully",
            "pid": process.pid,
            "mock_url": f"http://localhost:{port}",
            "spec": spec,
            "use_examples": use_examples,
            "static_dir": static_dir,
            "command": " ".join(cmd),
            "note": f"Mock API is available at http://localhost:{port} — all endpoints from {spec} are being served as mocks"
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Wiretap binary not found. Install with: npm install -g @pb33f/wiretap",
            "install_options": [
                "npm install -g @pb33f/wiretap",
                "yarn global add @pb33f/wiretap",
                "brew install pb33f/taps/wiretap"
            ]
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
async def inspect_spec(
    spec: str,
    filter_path: Optional[str] = None,
    show_schemas: bool = False
) -> dict:
    """Parse and inspect an OpenAPI specification file to list available paths, operations,
    schemas, and any spec-level issues. Use this to understand what an API spec defines."""
    try:
        # Load the spec - support both file path and URL
        spec_data = None

        if spec.startswith("http://") or spec.startswith("https://"):
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(spec)
                response.raise_for_status()
                content = response.text
                try:
                    spec_data = json.loads(content)
                except json.JSONDecodeError:
                    spec_data = yaml.safe_load(content)
        else:
            with open(spec, 'r') as f:
                content = f.read()
                try:
                    spec_data = json.loads(content)
                except json.JSONDecodeError:
                    spec_data = yaml.safe_load(content)

        if not spec_data:
            return {"success": False, "error": "Failed to parse specification file"}

        # Extract spec info
        info = spec_data.get("info", {})
        openapi_version = spec_data.get("openapi", spec_data.get("swagger", "unknown"))
        servers = spec_data.get("servers", [])
        paths = spec_data.get("paths", {})
        components = spec_data.get("components", {})
        schemas = components.get("schemas", spec_data.get("definitions", {}))

        # Build operations list
        operations = []
        http_methods = ["get", "post", "put", "patch", "delete", "head", "options", "trace"]

        for path, path_item in paths.items():
            if filter_path and not path.startswith(filter_path):
                continue
            if not isinstance(path_item, dict):
                continue
            for method in http_methods:
                if method in path_item:
                    op = path_item[method]
                    operation_entry = {
                        "method": method.upper(),
                        "path": path,
                        "summary": op.get("summary", ""),
                        "description": op.get("description", ""),
                        "operationId": op.get("operationId", ""),
                        "tags": op.get("tags", []),
                        "parameters": len(op.get("parameters", [])),
                        "request_body": bool(op.get("requestBody")),
                        "responses": list(op.get("responses", {}).keys())
                    }
                    operations.append(operation_entry)

        result = {
            "success": True,
            "spec_file": spec,
            "openapi_version": openapi_version,
            "title": info.get("title", "Unknown"),
            "version": info.get("version", "Unknown"),
            "description": info.get("description", ""),
            "servers": servers,
            "total_paths": len(paths),
            "total_operations": len(operations),
            "operations": operations,
        }

        if filter_path:
            result["filter_applied"] = filter_path

        if show_schemas:
            schema_summary = {}
            for schema_name, schema_def in schemas.items():
                if isinstance(schema_def, dict):
                    schema_summary[schema_name] = {
                        "type": schema_def.get("type", "object"),
                        "properties": list(schema_def.get("properties", {}).keys()),
                        "required": schema_def.get("required", []),
                        "description": schema_def.get("description", "")
                    }
            result["schemas"] = schema_summary
            result["total_schemas"] = len(schemas)

        # Tag summary
        all_tags = set()
        for op in operations:
            for tag in op.get("tags", []):
                all_tags.add(tag)
        result["tags"] = sorted(list(all_tags))

        return result

    except FileNotFoundError:
        return {"success": False, "error": f"Specification file not found: {spec}"}
    except yaml.YAMLError as e:
        return {"success": False, "error": f"Failed to parse YAML/JSON spec: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": str(e)}




_SERVER_SLUG = mcp.name.lower().replace(" ", "-").replace("_", "-")

def _track(tool_name: str, ua: str = ""):
    try:
        import urllib.request, json as _json
        data = _json.dumps({"slug": _SERVER_SLUG, "event": "tool_call", "tool": tool_name, "user_agent": ua}).encode()
        req = urllib.request.Request("https://www.volspan.dev/api/analytics/event", data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=1)
    except Exception:
        pass

async def health(request):
    return JSONResponse({"status": "ok", "server": mcp.name})

async def tools(request):
    registered = await mcp.list_tools()
    tool_list = [{"name": t.name, "description": t.description or ""} for t in registered]
    return JSONResponse({"tools": tool_list, "count": len(tool_list)})

mcp_app = mcp.http_app(transport="streamable-http")

class _FixAcceptHeader:
    """Ensure Accept header includes both types FastMCP requires."""
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            accept = headers.get(b"accept", b"").decode()
            if "text/event-stream" not in accept:
                new_headers = [(k, v) for k, v in scope["headers"] if k != b"accept"]
                new_headers.append((b"accept", b"application/json, text/event-stream"))
                scope = dict(scope, headers=new_headers)
        await self.app(scope, receive, send)

app = _FixAcceptHeader(Starlette(
    routes=[
        Route("/health", health),
        Route("/tools", tools),
        Mount("/", mcp_app),
    ],
    lifespan=mcp_app.lifespan,
))

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
