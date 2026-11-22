#!/usr/bin/env python3
"""Run a private vpnctl stand, browser journeys or the stdio MCP server."""
import argparse
import asyncio
import json
import signal
import threading

from browser import SUITES, run_suite
from stand import stand


async def mcp_server():
    from mcp import types
    from mcp.server import Server
    from mcp.server.stdio import stdio_server

    server = Server("vpnctl-qa")
    catalog = types.Tool(name="qa_catalog", description="List the isolated browser suites.",
                         inputSchema={"type": "object", "properties": {}, "additionalProperties": False})
    run = types.Tool(name="qa_run", description="Run browser checks on a fresh offline vpnctl stand.",
                     inputSchema={"type": "object", "additionalProperties": False, "required": ["suite"],
                                  "properties": {"suite": {"type": "string", "enum": [*SUITES, "all"]}}})

    @server.list_tools()
    async def list_tools():
        return [catalog, run]

    @server.call_tool(validate_input=True)
    async def call_tool(name, arguments):
        if name == "qa_catalog":
            return {"suites": list(SUITES)}
        if name == "qa_run":
            return await asyncio.to_thread(run_suite, arguments["suite"])
        raise ValueError("Unknown QA tool")

    async with stdio_server() as (reader, writer):
        await server.run(reader, writer, server.create_initialization_options())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=0)
    run = commands.add_parser("run")
    run.add_argument("--suite", choices=(*SUITES, "all"), default="all")
    commands.add_parser("mcp")
    args = parser.parse_args()
    if args.command == "mcp":
        asyncio.run(mcp_server())
    elif args.command == "run":
        report = run_suite(args.suite)
        print(json.dumps(report, indent=2))
        return int(any(not row["passed"] for row in report["checks"]))
    else:
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        with stand(args.port) as fixture:
            print(fixture.origin + "/admin/", flush=True)
            stop.wait()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
