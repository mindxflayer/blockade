import sys

import os

import structlog

structlog.configure(processors=[structlog.processors.TimeStamper(fmt='iso'), structlog.processors.add_log_level, structlog.processors.JSONRenderer()], logger_factory=structlog.PrintLoggerFactory(sys.stderr))

import argparse

import asyncio

from dotenv import load_dotenv

from mcp_firewall.proxy.stdio import run_stdio_proxy

from mcp_firewall.interceptor.parser import intercept_request

logger = structlog.get_logger()

load_dotenv()

ASCII_LOGO = r"""
 ██████╗ ██╗      ██████╗  ██████╗██╗  ██╗ █████╗ ██████╗ ███████╗
 ██╔══██╗██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔══██╗██╔══██╗██╔════╝
 ██████╔╝██║     ██║   ██║██║     █████╔╝ ███████║██║  ██║█████╗  
 ██╔══██╗██║     ██║   ██║██║     ██╔═██╗ ██╔══██║██║  ██║██╔══╝  
 ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗██║  ██║██████╔╝███████╗
 ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝
"""

def print_banner() -> None:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich import box

                                                                              
    console = Console(stderr=True, highlight=False)

    logo = Text(ASCII_LOGO)

    subtitle = Text.assemble(
        ("  MCP Security Proxy", ""),
        ("  •  ", ""),
        ("v0.1.0", ""),
        ("  •  ", ""),
        ("by Ishaani Prashant (@mindxflayer)", ""),
    )

    panel = Panel(
        Text.assemble(logo, "\n", subtitle),
        box=box.DOUBLE_EDGE,
        padding=(0, 2),
    )

    console.print(panel)
    console.print()

def cli():

    print_banner()

    parser = argparse.ArgumentParser(description='Blockade — MCP security proxy')

    subparsers = parser.add_subparsers(dest='command', required=True)

    wrap_parser = subparsers.add_parser('wrap', help='Wrap and proxy a downstream MCP server')

    wrap_parser.add_argument('server_cmd', help='Command to run the downstream MCP server')

    wrap_parser.add_argument('-H', '--header', action='append', help="HTTP header for remote connections (e.g. 'Authorization: Bearer token')")

    wrap_parser.add_argument('--transport', choices=['stdio', 'sse', 'http'], default='auto', help='Override transport mode (auto, stdio, sse, http)')

    wrap_parser.add_argument('server_args', nargs=argparse.REMAINDER, help='Arguments for the downstream MCP server')

    subparsers.add_parser('init', help='Initialize firewall settings and credentials')

    approve_parser = subparsers.add_parser('approve-schema-change', help='Approve a new tool schema for a given server ID')

    approve_parser.add_argument('server_id', help='The server ID to clear tool pins for')

    args = parser.parse_args()

    if args.command == 'wrap':

        if not os.getenv('MCP_SERVER_ID'):

            import hashlib

            cmd_str = args.server_cmd

            if hasattr(args, 'server_args') and args.server_args:

                cmd_str += ' ' + ' '.join(args.server_args)

            os.environ['MCP_SERVER_ID'] = 'server_' + hashlib.sha256(cmd_str.encode()).hexdigest()[:8]

        try:

            headers = {}

            if hasattr(args, 'header') and args.header:

                for h in args.header:

                    if ':' in h:

                        k, v = h.split(':', 1)

                        headers[k.strip()] = v.strip()

            if args.server_cmd.startswith(('http://', 'https://')) or args.transport in ('sse', 'http'):

                from mcp_firewall.proxy.http import run_http_proxy

                from mcp_firewall.interceptor.parser import intercept_request

                asyncio.run(run_http_proxy(args.server_cmd, intercept_request, headers=headers))

            else:

                from mcp_firewall.proxy.stdio import run_stdio_proxy

                from mcp_firewall.interceptor.parser import intercept_request

                asyncio.run(run_stdio_proxy(args.server_cmd, getattr(args, 'server_args', []), intercept_request))

        except KeyboardInterrupt:

            logger.info('Proxy interrupted by user')

            sys.exit(0)

        except Exception as e:

            logger.exception('Proxy runtime error occurred', error=str(e))

            sys.exit(1)

    elif args.command == 'init':

        from mcp_firewall.approval.cli import run_init_cli

        run_init_cli()

    elif args.command == 'approve-schema-change':

        import json

        pin_file = os.path.expanduser('~/.config/blockade/tool_pins.json')

        if os.path.exists(pin_file):

            with open(pin_file, 'r', encoding='utf-8') as f:

                pins = json.load(f)

            if args.server_id in pins:

                del pins[args.server_id]

                with open(pin_file, 'w', encoding='utf-8') as f:

                    json.dump(pins, f, indent=2)

                logger.info('Cleared tool pins for server. Next connection will re-pin.', server=args.server_id)

            else:

                logger.info('Server ID not found in pins.', server=args.server_id)

        else:

            logger.info('No pins file found.')

if __name__ == '__main__':

    cli()
