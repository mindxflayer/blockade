import os

import json

import hashlib

import structlog

logger = structlog.get_logger()

PIN_FILE = os.path.expanduser('~/.config/blockade/tool_pins.json')



def compute_tools_hash(tools: list) -> str:

    sorted_tools = sorted(tools, key=lambda t: t.get('name', ''))

    serialized = json.dumps(sorted_tools, sort_keys=True)

    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()



def check_and_pin_tools(server_id: str, tools: list) -> tuple[bool, str]:

    new_hash = compute_tools_hash(tools)

    pins = {}

    if os.path.exists(PIN_FILE):

        try:

            with open(PIN_FILE, 'r', encoding='utf-8') as f:

                pins = json.load(f)

        except Exception as e:

            logger.error('Failed to load tool pins file, resetting', error=str(e))

    if server_id not in pins:

        pins[server_id] = {'hash': new_hash, 'tools': tools}

        try:

            os.makedirs(os.path.dirname(PIN_FILE), exist_ok=True)

            with open(PIN_FILE, 'w', encoding='utf-8') as f:

                json.dump(pins, f, indent=2)

            logger.info('Successfully pinned new tools schema for server', server=server_id, hash=new_hash)

        except Exception as e:

            logger.error('Failed to save tool pin to file', error=str(e))

        return (True, '')

    pinned_data = pins[server_id]

    pinned_hash = pinned_data.get('hash')

    if pinned_hash != new_hash:

        logger.error('CRITICAL: Tool schema rug-pull detected! Tool definitions changed from first connection.', server=server_id, expected=pinned_hash, actual=new_hash)

        return (False, f"Downstream server '{server_id}' tool definitions changed! Expected hash: {pinned_hash}, got: {new_hash}. To approve this schema change, run: mcp-firewall approve-schema-change {server_id}")

    return (True, '')
