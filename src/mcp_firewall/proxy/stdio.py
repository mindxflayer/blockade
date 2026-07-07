import asyncio

import json

import sys

import shutil

from typing import List, Callable, Awaitable

import structlog

from mcp_firewall.interceptor.parser import intercept_response, get_pending_request_info

logger = structlog.get_logger()

input_queue: asyncio.Queue = asyncio.Queue()



def blocking_stdin_reader(loop: asyncio.AbstractEventLoop):

    logger.debug('Starting stdin reader thread')

    while True:

        try:

            line = sys.stdin.readline()

            if not line:

                loop.call_soon_threadsafe(input_queue.put_nowait, None)

                break

            loop.call_soon_threadsafe(input_queue.put_nowait, line)

        except Exception as e:

            logger.exception('Error in stdin reader thread', error=str(e))

            loop.call_soon_threadsafe(input_queue.put_nowait, None)

            break



async def run_stdio_proxy(cmd: str, args: List[str], interceptor_fn: Callable[[dict], Awaitable[tuple[bool, str, dict]]]):

    resolved_cmd = shutil.which(cmd)

    if not resolved_cmd:

        if sys.platform == 'win32' and (not cmd.endswith(('.exe', '.cmd', '.bat'))):

            for ext in ('.cmd', '.bat', '.exe'):

                checked = shutil.which(cmd + ext)

                if checked:

                    resolved_cmd = checked

                    break

        if not resolved_cmd:

            resolved_cmd = cmd

    logger.info('Spawning downstream MCP server', cmd=cmd, args=args, resolved_cmd=resolved_cmd)

    use_shell = sys.platform == 'win32' and resolved_cmd.endswith(('.cmd', '.bat'))

    try:

        process = await asyncio.create_subprocess_exec(resolved_cmd, *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

    except Exception as e:

        if sys.platform == 'win32':

            logger.warning('create_subprocess_exec failed, falling back to create_subprocess_shell', error=str(e))

            full_cmd = f'"{resolved_cmd}" ' + ' '.join((f'"{a}"' for a in args))

            process = await asyncio.create_subprocess_shell(full_cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        else:

            raise e

    loop = asyncio.get_running_loop()

    loop.run_in_executor(None, blocking_stdin_reader, loop)



    pending_tasks = set()



    async def handle_client_input():

        while True:

            line = await input_queue.get()

            if line is None:

                if pending_tasks:

                    logger.info('stdin EOF reached, waiting for pending tasks', count=len(pending_tasks))

                    await asyncio.gather(*pending_tasks, return_exceptions=True)

                from mcp_firewall.interceptor.parser import _pending_requests

                if _pending_requests:

                    logger.info('stdin EOF reached, waiting for downstream responses', count=len(_pending_requests))

                    for _ in range(100):                        

                        if not _pending_requests:

                            break

                        await asyncio.sleep(0.1)

                logger.info('stdin EOF reached, shutting down downstream process')

                break

            line = line.strip()

            if not line:

                continue

            try:

                message = json.loads(line)

            except json.JSONDecodeError:

                logger.error('Failed to parse JSON from client stdin', content=line)

                if process.stdin:

                    process.stdin.write(line.encode('utf-8') + b'\n')

                    await process.stdin.drain()

                continue

            is_request = isinstance(message, dict) and 'method' in message and ('id' in message)

            if is_request:

                async def process_request(msg):

                    logger.debug('Intercepted request', method=msg['method'], message_id=msg['id'])

                    allowed, block_reason, modified_message = await interceptor_fn(msg)

                    if not allowed:

                        if block_reason.startswith('SANDBOX_REDIRECT:'):

                            result_str = block_reason[len('SANDBOX_REDIRECT:'):]

                            result_obj = json.loads(result_str)

                            success_resp = {'jsonrpc': '2.0', 'id': msg['id'], 'result': result_obj}

                            sys.stdout.write(json.dumps(success_resp) + '\n')

                            sys.stdout.flush()

                            return

                        logger.warn('Blocking request', message_id=msg['id'], reason=block_reason)

                        error_resp = {'jsonrpc': '2.0', 'id': msg['id'], 'error': {'code': -32003, 'message': f'Blocked by MCP Firewall: {block_reason}'}}

                        sys.stdout.write(json.dumps(error_resp) + '\n')

                        sys.stdout.flush()

                        return

                    logger.debug('Forwarding request to downstream server', message_id=msg['id'])

                    if process.stdin:

                        payload = json.dumps(modified_message) + '\n'

                        process.stdin.write(payload.encode('utf-8'))

                        await process.stdin.drain()

                task = asyncio.create_task(process_request(message))

                pending_tasks.add(task)

                task.add_done_callback(pending_tasks.discard)

                continue

            if process.stdin:

                payload = json.dumps(message) + '\n'

                process.stdin.write(payload.encode('utf-8'))

                await process.stdin.drain()



    async def handle_server_output():

        while True:

            if not process.stdout:

                break

            line = await process.stdout.readline()

            if not line:

                logger.info('Downstream server stdout closed')

                break

            line_decoded = line.strip().decode('utf-8', errors='ignore')

            if not line_decoded:

                sys.stdout.buffer.write(line)

                sys.stdout.flush()

                continue

            try:

                message = json.loads(line_decoded)

                if isinstance(message, dict) and 'id' in message:

                    resp_id = message['id']

                    req_info = get_pending_request_info(resp_id)

                    if req_info:

                        message = await intercept_response(req_info, message)

                        line = (json.dumps(message) + '\n').encode('utf-8')

            except Exception as e:

                logger.debug('Failed to handle response intercept, forwarding raw', error=str(e))

            sys.stdout.buffer.write(line)

            sys.stdout.flush()



    async def handle_server_stderr():

        while True:

            if not process.stderr:

                break

            line = await process.stderr.readline()

            if not line:

                break

            sys.stderr.buffer.write(line)

            sys.stderr.flush()

    tasks = [asyncio.create_task(handle_client_input()), asyncio.create_task(handle_server_output()), asyncio.create_task(handle_server_stderr())]

    await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

    if process.returncode is None:

        try:

            process.terminate()

            await process.wait()

        except Exception:

            pass

    logger.info('stdio proxy session ended')
