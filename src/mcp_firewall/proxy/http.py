import asyncio

import json

import sys

from urllib.parse import urljoin

from typing import Callable, Awaitable, Optional

import httpx

import structlog

from mcp_firewall.interceptor.parser import intercept_request, get_pending_request_info, intercept_response

logger = structlog.get_logger()

input_queue: asyncio.Queue = asyncio.Queue()



def blocking_stdin_reader(loop: asyncio.AbstractEventLoop):

    while True:

        try:

            line = sys.stdin.readline()

            if not line:

                loop.call_soon_threadsafe(input_queue.put_nowait, None)

                break

            loop.call_soon_threadsafe(input_queue.put_nowait, line)

        except Exception as e:

            logger.exception('Error in HTTP proxy stdin reader thread', error=str(e))

            loop.call_soon_threadsafe(input_queue.put_nowait, None)

            break



async def parse_http_stream(response_stream):

    current_event = 'message'

    current_data = []

    async for line in response_stream.aiter_lines():

        line = line.strip()

        if not line:

            if current_data:

                yield (current_event, '\n'.join(current_data))

                current_data = []

                current_event = 'message'

            continue

        if line.startswith('event:'):

            current_event = line[6:].strip()

        elif line.startswith('data:'):

            current_data.append(line[5:].strip())



async def run_http_proxy(http_url: str, interceptor_fn: Callable[[dict], Awaitable[tuple[bool, str, dict]]], headers: Optional[dict]=None):

    logger.info('Starting HTTP client proxy connecting to remote MCP server', url=http_url)

    post_url: Optional[str] = None

    post_url_ready = asyncio.Event()

    loop = asyncio.get_running_loop()

    loop.run_in_executor(None, blocking_stdin_reader, loop)

    async with httpx.AsyncClient(timeout=60.0, headers=headers) as client:



        async def handle_http_listener():

            nonlocal post_url

            try:

                async with client.stream('GET', http_url) as r:

                    if r.status_code != 200:

                        logger.error('Failed to connect to HTTP stream', status_code=r.status_code)

                        return

                    async for event, data in parse_http_stream(r):

                        if event == 'endpoint':

                            post_url = urljoin(http_url, data)

                            logger.info('Discovered remote POST message endpoint', post_url=post_url)

                            post_url_ready.set()

                        elif event == 'message':

                            try:

                                message = json.loads(data)

                                if isinstance(message, dict) and 'id' in message:

                                    resp_id = message['id']

                                    req_info = get_pending_request_info(resp_id)

                                    if req_info:

                                        message = await intercept_response(req_info, message)

                                        data = json.dumps(message)

                            except Exception as e:

                                logger.debug('Failed to handle response intercept in HTTP stream', error=str(e))

                            sys.stdout.write(data + '\n')

                            sys.stdout.flush()

            except Exception as e:

                logger.exception('Error in HTTP line stream reader loop', error=str(e))

            finally:

                logger.info('HTTP stream disconnected')



        pending_tasks = set()



        async def handle_client_stdin():

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

                    break

                line = line.strip()

                if not line:

                    continue

                try:

                    message = json.loads(line)

                except json.JSONDecodeError:

                    logger.error('Failed to parse client stdio JSON in HTTP proxy', content=line)

                    continue

                is_request = isinstance(message, dict) and 'method' in message and 'id' in message

                if is_request:

                    async def process_request(msg):

                        allowed, block_reason, modified_message = await interceptor_fn(msg)

                        if not allowed:

                            if block_reason.startswith("SANDBOX_REDIRECT:"):

                                result_str = block_reason[len("SANDBOX_REDIRECT:"):]

                                result_obj = json.loads(result_str)

                                success_resp = {

                                    "jsonrpc": "2.0",

                                    "id": msg["id"],

                                    "result": result_obj

                                }

                                sys.stdout.write(json.dumps(success_resp) + "\n")

                                sys.stdout.flush()

                                return

                                

                            error_resp = {

                                "jsonrpc": "2.0",

                                "id": msg["id"],

                                "error": {

                                    "code": -32003,

                                    "message": f"Blocked by MCP Firewall: {block_reason}"

                                }

                            }

                            sys.stdout.write(json.dumps(error_resp) + "\n")

                            sys.stdout.flush()

                            return



                                                                    

                        try:

                            await asyncio.wait_for(post_url_ready.wait(), timeout=10.0)

                        except asyncio.TimeoutError:

                            logger.error("Timed out waiting for remote endpoint configuration")

                            return

                            

                                                                   

                        try:

                            resp = await client.post(post_url, json=modified_message)

                            if resp.status_code >= 400:

                                logger.error("Server returned POST error", status_code=resp.status_code, body=resp.text)

                        except Exception as e:

                            logger.exception("Failed to post message to remote endpoint", error=str(e))



                    task = asyncio.create_task(process_request(message))

                    pending_tasks.add(task)

                    task.add_done_callback(pending_tasks.discard)

                    continue

                try:

                    await asyncio.wait_for(post_url_ready.wait(), timeout=10.0)

                except asyncio.TimeoutError:

                    logger.error('Timed out waiting for remote endpoint configuration')

                    continue

                try:

                    resp = await client.post(post_url, json=message)

                    if resp.status_code >= 400:

                        logger.error('Server returned POST error', status_code=resp.status_code, body=resp.text)

                except Exception as e:

                    logger.exception('Failed to post message to remote endpoint', error=str(e))

        tasks = [asyncio.create_task(handle_http_listener()), asyncio.create_task(handle_client_stdin())]

        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        logger.info('HTTP proxy session ended')
