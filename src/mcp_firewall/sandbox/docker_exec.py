
import os

import subprocess

import asyncio

import structlog

logger = structlog.get_logger()

try:

    import docker

except ImportError:

    docker = None

def is_docker_available() -> bool:

    if docker is not None:

        try:

            client = docker.from_env()

            client.ping()

            return True

        except Exception:

            pass

    try:

        res = subprocess.run(['docker', '--version'], capture_output=True, text=True)

        return res.returncode == 0

    except Exception:

        return False

async def run_sandboxed(arguments: dict, sandbox_config: dict, cwd: str='.') -> dict:

    abs_cwd = os.path.abspath(cwd)

                                                                     

    command = arguments.get('command')

    if not command:

                                                                                                                 

        command = arguments.get('script') or arguments.get('cmd') or arguments.get('code')

        if not command:

            return {'content': [{'type': 'text', 'text': 'Error: Could not determine command to execute from arguments'}], 'isError': True}

            

    network_mode = sandbox_config.get('network', 'none')

    if network_mode not in ('none', 'bridge', 'host'):

        network_mode = 'none'

    if not is_docker_available():

        if os.getenv('ALLOW_UNSANDBOXED_FALLBACK', 'false').lower() == 'true':

            logger.warn('Docker is not available! Executing unsandboxed due to ALLOW_UNSANDBOXED_FALLBACK=true.')

            loop = asyncio.get_running_loop()

            def run_local():

                res = subprocess.run(command, shell=True, capture_output=True, text=True, cwd=abs_cwd)

                text = f'[WARNING: Docker sandbox unavailable; executed locally]\n\n'

                text += f'STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}'

                return {'content': [{'type': 'text', 'text': text}], 'isError': res.returncode != 0}

            return await loop.run_in_executor(None, run_local)

        else:

            logger.error('Docker is not available and ALLOW_UNSANDBOXED_FALLBACK is not enabled. Denying execution.')

            return {'content': [{'type': 'text', 'text': 'Error: Sandbox execution failed because Docker is not available and ALLOW_UNSANDBOXED_FALLBACK is not enabled.'}], 'isError': True}

    if docker is not None:

        try:

            logger.info('Executing sandboxed command via docker-py', command=command, cwd=abs_cwd)

            client = docker.from_env()

            loop = asyncio.get_running_loop()

            def run_container():

                container = client.containers.run(image='alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b', command=['sh', '-c', command], network_mode=network_mode, volumes={abs_cwd: {'bind': '/workspace', 'mode': 'ro'}}, working_dir='/workspace', mem_limit='256m', pids_limit=64, cpu_quota=50000, user='nobody', read_only=True, tmpfs={'/tmp': ''}, security_opt=['no-new-privileges'], detach=True)

                try:

                    result = container.wait(timeout=30)

                    logs = container.logs().decode('utf-8', errors='replace')

                    if len(logs) > 50000:

                        logs = logs[:50000] + '\n...[TRUNCATED BY MCP FIREWALL]...'

                    return (logs, result.get('StatusCode', 1) != 0)

                except Exception as e:

                    try:

                        container.kill()

                    except:

                        pass

                    return (f'Execution timed out or failed: {str(e)}', True)

                finally:

                    try:

                        container.remove(force=True)

                    except:

                        pass

            stdout_str, is_err = await loop.run_in_executor(None, run_container)

            return {'content': [{'type': 'text', 'text': stdout_str}], 'isError': is_err}

        except Exception as e:

            logger.exception('docker-py sandboxing failed, falling back to Docker CLI invocation', error=str(e))

    logger.info('Executing sandboxed command via Docker CLI', command=command, cwd=abs_cwd)

    import uuid

    container_name = f'mcp-sandbox-{uuid.uuid4().hex[:8]}'

    container_cwd = '/workspace'

    cmd = ['docker', 'run', '--rm', '--name', container_name, '--network', network_mode, '--memory', '256m', '--pids-limit', '64', '--cpu-quota', '50000', '--user', 'nobody', '--read-only', '--tmpfs', '/tmp', '--security-opt', 'no-new-privileges', '-v', f'{abs_cwd}:{container_cwd}:ro', '-w', container_cwd, 'alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b', 'sh', '-c', command]

    loop = asyncio.get_running_loop()

    def run_cli():

        try:

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            combined_text = res.stdout + res.stderr

            if len(combined_text) > 50000:

                combined_text = combined_text[:50000] + '\n...[TRUNCATED BY MCP FIREWALL]...'

            return {'content': [{'type': 'text', 'text': combined_text}], 'isError': res.returncode != 0}

        except subprocess.TimeoutExpired:

            subprocess.run(['docker', 'kill', container_name], capture_output=True)

            return {'content': [{'type': 'text', 'text': 'Error: Sandbox execution timed out after 30 seconds.'}], 'isError': True}

    try:

        return await loop.run_in_executor(None, run_cli)

    except Exception as e:

        logger.error('Docker CLI execution failed', error=str(e))

        return {'content': [{'type': 'text', 'text': f'Error running Docker sandbox CLI: {str(e)}'}], 'isError': True}
