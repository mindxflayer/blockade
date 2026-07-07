import sys

import os

import asyncio

import structlog

from rich.console import Console

from rich.panel import Panel

from rich.pretty import Pretty

logger = structlog.get_logger()



def _sync_prompt(tool_name: str, arguments: dict, reason: str) -> bool:

    console = Console(stderr=True)

    panel_content = f'[bold yellow]⚠️ MCP Tool Call Requires Human Approval[/bold yellow]\n\n[bold]Tool:[/bold] {tool_name}\n[bold]Reason:[/bold] {reason}\n\n[bold]Arguments:[/bold]'

    console.print(Panel(panel_content, border_style='yellow'))

    console.print(Pretty(arguments, indent_size=2))

    console.print('')

    try:

        if os.name == 'nt':

            with open('CON', 'r') as tty_in, open('CON', 'w') as tty_out:

                tty_out.write('Approve execution of this tool? [y/N]: ')

                tty_out.flush()

                choice = tty_in.readline().strip().lower()

        else:

            with open('/dev/tty', 'r') as tty_in, open('/dev/tty', 'w') as tty_out:

                tty_out.write('Approve execution of this tool? [y/N]: ')

                tty_out.flush()

                choice = tty_in.readline().strip().lower()

        approved = choice in ('y', 'yes')

        if approved:

            console.print('[green]✓ Tool call approved by user.[/green]')

        else:

            console.print('[red]✗ Tool call blocked by user.[/red]')

        return approved

    except Exception as e:

        logger.error('Failed to read from TTY/CON stream', error=str(e))

        console.print('[red]❌ Direct console reader failed. Defaulting to DENIME.[/red]')

        return False



async def prompt_human_cli(tool_name: str, arguments: dict, reason: str) -> bool:

    loop = asyncio.get_running_loop()

    timeout_sec = int(os.getenv('APPROVAL_TIMEOUT_SECONDS', '300'))

    try:

        return await asyncio.wait_for(loop.run_in_executor(None, _sync_prompt, tool_name, arguments, reason), timeout=timeout_sec)

    except asyncio.TimeoutError:

        logger.warn('Human CLI approval timed out, denying execution')

        return False



def run_init_cli():

    import getpass

    import httpx

    console = Console()

    console.print('[bold cyan]MCP Firewall Configuration Setup[/bold cyan]')

    console.print('═' * 40)

    console.print('')

    console.print('Which Judge LLM provider do you want to use?')

    console.print('1) Google Gemini (default: gemini-2.5-flash)')

    console.print('2) Ollama (local model: llama3.1 or qwen2.5)')

    console.print('')

    choice = input('Enter choice [1-2]: ').strip()

    provider = 'gemini'

    if choice == '2':

        provider = 'ollama'

    api_key = ''

    if provider in ('gemini',):

        prompt_msg = f'Enter your {provider.upper()} API Key (hidden): '

        api_key = getpass.getpass(prompt_msg).strip()

        if not api_key:

            console.print('[red]Error: API Key is required for remote providers.[/red]')

            return

    console.print(f'[yellow]Validating {provider} connection...[/yellow]')

    validation_ok = False

    try:

        if provider == 'gemini':

            url = f'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}'

            body = {'contents': {'parts': [{'text': 'hello'}]}, 'generationConfig': {'maxOutputTokens': 1}}

            resp = httpx.post(url, json=body, timeout=5.0)

            if resp.status_code == 200:

                validation_ok = True

            else:

                console.print(f'[red]Gemini validation failed (HTTP {resp.status_code}): {resp.text}[/red]')

        elif provider == 'ollama':

            resp = httpx.get('http://localhost:11434/api/tags', timeout=3.0)

            if resp.status_code == 200:

                validation_ok = True

                console.print('[green]Ollama connection succeeded.[/green]')

            else:

                console.print(f'[red]Ollama returned error: HTTP {resp.status_code}[/red]')

    except Exception as e:

        console.print(f'[red]An error occurred during validation: {str(e)}[/red]')

    if not validation_ok and provider != 'ollama':

        console.print('[yellow]Could not verify API Key with the provider.[/yellow]')

        proceed = input('Do you want to proceed and save changes anyway? [y/N]: ').strip().lower()

        if proceed not in ('y', 'yes'):

            return

    if validation_ok:

        console.print('[green]✓ Key validation / connection check succeeded![/green]')

    console.print('')

    console.print('Where should this configuration live?')

    console.print('1) .env in the current directory (recommended for local workspace development)')

    console.print('2) Global user config (~/.config/blockade/config.env)')

    console.print('')

    loc_choice = input('Enter choice [1-2]: ').strip()

    if loc_choice == '2':

        conf_path = os.path.expanduser('~/.config/blockade/config.env')

    else:

        conf_path = os.path.abspath('.env')

    env_content = f'JUDGE_PROVIDER={provider}\n'

    if provider == 'gemini':

        env_content += f'GEMINI_API_KEY={api_key}\n'

    try:

        os.makedirs(os.path.dirname(conf_path), exist_ok=True)

        if os.path.exists(conf_path):

            overwrite = input(f'File {conf_path} already exists. Overwrite? [y/N]: ').strip().lower()

            if overwrite not in ('y', 'yes'):

                console.print('[yellow]Setup aborted.[/yellow]')

                return

        with open(conf_path, 'w', encoding='utf-8') as f:

            f.write(env_content)

        console.print(f'[green]✓ Config successfully written to {conf_path}[/green]')

        if loc_choice != '2':

            if os.path.exists('.git'):

                git_ignore_path = '.gitignore'

                has_env = False

                if os.path.exists(git_ignore_path):

                    with open(git_ignore_path, 'r', encoding='utf-8') as gf:

                        if '.env' in gf.read():

                            has_env = True

                if not has_env:

                    with open(git_ignore_path, 'a', encoding='utf-8') as gf:

                        gf.write('\n# MCP Firewall secrets\n.env\n')

                    console.print('[green]✓ Added .env rule to .gitignore[/green]')

    except Exception as e:

        console.print(f'[red]Failed writing configuration: {str(e)}[/red]')
