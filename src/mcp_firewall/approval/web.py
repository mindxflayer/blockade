import os

import uuid

import asyncio

import threading

from typing import Dict, Any

from fastapi import FastAPI, HTTPException

from fastapi.responses import HTMLResponse

from pydantic import BaseModel

import uvicorn

import structlog

logger = structlog.get_logger()

app = FastAPI(title='MCP Firewall Approval Hub')

pending_decisions: Dict[str, Dict[str, Any]] = {}



class DecisionPayload(BaseModel):

    decision: str



@app.get('/approve/{req_id}', response_class=HTMLResponse)

async def serve_approval_page(req_id: str):

    if req_id not in pending_decisions:

        raise HTTPException(status_code=404, detail='Approval request expired or not found')

    data = pending_decisions[req_id]

    import json

    import html

    args_json = html.escape(json.dumps(data['arguments'], indent=2))

    safe_tool_name = html.escape(data['tool_name'])

    safe_reason = html.escape(data['reason'])

    html_content = f"""\n    <!DOCTYPE html>\n    <html lang="en">\n    <head>\n        <meta charset="UTF-8">\n        <meta name="viewport" content="width=device-width, initial-scale=1.0">\n        <title>MCP Firewall - Approval Gate</title>\n        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">\n        <style>\n            :root {{\n                --bg: #0b0c10;\n                --surface: #1f2833;\n                --accent: #66fcf1;\n                --accent-hover: #45a29e;\n                --text-main: #c5c6c7;\n                --text-bright: #ffffff;\n                --danger: #ff4d4d;\n                --success: #2ecc71;\n            }}\n            * {{\n                box-sizing: border-box;\n                margin: 0;\n                padding: 0;\n            }}\n            body {{\n                background-color: var(--bg);\n                color: var(--text-main);\n                font-family: 'Outfit', sans-serif;\n                display: flex;\n                justify-content: center;\n                align-items: center;\n                min-height: 100vh;\n                padding: 20px;\n                overflow-x: hidden;\n            }}\n            .card {{\n                background: linear-gradient(135deg, rgba(31, 40, 51, 0.8), rgba(11, 12, 16, 0.9));\n                border: 1px solid rgba(102, 252, 241, 0.2);\n                border-radius: 16px;\n                width: 100%;\n                max-width: 650px;\n                padding: 40px;\n                box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);\n                backdrop-filter: blur(8px);\n                position: relative;\n                animation: fadeIn 0.5s ease-out;\n            }}\n            @keyframes fadeIn {{\n                from {{ opacity: 0; transform: translateY(20px); }}\n                to {{ opacity: 1; transform: translateY(0); }}\n            }}\n            .card::before {{\n                content: '';\n                position: absolute;\n                top: -2px; left: -2px; right: -2px; bottom: -2px;\n                background: linear-gradient(280deg, var(--accent), transparent, var(--danger));\n                border-radius: 17px;\n                z-index: -1;\n                filter: blur(10px);\n                opacity: 0.15;\n            }}\n            h1 {{\n                font-size: 2.2rem;\n                font-weight: 800;\n                color: var(--text-bright);\n                margin-bottom: 8px;\n                text-transform: uppercase;\n                background: linear-gradient(to right, var(--text-bright), var(--accent));\n                -webkit-background-clip: text;\n                -webkit-text-fill-color: transparent;\n            }}\n            .badge {{\n                display: inline-block;\n                padding: 4px 12px;\n                border-radius: 20px;\n                font-size: 0.8rem;\n                font-weight: 600;\n                background-color: rgba(255, 77, 77, 0.2);\n                color: var(--danger);\n                border: 1px solid rgba(255, 77, 77, 0.4);\n                margin-bottom: 24px;\n            }}\n            .meta {{\n                margin-bottom: 24px;\n            }}\n            .meta-item {{\n                margin-bottom: 12px;\n            }}\n            .meta-label {{\n                font-size: 0.9rem;\n                text-transform: uppercase;\n                color: var(--accent);\n                letter-spacing: 1px;\n                margin-bottom: 4px;\n            }}\n            .meta-val {{\n                font-size: 1.2rem;\n                color: var(--text-bright);\n                font-weight: 600;\n            }}\n            .reason-box {{\n                background-color: rgba(255,255,255,0.02);\n                border-left: 3px solid var(--accent);\n                padding: 12px;\n                border-radius: 4px;\n                font-size: 0.95rem;\n                line-height: 1.5;\n            }}\n            .args-label {{\n                font-size: 0.9rem;\n                text-transform: uppercase;\n                color: var(--accent);\n                letter-spacing: 1px;\n                margin-bottom: 8px;\n                margin-top: 24px;\n            }}\n            pre {{\n                background-color: #0b0c10;\n                border: 1px solid rgba(255, 255, 255, 0.05);\n                border-radius: 8px;\n                padding: 16px;\n                font-family: 'JetBrains Mono', monospace;\n                font-size: 0.9rem;\n                overflow-x: auto;\n                color: #a9b7c6;\n                max-height: 250px;\n            }}\n            .actions {{\n                display: flex;\n                gap: 20px;\n                margin-top: 32px;\n            }}\n            button {{\n                flex: 1;\n                padding: 14px;\n                border: none;\n                border-radius: 8px;\n                font-family: 'Outfit', sans-serif;\n                font-size: 1.1rem;\n                font-weight: 600;\n                cursor: pointer;\n                transition: all 0.2s ease;\n            }}\n            .btn-approve {{\n                background-color: var(--success);\n                color: var(--bg);\n                box-shadow: 0 4px 14px rgba(46, 204, 113, 0.3);\n            }}\n            .btn-approve:hover {{\n                opacity: 0.9;\n                transform: translateY(-2px);\n            }}\n            .btn-deny {{\n                background-color: var(--danger);\n                color: var(--text-bright);\n                box-shadow: 0 4px 14px rgba(255, 77, 77, 0.3);\n            }}\n            .btn-deny:hover {{\n                opacity: 0.9;\n                transform: translateY(-2px);\n            }}\n            .btn-disabled {{\n                opacity: 0.5 !important;\n                cursor: not-allowed;\n                transform: none !important;\n            }}\n            #status-banner {{\n                margin-top: 20px;\n                text-align: center;\n                font-weight: 600;\n                font-size: 1.1rem;\n            }}\n        </style>\n    </head>\n    <body>\n        <div class="card">\n            <h1>MCP Firewall</h1>\n            <div class="badge">Awaiting Authorization</div>\n            \n            <div class="meta">\n                <div class="meta-item">\n                    <div class="meta-label">Requested Tool</div>\n                    <div class="meta-val">{safe_tool_name}</div>\n                </div>\n                <div class="meta-item">\n                    <div class="meta-label">Verdict Reason</div>\n                    <div class="reason-box">{safe_reason}</div>\n                </div>\n            </div>\n            \n            <div class="args-label">Arguments</div>\n            <pre><code>{args_json}</code></pre>\n            \n            <div class="actions" id="action-panel">\n                <button class="btn-deny" onclick="submitDecision('deny')">DENY EXECUTION</button>\n                <button class="btn-approve" onclick="submitDecision('allow')">APPROVE TOOL</button>\n            </div>\n            \n            <div id="status-banner"></div>\n        </div>\n        \n        <script>\n            async function submitDecision(verdict) {{\n                const pnl = document.getElementById('action-panel');\n                const banner = document.getElementById('status-banner');\n                \n                // Disable interface\n                const buttons = pnl.getElementsByTagName('button');\n                for (let btn of buttons) {{\n                    btn.classList.add('btn-disabled');\n                    btn.disabled = true;\n                }}\n                \n                try {{\n                    const res = await fetch('/api/decide/{req_id}', {{\n                        method: 'POST',\n                        headers: {{ 'Content-Type': 'application/json' }},\n                        body: JSON.stringify({{ decision: verdict }})\n                    }});\n                    \n                    if (res.ok) {{\n                        if (verdict === 'allow') {{\n                            banner.style.color = 'var(--success)';\n                            banner.innerText = '✓ Tool request approved successfully. You may close this tab.';\n                        }} else {{\n                            banner.style.color = 'var(--danger)';\n                            banner.innerText = '✗ Tool request blocked. You may close this tab.';\n                        }}\n                    }} else {{\n                        const err = await res.text();\n                        banner.style.color = 'var(--danger)';\n                        banner.innerText = 'Error submitting response: ' + err;\n                    }}\n                }} catch (e) {{\n                    banner.style.color = 'var(--danger)';\n                    banner.innerText = 'Network error: ' + e;\n                }}\n            }}\n        </script>\n    </body>\n    </html>\n    """

    return html_content



@app.post('/api/decide/{req_id}')

async def submit_decision(req_id: str, payload: DecisionPayload):

    if req_id not in pending_decisions:

        raise HTTPException(status_code=404, detail='Request expired or not found')

    data = pending_decisions.pop(req_id)

    fut = data['future']

    loop = fut.get_loop()

    loop.call_soon_threadsafe(fut.set_result, payload.decision == 'allow')

    return {'status': 'success'}

_server_thread: threading.Thread = None

_web_port = int(os.getenv('MCP_FIREWALL_WEB_PORT', '8082'))



def start_web_server():

    global _server_thread

    if _server_thread is not None:

        return



    def run():

        config = uvicorn.Config(app, host='127.0.0.1', port=_web_port, log_level='warning')

        server = uvicorn.Server(config)

        server.run()

    _server_thread = threading.Thread(target=run, daemon=True)

    _server_thread.start()

    logger.info('Local Web Approval server started', port=_web_port)



async def prompt_human_web(tool_name: str, arguments: dict, reason: str) -> bool:

    req_id = 'req_' + str(uuid.uuid4().hex[:8])

    loop = asyncio.get_running_loop()

    fut = loop.create_future()

    pending_decisions[req_id] = {'future': fut, 'tool_name': tool_name, 'arguments': arguments, 'reason': reason}

    approval_url = f'http://127.0.0.1:{_web_port}/approve/{req_id}'

    from rich.console import Console

    from rich.panel import Panel

    console = Console(stderr=True)

    panel_info = f'[bold red]⛔ HIGH RISK TOOL BLOCKED - HUMAN INTERVENTION REQUIRED[/bold red]\n\n[bold]Tool Name:[/bold] {tool_name}\n[bold]Warning Reason:[/bold] {reason}\n\n[bold yellow]👉 Approve via URL:[/bold yellow] [underline]{approval_url}[/underline]'

    console.print(Panel(panel_info, border_style='red'))

    start_web_server()

    timeout_sec = int(os.getenv('APPROVAL_TIMEOUT_SECONDS', '300'))

    try:

        approved = await asyncio.wait_for(fut, timeout=timeout_sec)

        return approved

    except asyncio.TimeoutError:

        logger.warn('Human web approval timed out, denying execution', req_id=req_id)

        pending_decisions.pop(req_id, None)

        return False

    except Exception as e:

        logger.exception('Web approval waiting failed', error=str(e))

        return False
