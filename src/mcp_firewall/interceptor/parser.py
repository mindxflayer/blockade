import os

import structlog

from typing import Dict, Tuple

from mcp_firewall.policy.engine import PolicyEngine

from mcp_firewall.audit.db import AuditLogger

logger = structlog.get_logger()

policy_engine = PolicyEngine()

audit_logger = AuditLogger()

_pending_requests: Dict[int, dict] = {}



def track_request(request_id: int, method: str):

    _pending_requests[request_id] = {'method': method, 'risk_tier': 'low', 'tool_name': None}

    logger.debug('Tracking pending request', request_id=request_id, method=method)



def get_pending_request_info(request_id: int) -> dict | None:

    return _pending_requests.pop(request_id, None)



async def intercept_request(request: dict) -> Tuple[bool, str, dict]:

    method = request.get('method')

    req_id = request.get('id')

    if req_id is not None and method:

        track_request(req_id, method)

    

    if method == 'tools/call':

        params = request.get('params', {})

        tool_name = params.get('name')

        arguments = params.get('arguments', {})

        profile = os.getenv('MCP_PROFILE', 'default')

        action_result = policy_engine.evaluate(tool_name, profile)

        if isinstance(action_result, dict):

            action = action_result.get('action', 'deny')

            sandbox_config = action_result

        else:

            action = action_result

            sandbox_config = {}

            

        logger.info('Evaluating tool call request with policy', id=req_id, tool=tool_name, profile=profile, action=action)

        

                                                                           

        is_sink = tool_name in ('run_command', 'write_file', 'fetch', 'http_post') or action in ('sandbox', 'judge', 'approve', 'approve_medium', 'approve_high')

        if is_sink:

            from mcp_firewall.taint.tracker import check_taint

            if check_taint(arguments):

                logger.error("Confused deputy attack detected: tainted data passed to sink tool", tool=tool_name)

                await audit_logger.log_decision(tool_name=tool_name, arguments=arguments, profile=profile, policy_verdict=action, final_action='deny', judge_reasoning='Tainted data detected in sink arguments')

                _pending_requests.pop(req_id, None)

                return (False, f"Blocked by taint tracking: Untrusted data from a previous tool call was passed to '{tool_name}'", request)

                

        if action == 'deny':

            await audit_logger.log_decision(tool_name=tool_name, arguments=arguments, profile=profile, policy_verdict=action, final_action='deny')

            _pending_requests.pop(req_id, None)

            return (False, f"Blocked by policy profile '{profile}' for tool '{tool_name}'", request)

        elif action == 'sandbox':

            from mcp_firewall.sandbox.docker_exec import run_sandboxed

            import json

            try:

                result = await run_sandboxed(arguments, sandbox_config)

                redirect_payload = 'SANDBOX_REDIRECT:' + json.dumps(result)

                await audit_logger.log_decision(tool_name=tool_name, arguments=arguments, profile=profile, policy_verdict=action, final_action='sandbox')

                _pending_requests.pop(req_id, None)

                return (False, redirect_payload, request)

            except Exception as e:

                logger.exception('Sandbox execution failed', error=str(e))

                _pending_requests.pop(req_id, None)

                return (False, f'Sandbox failed to execute: {str(e)}', request)

        elif action == 'allow' or action == 'audit':

            await audit_logger.log_decision(tool_name=tool_name, arguments=arguments, profile=profile, policy_verdict=action, final_action='allow')

            return (True, '', request)

        from mcp_firewall.judge.factory import get_judge

        needs_judge = action in ('judge', 'approve_medium', 'approve_high')

        verdict = None

        if needs_judge:

            try:

                judge = get_judge()

                verdict = await judge.classify(tool_name, arguments)

            except Exception as e:

                logger.exception('Judge LLM classification failed, defaulting to safe deny', error=str(e))

                _pending_requests.pop(req_id, None)

                return (False, f'Judge LLM failed to evaluate request safety: {str(e)}', request)

        risk_tier = verdict.risk_tier if verdict else 'low'

        reason = verdict.reasoning if verdict else ''

        flags = verdict.flags if verdict else []

        

        if req_id in _pending_requests:

            _pending_requests[req_id]['risk_tier'] = risk_tier

            _pending_requests[req_id]['tool_name'] = tool_name

        if action == 'judge' and risk_tier == 'high':

            await audit_logger.log_decision(tool_name=tool_name, arguments=arguments, profile=profile, policy_verdict=action, judge_verdict=risk_tier, judge_reasoning=reason, final_action='deny')

            _pending_requests.pop(req_id, None)

            return (False, f"Blocked by Judge LLM (high risk): {reason} (flags: {', '.join(flags)})", request)

        is_gated = action == 'approve' or (action == 'approve_medium' and risk_tier in ('medium', 'high')) or (action == 'approve_high' and risk_tier == 'high')

        if is_gated:

            from mcp_firewall.approval.cli import prompt_human_cli

            from mcp_firewall.approval.web import prompt_human_web

            app_mode = os.getenv('APPROVAL_MODE', 'cli').lower()

            reason_str = reason or f"Gated by policy action '{action}' (risk: {risk_tier})"

            logger.info('Requesting human approval for tool call', tool=tool_name, mode=app_mode)

            if app_mode == 'web':

                approved = await prompt_human_web(tool_name, arguments, reason_str)

            else:

                approved = await prompt_human_cli(tool_name, arguments, reason_str)

            if not approved:

                await audit_logger.log_decision(tool_name=tool_name, arguments=arguments, profile=profile, policy_verdict=action, judge_verdict=risk_tier if verdict else None, judge_reasoning=reason if verdict else None, human_approved=False, final_action='deny')

                _pending_requests.pop(req_id, None)

                return (False, 'Gated tool call rejected by human supervisor', request)

            else:

                await audit_logger.log_decision(tool_name=tool_name, arguments=arguments, profile=profile, policy_verdict=action, judge_verdict=risk_tier if verdict else None, judge_reasoning=reason if verdict else None, human_approved=True, final_action='allow')

                return (True, '', request)

        await audit_logger.log_decision(tool_name=tool_name, arguments=arguments, profile=profile, policy_verdict=action, judge_verdict=risk_tier if verdict else None, judge_reasoning=reason if verdict else None, final_action='allow')

        return (True, '', request)

    elif method and not method.startswith("notifications/"):

                                                                                                        

        profile = os.getenv('MCP_PROFILE', 'default')

        params = request.get('params', {})

        action_result = policy_engine.evaluate(method, profile)

        action = action_result.get('action', 'deny') if isinstance(action_result, dict) else action_result

        

        if action == 'deny':

            await audit_logger.log_decision(tool_name=method, arguments=params, profile=profile, policy_verdict=action, final_action='deny')

            _pending_requests.pop(req_id, None)

            return (False, f"Blocked by policy profile '{profile}' for method '{method}'", request)

            

        await audit_logger.log_decision(tool_name=method, arguments=params, profile=profile, policy_verdict=action, final_action='allow')

        return (True, '', request)

        

    return (True, '', request)



async def intercept_response(req_info: dict | None, response: dict) -> dict:

    if not req_info:

        return response

        

    request_method = req_info.get('method')

    logger.debug('Intercepting response', method=request_method, response=response)

    

    if request_method == 'tools/list':

        server_id = os.getenv('MCP_SERVER_ID', 'default_server')

        result = response.get('result', {})

        tools = result.get('tools', [])

        from mcp_firewall.taint.schema_pinning import check_and_pin_tools

        success, alarm_str = check_and_pin_tools(server_id, tools)

        if not success:

            logger.error('Rug-pull detected, returning JSON-RPC error', server=server_id)

            return {'jsonrpc': '2.0', 'id': response.get('id'), 'error': {'code': -32603, 'message': f'Blocked by MCP Firewall rug-pull defense: {alarm_str}'}}

            

    elif request_method == 'tools/call' and 'result' in response:

        risk_tier = req_info.get('risk_tier', 'low')

        tool_name = req_info.get('tool_name', 'unknown')

        judge_results = os.getenv('JUDGE_RESULTS', 'false').lower() == 'true'

        

        if risk_tier == 'high' or judge_results:

            from mcp_firewall.judge.factory import get_judge

            try:

                judge = get_judge()

                                                                                                  

                if hasattr(judge, 'classify_result'):

                    res_verdict = await judge.classify_result(tool_name, response['result'])

                else:

                                                                                                 

                    res_verdict = await judge.classify(tool_name, {"result": response['result']})

                    

                if res_verdict.risk_tier == 'high' and ('injection' in res_verdict.flags or 'exfiltration' in res_verdict.flags):

                    logger.error('Prompt injection or malicious payload detected in tool result!', tool=tool_name, reason=res_verdict.reasoning)

                    return {

                        'jsonrpc': '2.0', 

                        'id': response.get('id'), 

                        'error': {

                            'code': -32603, 

                            'message': f'Blocked by MCP Firewall: Malicious tool result detected (flags: {", ".join(res_verdict.flags)})'

                        }

                    }

            except Exception as e:

                logger.exception('Failed to evaluate tool result with Judge LLM', error=str(e))

                

                                                

        is_source = any(s in tool_name.lower() for s in ('read', 'fetch', 'get', 'list', 'search'))

        if is_source:

            from mcp_firewall.taint.tracker import mark_tainted

            mark_tainted(response['result'], source=tool_name)

                

    return response
