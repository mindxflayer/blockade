import os

import sqlite3

import json

import re

from datetime import datetime

from typing import Optional, List, Dict, Any

import structlog

logger = structlog.get_logger()



class AuditLogger:

    SECRET_PATTERNS = [re.compile('AKIA[0-9A-Z]{16}'), re.compile('ey[A-Za-z0-9-_=]+\\.ey[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*'), re.compile('(?:sk-|ghp_)[a-zA-Z0-9_.-]{20,}'), re.compile('Bearer\\s+[a-zA-Z0-9_.-]+'), re.compile('-----BEGIN[A-Z\\s]+PRIVATE KEY-----')]



    def __init__(self, db_path: Optional[str]=None):

        self.db_path = db_path or os.getenv('MCP_AUDIT_DB_PATH') or os.path.expanduser('~/.config/blockade/audit.db')

        self._init_db()



    def _init_db(self):

        try:

            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

            with sqlite3.connect(self.db_path) as conn:

                cursor = conn.cursor()

                cursor.execute('PRAGMA journal_mode=WAL;')

                                                                            
                try:
                    cursor.execute("PRAGMA table_info(audit_logs)")
                    cols = [r[1] for r in cursor.fetchall()]
                    if 'role' in cols:
                        cursor.execute("DROP TABLE audit_logs")
                except Exception:
                    pass

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        arguments TEXT,
                        profile TEXT NOT NULL DEFAULT 'default',
                        policy_verdict TEXT NOT NULL,
                        judge_verdict TEXT,
                        judge_reasoning TEXT,
                        human_approved INTEGER, -- 1=Approved, 0=Denied, NULL=Not Gated
                        final_action TEXT NOT NULL -- 'allow', 'deny'
                    )
                """)

                                                                            

                try:

                    cursor.execute("ALTER TABLE audit_logs ADD COLUMN profile TEXT NOT NULL DEFAULT 'default'")

                except sqlite3.OperationalError:

                    pass                                

                conn.commit()

            logger.info('Initialized audit database', path=self.db_path)

        except Exception as e:

            logger.exception('Failed to initialize audit database', path=self.db_path, error=str(e))



    async def log_decision(self, tool_name: str, arguments: Dict[str, Any], profile: str, policy_verdict: str, judge_verdict: Optional[str]=None, judge_reasoning: Optional[str]=None, human_approved: Optional[bool]=None, final_action: str='deny') -> int:

        import asyncio

        loop = asyncio.get_running_loop()

        clean_args = self._redact_secrets(arguments)

        args_str = json.dumps(clean_args)

        if len(args_str) > 100000:

            args_str = args_str[:100000] + '...[TRUNCATED]'

            

        timestamp = datetime.utcnow().isoformat()

        approved_val = None

        if human_approved is not None:

            approved_val = 1 if human_approved else 0



        def _sync_write():

            try:

                with sqlite3.connect(self.db_path) as conn:

                    cursor = conn.cursor()

                    cursor.execute('\n                        INSERT INTO audit_logs (\n                            timestamp, tool_name, arguments, profile, policy_verdict,\n                            judge_verdict, judge_reasoning, human_approved, final_action\n                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)\n                    ', (timestamp, tool_name, args_str, profile, policy_verdict, judge_verdict, judge_reasoning, approved_val, final_action))

                    conn.commit()

                    row_id = cursor.lastrowid or -1

                    logger.debug('Logged firewall decision to database', log_id=row_id, tool=tool_name, action=final_action)

                    return row_id

            except Exception as e:

                logger.exception('Failed to write to audit log database', error=str(e))

                return 0

        return await loop.run_in_executor(None, _sync_write)



    def _redact_secrets(self, data: Any, parent_key: str = None) -> Any:

        if isinstance(data, dict):

            return {k: self._redact_secrets(v, k) for k, v in data.items()}

        elif isinstance(data, list):

            return [self._redact_secrets(item, parent_key) for item in data]

        elif isinstance(data, str):

            for pattern in self.SECRET_PATTERNS:

                if pattern.match(data):

                    return '[REDACTED_PATTERN]'

            if parent_key and any((s in parent_key.lower() for s in ['key', 'secret', 'token', 'password', 'auth', 'credential'])):

                return '[REDACTED]'

            return data

        return data



    def get_logs(self, limit: int=50) -> List[Dict[str, Any]]:

        try:

            with sqlite3.connect(self.db_path) as conn:

                conn.row_factory = sqlite3.Row

                cursor = conn.cursor()

                cursor.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?', (limit,))

                rows = cursor.fetchall()

                return [dict(row) for row in rows]

        except Exception as e:

            logger.exception('Failed to retrieve audit logs', error=str(e))

            return []
