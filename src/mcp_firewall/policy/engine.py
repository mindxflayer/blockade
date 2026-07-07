import os

import fnmatch

from typing import Dict, Optional

import yaml

from pydantic import BaseModel, Field

import structlog

logger = structlog.get_logger()

DEFAULT_POLICY_YAML = '\ndefault_profile: default\nprofiles:\n  default:\n    tools:\n      "read_file": "allow"\n      "write_file": "approve_medium"\n      "run_command": "approve_high"\n      "*": "judge"\n'



from typing import Dict, Optional, Union, Any



class ProfilePolicy(BaseModel):

    tools: Dict[str, Union[str, Dict[str, Any]]] = Field(default_factory=dict, description="Map of tool name patterns (e.g. 'filesystem:*') to actions (allow, deny, audit, judge, approve, approve_medium, approve_high) or complex configs")



class FirewallPolicy(BaseModel):

    default_profile: str = 'default'

    profiles: Dict[str, ProfilePolicy] = Field(default_factory=dict)



class PolicyEngine:



    def __init__(self, policy_path: Optional[str]=None):

        self.policy_path = policy_path or os.getenv('MCP_POLICY_PATH') or os.path.expanduser('~/.config/blockade/policies.yaml')

        self.policy = self._load_policy()



    def _load_policy(self) -> FirewallPolicy:

        if not os.path.exists(self.policy_path):

            try:

                os.makedirs(os.path.dirname(self.policy_path), exist_ok=True)

                with open(self.policy_path, 'w', encoding='utf-8') as f:

                    f.write(DEFAULT_POLICY_YAML.strip())

                logger.info('Created default policy configuration', path=self.policy_path)

            except Exception as e:

                logger.warning('Could not create default policy directory/file, using memory fallback', error=str(e))

                return FirewallPolicy.model_validate(yaml.safe_load(DEFAULT_POLICY_YAML))

        try:
            with open(self.policy_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data and 'roles' in data and 'profiles' not in data:
                    data['profiles'] = data.pop('roles')
                    if 'default_role' in data and 'default_profile' not in data:
                        data['default_profile'] = data.pop('default_role')
                    try:
                        with open(self.policy_path, 'w', encoding='utf-8') as wf:
                            yaml.dump(data, wf)
                        logger.info('Migrated legacy roles configuration to profiles', path=self.policy_path)
                    except Exception as we:
                        logger.warning('Failed to write migrated config back to file', error=str(we))
                return FirewallPolicy.model_validate(data)
        except Exception as e:
            logger.exception('Failed to load policy configuration, fallback to default schema', error=str(e))
            return FirewallPolicy.model_validate(yaml.safe_load(DEFAULT_POLICY_YAML))



    def reload(self):

        self.policy = self._load_policy()



    def evaluate(self, tool_name: str, profile: Optional[str]=None) -> Union[str, Dict[str, Any]]:

        profile = profile or self.policy.default_profile

        profile_config = self.policy.profiles.get(profile)

        if not profile_config:

            logger.warn('Specified profile not found in policy, falling back to default', profile=profile)

            profile_config = self.policy.profiles.get(self.policy.default_profile)

        if not profile_config:

            logger.error('Default policy profile configuration missing, denying execution')

            return 'deny'

        matched_action = None

        patterns = list(profile_config.tools.keys())

        patterns.sort(key=lambda x: (x.count('*'), -len(x)))

        for pattern in patterns:

            if fnmatch.fnmatch(tool_name, pattern):

                matched_action = profile_config.tools[pattern]

                logger.debug('Matched tool pattern rule', tool=tool_name, pattern=pattern, action=matched_action)

                break

        if not matched_action:

            logger.warn('No policy rules matched for tool call, fallback to judge', tool=tool_name)

            return 'judge'

        return matched_action
