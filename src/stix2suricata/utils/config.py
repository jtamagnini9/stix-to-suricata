"""Configuration management"""

import yaml
import os
from typing import Any


class Config:
    """Configuration handler"""
    
    def __init__(self, config_path: str = None):
        self.config = {}
        
        if config_path and os.path.exists(config_path):
            self.load(config_path)
        else:
            self.load_defaults()
    
    def load(self, config_path: str):
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
    
    def load_defaults(self):
        """Load default configuration"""
        self.config = {
            'suricata': {
                'sid_start': 5000000,
                'default_priority': 2,
                'default_classtype': 'trojan-activity',
                'default_action': 'alert'
            },
            'logging': {
                'level': 'INFO'
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
