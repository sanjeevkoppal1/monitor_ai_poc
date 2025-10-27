#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor - Configuration Management
Comprehensive configuration loading, validation, and management system.
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
import tempfile
import shutil
from datetime import datetime

import structlog
logger = structlog.get_logger()


@dataclass
class ConfigValidationError:
    """Represents a configuration validation error."""
    path: str                    # Configuration path where error occurred
    message: str                 # Error message
    severity: str = "error"      # error, warning, info
    suggestion: Optional[str] = None  # Suggested fix


class ConfigManager:
    """
    Comprehensive configuration management for Crown Jewel Monitor.
    
    Features:
    - YAML configuration loading with environment variable substitution
    - Configuration validation with detailed error reporting
    - Hot-reload capability with change detection
    - Default value injection and schema validation
    - Environment-specific configuration merging
    """
    
    def __init__(self, config_path: Union[str, Path]):
        """
        Initialize configuration manager.
        
        Args:
            config_path: Path to primary configuration file
        """
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.validation_errors: List[ConfigValidationError] = []
        self.last_modified: Optional[datetime] = None
        self.environment = os.getenv('CROWN_JEWEL_ENV', 'development')
        
        logger.info("ConfigManager initialized",
                   config_path=str(self.config_path),
                   environment=self.environment)
    
    async def load_config(self) -> bool:
        """
        Load configuration from file with validation.
        
        Returns:
            True if loading successful, False otherwise
        """
        try:
            logger.info("Loading configuration", config_path=str(self.config_path))
            
            # Check if config file exists
            if not self.config_path.exists():
                logger.error("Configuration file not found", path=str(self.config_path))
                return False
            
            # Load primary configuration
            with open(self.config_path, 'r') as f:
                raw_config = yaml.safe_load(f)
            
            if not raw_config:
                logger.error("Configuration file is empty or invalid")
                return False
            
            # Perform environment variable substitution
            self.config = self._substitute_environment_variables(raw_config)
            
            # Load environment-specific overrides
            await self._load_environment_overrides()
            
            # Apply default values
            self._apply_defaults()
            
            # Validate configuration
            if not await self._validate_config():
                logger.error("Configuration validation failed",
                           errors=[e.message for e in self.validation_errors])
                return False
            
            # Update modification time
            self.last_modified = datetime.fromtimestamp(self.config_path.stat().st_mtime)
            
            logger.info("Configuration loaded successfully",
                       sections=list(self.config.keys()))
            return True
            
        except yaml.YAMLError as e:
            logger.error("YAML parsing error", error=str(e))
            return False
        except Exception as e:
            logger.error("Error loading configuration", error=str(e))
            return False
    
    def get_config(self) -> Dict[str, Any]:
        """
        Get the current configuration.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config.copy()
    
    def get_section(self, section: str, default: Any = None) -> Any:
        """
        Get a specific configuration section.
        
        Args:
            section: Section name (supports dot notation like 'global.log_level')
            default: Default value if section not found
            
        Returns:
            Configuration section value or default
        """
        return self._get_nested_value(self.config, section, default)
    
    def set_value(self, path: str, value: Any) -> None:
        """
        Set a configuration value (runtime only).
        
        Args:
            path: Configuration path (dot notation)
            value: Value to set
        """
        self._set_nested_value(self.config, path, value)
    
    async def reload_if_changed(self) -> bool:
        """
        Reload configuration if file has changed.
        
        Returns:
            True if configuration was reloaded, False if no changes
        """
        try:
            if not self.config_path.exists():
                return False
            
            current_modified = datetime.fromtimestamp(self.config_path.stat().st_mtime)
            
            if self.last_modified and current_modified <= self.last_modified:
                return False
            
            logger.info("Configuration file changed, reloading")
            return await self.load_config()
            
        except Exception as e:
            logger.error("Error checking configuration changes", error=str(e))
            return False
    
    async def validate_config_file(self, config_path: Path) -> List[ConfigValidationError]:
        """
        Validate a configuration file without loading it.
        
        Args:
            config_path: Path to configuration file to validate
            
        Returns:
            List of validation errors
        """
        errors = []
        
        try:
            if not config_path.exists():
                errors.append(ConfigValidationError(
                    path=str(config_path),
                    message="Configuration file not found"
                ))
                return errors
            
            # Load and parse YAML
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if not config:
                errors.append(ConfigValidationError(
                    path=str(config_path),
                    message="Configuration file is empty"
                ))
                return errors
            
            # Perform validation
            temp_manager = ConfigManager(config_path)
            temp_manager.config = self._substitute_environment_variables(config)
            temp_manager._apply_defaults()
            
            await temp_manager._validate_config()
            errors.extend(temp_manager.validation_errors)
            
        except yaml.YAMLError as e:
            errors.append(ConfigValidationError(
                path=str(config_path),
                message=f"YAML parsing error: {str(e)}"
            ))
        except Exception as e:
            errors.append(ConfigValidationError(
                path=str(config_path),
                message=f"Validation error: {str(e)}"
            ))
        
        return errors
    
    def export_config(self, output_path: Path, format: str = 'yaml',
                      include_sensitive: bool = False) -> bool:
        """
        Export current configuration to file.
        
        Args:
            output_path: Output file path
            format: Output format ('yaml' or 'json')
            include_sensitive: Whether to include sensitive values
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            config_to_export = self.config.copy()
            
            # Mask sensitive values if requested
            if not include_sensitive:
                config_to_export = self._mask_sensitive_values(config_to_export)
            
            # Export based on format
            with open(output_path, 'w') as f:
                if format.lower() == 'json':
                    json.dump(config_to_export, f, indent=2, default=str)
                else:
                    yaml.dump(config_to_export, f, default_flow_style=False, indent=2)
            
            logger.info("Configuration exported",
                       output_path=str(output_path),
                       format=format)
            return True
            
        except Exception as e:
            logger.error("Error exporting configuration",
                        output_path=str(output_path),
                        error=str(e))
            return False
    
    # =========================================================================
    # PRIVATE METHODS
    # =========================================================================
    
    def _substitute_environment_variables(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Substitute environment variables in configuration values.
        
        Supports ${VAR_NAME} and ${VAR_NAME:default_value} syntax.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Configuration with environment variables substituted
        """
        def substitute_value(value):
            if isinstance(value, str):
                # Handle ${VAR_NAME} and ${VAR_NAME:default} patterns
                import re
                
                def replace_env_var(match):
                    var_expr = match.group(1)
                    if ':' in var_expr:
                        var_name, default_value = var_expr.split(':', 1)
                        return os.getenv(var_name.strip(), default_value.strip())
                    else:
                        env_value = os.getenv(var_expr.strip())
                        if env_value is None:
                            logger.warning("Environment variable not found",
                                         variable=var_expr.strip())
                            return match.group(0)  # Return original if not found
                        return env_value
                
                return re.sub(r'\$\{([^}]+)\}', replace_env_var, value)
            
            elif isinstance(value, dict):
                return {k: substitute_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [substitute_value(item) for item in value]
            else:
                return value
        
        return substitute_value(config)
    
    async def _load_environment_overrides(self) -> None:
        """
        Load environment-specific configuration overrides.
        """
        # Look for environment-specific config files
        config_dir = self.config_path.parent
        env_config_file = config_dir / f"{self.environment}.yaml"
        
        if env_config_file.exists():
            try:
                logger.info("Loading environment-specific configuration",
                           env_file=str(env_config_file))
                
                with open(env_config_file, 'r') as f:
                    env_config = yaml.safe_load(f)
                
                if env_config:
                    # Merge environment-specific configuration
                    self.config = self._deep_merge(self.config, env_config)
                    
            except Exception as e:
                logger.warning("Error loading environment configuration",
                              env_file=str(env_config_file),
                              error=str(e))
    
    def _apply_defaults(self) -> None:
        """
        Apply default values to configuration.
        """
        defaults = {
            'global': {
                'log_level': 'INFO',
                'monitoring_interval': 60,
                'max_concurrent_agents': 5,
                'data_retention_hours': 24,
                'async_timeout': 30,
                'connection_pool_size': 10,
                'enable_ml_anomaly_detection': True,
                'enable_auto_remediation': False,
                'enable_predictive_alerts': True
            },
            'alerting': {
                'enabled': True,
                'default_severity_threshold': 'medium',
                'alert_suppression_window': 300,
                'max_alerts_per_hour': 100
            },
            'api': {
                'enabled': True,
                'host': '0.0.0.0',
                'port': 8080,
                'debug': False
            },
            'agents': {}
        }
        
        # Merge defaults with current config (config takes precedence)
        self.config = self._deep_merge(defaults, self.config)
    
    async def _validate_config(self) -> bool:
        """
        Validate the loaded configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        self.validation_errors.clear()
        
        # Validate global section
        await self._validate_global_config()
        
        # Validate agents section
        await self._validate_agents_config()
        
        # Validate alerting section
        await self._validate_alerting_config()
        
        # Validate API section
        await self._validate_api_config()
        
        # Return True if no errors
        return len([e for e in self.validation_errors if e.severity == 'error']) == 0
    
    async def _validate_global_config(self) -> None:
        """Validate global configuration section."""
        global_config = self.config.get('global', {})
        
        # Required fields
        # None are strictly required as we have defaults
        
        # Validate numeric ranges
        monitoring_interval = global_config.get('monitoring_interval', 60)
        if not isinstance(monitoring_interval, (int, float)) or monitoring_interval < 10:
            self.validation_errors.append(ConfigValidationError(
                path='global.monitoring_interval',
                message='monitoring_interval must be a number >= 10',
                suggestion='Set to at least 10 seconds'
            ))
        
        max_concurrent = global_config.get('max_concurrent_agents', 5)
        if not isinstance(max_concurrent, int) or max_concurrent < 1:
            self.validation_errors.append(ConfigValidationError(
                path='global.max_concurrent_agents',
                message='max_concurrent_agents must be an integer >= 1'
            ))
        
        # Validate log level
        log_level = global_config.get('log_level', 'INFO')
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            self.validation_errors.append(ConfigValidationError(
                path='global.log_level',
                message='log_level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL'
            ))
    
    async def _validate_agents_config(self) -> None:
        """Validate agents configuration section."""
        agents_config = self.config.get('agents', {})
        
        if not agents_config:
            self.validation_errors.append(ConfigValidationError(
                path='agents',
                message='No agents configured',
                severity='warning',
                suggestion='Configure at least one monitoring agent'
            ))
            return
        
        valid_agent_types = ['splunk', 'java_health', 'proactive_detection', 'remediation']
        
        for agent_id, agent_config in agents_config.items():
            if not isinstance(agent_config, dict):
                self.validation_errors.append(ConfigValidationError(
                    path=f'agents.{agent_id}',
                    message='Agent configuration must be a dictionary'
                ))
                continue
            
            # Validate agent type
            agent_type = agent_config.get('type')
            if not agent_type:
                self.validation_errors.append(ConfigValidationError(
                    path=f'agents.{agent_id}.type',
                    message='Agent type is required'
                ))
            elif agent_type not in valid_agent_types:
                self.validation_errors.append(ConfigValidationError(
                    path=f'agents.{agent_id}.type',
                    message=f'Invalid agent type. Must be one of: {", ".join(valid_agent_types)}'
                ))
            
            # Validate execution interval if present
            execution_interval = agent_config.get('execution_interval')
            if execution_interval is not None:
                if not isinstance(execution_interval, (int, float)) or execution_interval < 10:
                    self.validation_errors.append(ConfigValidationError(
                        path=f'agents.{agent_id}.execution_interval',
                        message='execution_interval must be a number >= 10'
                    ))
    
    async def _validate_alerting_config(self) -> None:
        """Validate alerting configuration section."""
        alerting_config = self.config.get('alerting', {})
        
        # Validate channels
        channels = alerting_config.get('channels', {})
        for channel_id, channel_config in channels.items():
            if not isinstance(channel_config, dict):
                continue
            
            channel_type = channel_config.get('type')
            if not channel_type:
                self.validation_errors.append(ConfigValidationError(
                    path=f'alerting.channels.{channel_id}.type',
                    message='Channel type is required'
                ))
                continue
            
            # Validate channel-specific configuration
            if channel_type == 'slack':
                if not channel_config.get('config', {}).get('webhook_url'):
                    self.validation_errors.append(ConfigValidationError(
                        path=f'alerting.channels.{channel_id}.config.webhook_url',
                        message='Slack webhook URL is required'
                    ))
            
            elif channel_type == 'email':
                email_config = channel_config.get('config', {})
                required_fields = ['smtp_host', 'smtp_username', 'smtp_password', 'from_address']
                for field in required_fields:
                    if not email_config.get(field):
                        self.validation_errors.append(ConfigValidationError(
                            path=f'alerting.channels.{channel_id}.config.{field}',
                            message=f'Email {field} is required'
                        ))
            
            elif channel_type == 'pagerduty':
                if not channel_config.get('config', {}).get('integration_key'):
                    self.validation_errors.append(ConfigValidationError(
                        path=f'alerting.channels.{channel_id}.config.integration_key',
                        message='PagerDuty integration key is required'
                    ))
    
    async def _validate_api_config(self) -> None:
        """Validate API configuration section."""
        api_config = self.config.get('api', {})
        
        # Validate port
        port = api_config.get('port', 8080)
        if not isinstance(port, int) or port < 1 or port > 65535:
            self.validation_errors.append(ConfigValidationError(
                path='api.port',
                message='API port must be an integer between 1 and 65535'
            ))
        
        # Validate host
        host = api_config.get('host', '0.0.0.0')
        if not isinstance(host, str) or not host:
            self.validation_errors.append(ConfigValidationError(
                path='api.host',
                message='API host must be a non-empty string'
            ))
    
    def _get_nested_value(self, data: Dict[str, Any], path: str, default: Any = None) -> Any:
        """
        Get value from nested dictionary using dot notation.
        
        Args:
            data: Dictionary to search
            path: Dot-separated path (e.g., 'global.log_level')
            default: Default value if path not found
            
        Returns:
            Value at path or default
        """
        keys = path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        
        return current
    
    def _set_nested_value(self, data: Dict[str, Any], path: str, value: Any) -> None:
        """
        Set value in nested dictionary using dot notation.
        
        Args:
            data: Dictionary to modify
            path: Dot-separated path
            value: Value to set
        """
        keys = path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge two dictionaries.
        
        Args:
            base: Base dictionary
            override: Override dictionary
            
        Returns:
            Merged dictionary
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _mask_sensitive_values(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mask sensitive configuration values.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Configuration with sensitive values masked
        """
        sensitive_keys = {
            'password', 'passwd', 'token', 'key', 'secret', 'webhook_url',
            'smtp_password', 'integration_key', 'auth_token'
        }
        
        def mask_dict(data):
            if isinstance(data, dict):
                result = {}
                for k, v in data.items():
                    if any(sensitive in k.lower() for sensitive in sensitive_keys):
                        result[k] = "***MASKED***" if v else v
                    else:
                        result[k] = mask_dict(v)
                return result
            elif isinstance(data, list):
                return [mask_dict(item) for item in data]
            else:
                return data
        
        return mask_dict(config)