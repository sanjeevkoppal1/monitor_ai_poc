#!/usr/bin/env python3
"""
Crown Jewel Java Application Monitor - Main Application Entry Point
Primary executable for starting and managing the monitoring system.
"""

import asyncio
import signal
import sys
import os
import argparse
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import yaml

# Configure structured logging
import structlog

from .config.config_manager import ConfigManager
from .core.agent_framework import AgentOrchestrator, AgentFactory
from .core.alerting_system import AlertingSystem
from .api.rest_server import RestAPIServer

# Configure logging
logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=logging.INFO,
)

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger()


class CrownJewelMonitor:
    """
    Main application class for the Crown Jewel Monitor.
    Coordinates all system components and manages application lifecycle.
    """
    
    def __init__(self, config_path: str, log_level: str = "INFO"):
        """
        Initialize the Crown Jewel Monitor application.
        
        Args:
            config_path: Path to configuration file
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        """
        self.config_path = Path(config_path)
        self.log_level = log_level
        
        # Core components
        self.config_manager: Optional[ConfigManager] = None
        self.orchestrator: Optional[AgentOrchestrator] = None
        self.alerting_system: Optional[AlertingSystem] = None
        self.api_server: Optional[RestAPIServer] = None
        
        # Runtime state
        self.running = False
        self.startup_complete = False
        
        # Setup logging
        self._configure_logging()
        
        logger.info("Crown Jewel Monitor initializing",
                   config_path=str(self.config_path),
                   log_level=log_level)
    
    def _configure_logging(self) -> None:
        """Configure application logging based on settings."""
        log_level = getattr(logging, self.log_level.upper(), logging.INFO)
        logging.getLogger().setLevel(log_level)
        
        # Configure structured logging processors based on level
        if log_level == logging.DEBUG:
            # Add more detailed processors for debug mode
            structlog.configure(
                processors=[
                    structlog.stdlib.filter_by_level,
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.processors.UnicodeDecoder(),
                    structlog.dev.ConsoleRenderer()  # More readable for debug
                ],
                context_class=dict,
                logger_factory=structlog.stdlib.LoggerFactory(),
                wrapper_class=structlog.stdlib.BoundLogger,
                cache_logger_on_first_use=True,
            )
    
    async def initialize(self) -> bool:
        """
        Initialize all system components.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            logger.info("Starting Crown Jewel Monitor initialization")
            
            # 1. Load and validate configuration
            logger.info("Loading configuration", config_path=str(self.config_path))
            self.config_manager = ConfigManager(self.config_path)
            
            if not await self.config_manager.load_config():
                logger.error("Failed to load configuration")
                return False
            
            config = self.config_manager.get_config()
            
            # 2. Initialize alerting system
            logger.info("Initializing alerting system")
            alerting_config = config.get('alerting', {})
            self.alerting_system = AlertingSystem(alerting_config)
            
            if not await self.alerting_system.initialize():
                logger.error("Failed to initialize alerting system")
                return False
            
            # 3. Initialize agent orchestrator
            logger.info("Initializing agent orchestrator")
            global_config = config.get('global', {})
            self.orchestrator = AgentOrchestrator(global_config)
            
            # Connect orchestrator to alerting system
            self.orchestrator.set_alerting_system(self.alerting_system)
            
            if not await self.orchestrator.initialize():
                logger.error("Failed to initialize agent orchestrator")
                return False
            
            # 4. Create and register agents
            logger.info("Creating and registering agents")
            await self._create_agents(config)
            
            # 5. Initialize REST API server
            if config.get('api', {}).get('enabled', True):
                logger.info("Initializing REST API server")
                api_config = config.get('api', {})
                self.api_server = RestAPIServer(
                    orchestrator=self.orchestrator,
                    alerting_system=self.alerting_system,
                    config=api_config
                )
                
                if not await self.api_server.initialize():
                    logger.error("Failed to initialize REST API server")
                    return False
            
            logger.info("Crown Jewel Monitor initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error("Error during initialization", error=str(e), exc_info=True)
            return False
    
    async def _create_agents(self, config: Dict[str, Any]) -> None:
        """
        Create and register monitoring agents.
        
        Args:
            config: Application configuration
        """
        agents_config = config.get('agents', {})
        
        for agent_id, agent_config in agents_config.items():
            agent_type = agent_config.get('type')
            enabled = agent_config.get('enabled', True)
            
            if not enabled:
                logger.info("Skipping disabled agent", agent_id=agent_id)
                continue
            
            try:
                logger.info("Creating agent", agent_id=agent_id, agent_type=agent_type)
                
                # Get agent-specific configuration
                agent_specific_config = agent_config.get('config', {})
                
                # Merge with global configuration sections
                if agent_type == 'splunk':
                    agent_specific_config.update(config.get('splunk', {}))
                elif agent_type == 'java_health':
                    agent_specific_config.update(config.get('java_application', {}))
                elif agent_type == 'proactive_detection':
                    agent_specific_config.update(config.get('proactive_detection', {}))
                elif agent_type == 'remediation':
                    agent_specific_config.update(config.get('remediation', {}))
                
                # Create agent using factory
                agent = AgentFactory.create_agent(
                    agent_type=agent_type,
                    agent_id=agent_id,
                    config=agent_specific_config
                )
                
                # Set execution interval if specified
                execution_interval = agent_config.get('execution_interval')
                if execution_interval:
                    agent.execution_interval = execution_interval
                
                # Register with orchestrator
                self.orchestrator.register_agent(agent)
                
                logger.info("Agent created and registered",
                           agent_id=agent_id,
                           agent_type=agent_type)
                
            except Exception as e:
                logger.error("Failed to create agent",
                            agent_id=agent_id,
                            agent_type=agent_type,
                            error=str(e))
    
    async def start(self) -> None:
        """
        Start the Crown Jewel Monitor application.
        """
        if self.running:
            logger.warning("Application is already running")
            return
        
        try:
            logger.info("Starting Crown Jewel Monitor")
            self.running = True
            
            # Initialize all agents
            logger.info("Initializing all agents")
            await self.orchestrator.initialize_all_agents()
            
            # Start API server if configured
            if self.api_server:
                logger.info("Starting REST API server")
                await self.api_server.start()
            
            # Start continuous monitoring
            logger.info("Starting continuous monitoring")
            monitoring_interval = self.config_manager.get_config().get('global', {}).get('monitoring_interval', 60)
            
            # Start monitoring in background
            monitoring_task = asyncio.create_task(
                self.orchestrator.start_continuous_monitoring(interval=monitoring_interval)
            )
            
            self.startup_complete = True
            logger.info("Crown Jewel Monitor started successfully",
                       monitoring_interval=monitoring_interval)
            
            # Wait for monitoring to complete (runs indefinitely)
            await monitoring_task
            
        except Exception as e:
            logger.error("Error starting Crown Jewel Monitor", error=str(e), exc_info=True)
            self.running = False
            raise
    
    async def stop(self) -> None:
        """
        Stop the Crown Jewel Monitor application gracefully.
        """
        if not self.running:
            logger.info("Application is not running")
            return
        
        try:
            logger.info("Stopping Crown Jewel Monitor")
            self.running = False
            
            # Stop API server
            if self.api_server:
                logger.info("Stopping REST API server")
                await self.api_server.stop()
            
            # Stop all agents
            if self.orchestrator:
                logger.info("Stopping all agents")
                await self.orchestrator.stop_all_agents()
                await self.orchestrator.cleanup()
            
            # Cleanup alerting system
            if self.alerting_system:
                logger.info("Cleaning up alerting system")
                # Add cleanup method to alerting system if needed
            
            logger.info("Crown Jewel Monitor stopped successfully")
            
        except Exception as e:
            logger.error("Error stopping Crown Jewel Monitor", error=str(e))
    
    async def reload_config(self) -> bool:
        """
        Reload configuration and restart components as needed.
        
        Returns:
            True if reload successful, False otherwise
        """
        try:
            logger.info("Reloading configuration")
            
            if not await self.config_manager.load_config():
                logger.error("Failed to reload configuration")
                return False
            
            # For now, log that config was reloaded
            # Full hot-reload would require more complex state management
            logger.info("Configuration reloaded successfully")
            logger.warning("Note: Some configuration changes require application restart")
            
            return True
            
        except Exception as e:
            logger.error("Error reloading configuration", error=str(e))
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get current application status.
        
        Returns:
            Status information dictionary
        """
        status = {
            'running': self.running,
            'startup_complete': self.startup_complete,
            'components': {
                'config_manager': self.config_manager is not None,
                'orchestrator': self.orchestrator is not None,
                'alerting_system': self.alerting_system is not None,
                'api_server': self.api_server is not None
            }
        }
        
        if self.orchestrator:
            status['agents'] = {
                'registered': len(self.orchestrator.agents),
                'active': len([a for a in self.orchestrator.agents.values() if a.is_running])
            }
        
        return status


async def main():
    """
    Main entry point for the Crown Jewel Monitor application.
    """
    parser = argparse.ArgumentParser(
        description="Crown Jewel Java Application Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --config config/production.yaml
  %(prog)s --config config/dev.yaml --log-level DEBUG
  %(prog)s --config config/config.yaml --validate-only
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        required=True,
        help='Path to configuration file'
    )
    
    parser.add_argument(
        '--log-level', '-l',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--validate-only',
        action='store_true',
        help='Validate configuration and exit'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'Crown Jewel Monitor v{__import__("crown_jewel_monitor").__version__}'
    )
    
    args = parser.parse_args()
    
    # Create application instance
    app = CrownJewelMonitor(
        config_path=args.config,
        log_level=args.log_level
    )
    
    # Validate configuration only
    if args.validate_only:
        logger.info("Validating configuration only")
        try:
            if await app.initialize():
                logger.info("Configuration validation successful")
                return 0
            else:
                logger.error("Configuration validation failed")
                return 1
        except Exception as e:
            logger.error("Configuration validation error", error=str(e))
            return 1
    
    # Setup signal handlers for graceful shutdown
    def signal_handler():
        logger.info("Received shutdown signal")
        if app.running:
            asyncio.create_task(app.stop())
    
    # Register signal handlers
    loop = asyncio.get_event_loop()
    for sig in [signal.SIGTERM, signal.SIGINT]:
        loop.add_signal_handler(sig, signal_handler)
    
    try:
        # Initialize application
        if not await app.initialize():
            logger.error("Failed to initialize Crown Jewel Monitor")
            return 1
        
        # Start application
        await app.start()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error("Unexpected error", error=str(e), exc_info=True)
        return 1
    finally:
        # Ensure cleanup
        await app.stop()
    
    return 0


def cli_main():
    """CLI entry point that handles async main function."""
    return asyncio.run(main())

if __name__ == '__main__':
    sys.exit(cli_main())