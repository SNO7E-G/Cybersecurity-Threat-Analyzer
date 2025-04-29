# Plugin system initialization
"""
Cybersecurity Threat Analyzer Plugin System

This plugin system allows for extensibility of the threat analyzer through
custom plugins. Plugins can extend various aspects of the system including:

- Adding new detection algorithms
- Integrating with external security tools
- Implementing custom reporting mechanisms
- Adding support for specialized device types
- Creating custom visualization and analysis tools

To create a plugin:
1. Create a directory in the plugins/ folder with your plugin name
2. Create a Plugin class in __init__.py that implements the required methods
3. Register the plugin by putting it in the plugins/ directory

Plugin structure example:
```
plugins/
    my_plugin/
        __init__.py  # Contains Plugin class
        resources/   # Optional resources for your plugin
        README.md    # Documentation for your plugin
```

The Plugin class should implement the following methods:
- initialize() - Called when the plugin is loaded
- get_info() - Returns information about the plugin
- Additional methods depending on plugin type
"""

import os
import sys
import importlib
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger('plugins')

class PluginRegistry:
    """Registry for plugins and plugin management."""
    
    def __init__(self):
        """Initialize the plugin registry."""
        self.plugins = {}
        self.plugin_types = {
            'detection': [],
            'integration': [],
            'reporting': [],
            'device': [],
            'visualization': [],
            'custom': []
        }
    
    def discover_plugins(self, plugin_dir=None):
        """
        Discover plugins in the specified directory.
        
        Args:
            plugin_dir: Path to the plugins directory
        """
        if plugin_dir is None:
            # Use the directory of this file as the base
            plugin_dir = os.path.dirname(os.path.abspath(__file__))
        
        logger.info(f"Discovering plugins in {plugin_dir}")
        
        # Get all directories in the plugin directory
        try:
            items = os.listdir(plugin_dir)
            
            for item in items:
                item_path = os.path.join(plugin_dir, item)
                
                # Skip files and special directories
                if not os.path.isdir(item_path) or item.startswith('__'):
                    continue
                
                # Check if the directory has an __init__.py file
                init_file = os.path.join(item_path, '__init__.py')
                if not os.path.exists(init_file):
                    continue
                
                # Try to import the plugin
                try:
                    # Make sure plugin directory is in path
                    if plugin_dir not in sys.path:
                        sys.path.insert(0, plugin_dir)
                    
                    # Import the plugin module
                    module_name = item
                    plugin_module = importlib.import_module(module_name)
                    
                    # Check if it has a Plugin class
                    if hasattr(plugin_module, 'Plugin'):
                        plugin_class = getattr(plugin_module, 'Plugin')
                        plugin_instance = plugin_class()
                        
                        # Register the plugin
                        self.register_plugin(item, plugin_instance)
                        
                except Exception as e:
                    logger.error(f"Error loading plugin {item}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error discovering plugins: {str(e)}")
    
    def register_plugin(self, plugin_id, plugin_instance):
        """
        Register a plugin.
        
        Args:
            plugin_id: Unique identifier for the plugin
            plugin_instance: Instance of the plugin
        """
        try:
            # Check if plugin has required methods
            if not hasattr(plugin_instance, 'initialize') or not hasattr(plugin_instance, 'get_info'):
                logger.warning(f"Plugin {plugin_id} missing required methods")
                return
            
            # Get plugin info
            plugin_info = plugin_instance.get_info()
            
            # Initialize the plugin
            plugin_instance.initialize()
            
            # Register in main registry
            self.plugins[plugin_id] = {
                'instance': plugin_instance,
                'info': plugin_info
            }
            
            # Register by type
            plugin_type = plugin_info.get('type', 'custom')
            if plugin_type in self.plugin_types:
                self.plugin_types[plugin_type].append(plugin_id)
            else:
                self.plugin_types['custom'].append(plugin_id)
            
            logger.info(f"Registered plugin {plugin_id} ({plugin_info.get('name', 'Unknown')}) - {plugin_info.get('description', '')}")
            
        except Exception as e:
            logger.error(f"Error registering plugin {plugin_id}: {str(e)}")
    
    def get_plugin(self, plugin_id):
        """
        Get a plugin by ID.
        
        Args:
            plugin_id: ID of the plugin
            
        Returns:
            Plugin instance or None
        """
        if plugin_id in self.plugins:
            return self.plugins[plugin_id]['instance']
        return None
    
    def get_plugins_by_type(self, plugin_type):
        """
        Get all plugins of a specific type.
        
        Args:
            plugin_type: Type of plugins to retrieve
            
        Returns:
            List of plugin instances
        """
        if plugin_type not in self.plugin_types:
            return []
        
        return [self.plugins[plugin_id]['instance'] 
                for plugin_id in self.plugin_types[plugin_type] 
                if plugin_id in self.plugins]
    
    def list_plugins(self):
        """
        List all registered plugins.
        
        Returns:
            List of plugin information dictionaries
        """
        return [
            {
                'id': plugin_id,
                'name': plugin_data['info'].get('name', plugin_id),
                'version': plugin_data['info'].get('version', '0.1.0'),
                'description': plugin_data['info'].get('description', ''),
                'type': plugin_data['info'].get('type', 'custom'),
                'author': plugin_data['info'].get('author', 'Unknown')
            }
            for plugin_id, plugin_data in self.plugins.items()
        ]

# Create the plugin registry
registry = PluginRegistry()

# Auto-discover plugins when imported
registry.discover_plugins()

# Convenience function to get the registry
def get_registry():
    """Get the plugin registry."""
    return registry 