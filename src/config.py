#!/usr/bin/env python3
"""
Configuration module for API keys and settings.

Supports loading API keys from:
1. Environment variables (NVD_API_KEY, EPSS_API_KEY, etc.)
2. .env file in the project root
3. User input via command line
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any


class ConfigManager:
    """Manage API configuration and keys."""
    
    # API endpoints
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_URL = "https://api.first.org/data/v1/epss"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    VULNCHECK_KEV_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
    
    def __init__(self):
        """Initialize configuration manager."""
        self.config = {
            "nvd_api_key":   os.getenv("NVD_API_KEY", ""),
            "epss_api_key":  os.getenv("EPSS_API_KEY", ""),
            "github_token":  os.getenv("GITHUB_TOKEN", ""),
            "vulncheck_api_token": os.getenv("VULNCHECK_API_TOKEN", ""),
        }
        self._load_env_file()
    
    def _load_env_file(self) -> None:
        """Load API keys from .env file if it exists."""
        env_file = Path(".env")
        if env_file.exists():
            try:
                with open(env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            key, value = line.split("=", 1)
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")
                            if key == "NVD_API_KEY":
                                self.config["nvd_api_key"] = value
                            elif key == "EPSS_API_KEY":
                                self.config["epss_api_key"] = value
                            elif key == "GITHUB_TOKEN":
                                self.config["github_token"] = value
                            elif key == "VULNCHECK_API_TOKEN":
                                self.config["vulncheck_api_token"] = value
            except Exception as e:
                print(f"Warning: Could not read .env file: {e}", file=sys.stderr)
    
    def get_nvd_url(self, cve_id: str) -> str:
        """Get NVD API URL for a CVE with optional API key."""
        url = f"{self.NVD_URL}?cveId={cve_id}"
        if self.config.get("nvd_api_key"):
            url += f"&apiKey={self.config['nvd_api_key']}"
        return url
    
    def get_nvd_api_key(self) -> Optional[str]:
        """Get NVD API key if configured."""
        return self.config.get("nvd_api_key") or None
    
    def get_epss_api_key(self) -> Optional[str]:
        """Get EPSS API key if configured."""
        return self.config.get("epss_api_key") or None

    def get_github_token(self) -> Optional[str]:
        """Get GitHub personal access token if configured."""
        return self.config.get("github_token") or None

    def has_nvd_api_key(self) -> bool:
        """Check if NVD API key is configured."""
        return bool(self.config.get("nvd_api_key"))
    
    def has_epss_api_key(self) -> bool:
        """Check if EPSS API key is configured."""
        return bool(self.config.get("epss_api_key"))

    def has_github_token(self) -> bool:
        """Check if GitHub token is configured."""
        return bool(self.config.get("github_token"))

    def get_vulncheck_api_token(self) -> Optional[str]:
        """Get VulnCheck API token if configured."""
        return self.config.get("vulncheck_api_token") or None

    def has_vulncheck_api_token(self) -> bool:
        """Check if VulnCheck API token is configured."""
        return bool(self.config.get("vulncheck_api_token"))
    
    def save_to_env_file(self) -> None:
        """Save current configuration to .env file."""
        env_file = Path(".env")
        with open(env_file, 'w') as f:
            f.write("# Vulnerability Prioritization Tool - API Configuration\n")
            f.write("# Copy this file to .env and fill in your API keys\n\n")
            
            if self.config.get("nvd_api_key"):
                f.write(f'NVD_API_KEY="{self.config["nvd_api_key"]}"\n')
            else:
                f.write("# NVD_API_KEY=your_key_here\n")
            
            if self.config.get("epss_api_key"):
                f.write(f'EPSS_API_KEY="{self.config["epss_api_key"]}"\n')
            else:
                f.write("# EPSS_API_KEY=your_key_here\n")

            if self.config.get("github_token"):
                f.write(f'GITHUB_TOKEN="{self.config["github_token"]}"\n')
            else:
                f.write("# GITHUB_TOKEN=your_token_here\n")

            if self.config.get("vulncheck_api_token"):
                f.write(f'VULNCHECK_API_TOKEN="{self.config["vulncheck_api_token"]}"\n')
            else:
                f.write("# VULNCHECK_API_TOKEN=your_token_here\n")
    
    def prompt_for_keys(self) -> None:
        """Prompt user to enter API keys interactively."""
        print("\n" + "=" * 60)
        print("API Key Configuration")
        print("=" * 60)
        
        # NVD API Key
        if not self.config.get("nvd_api_key"):
            print("\n1. NVD API Key (optional but recommended)")
            print("   - Increases rate limit from 5 req/min to 5 req/sec")
            print("   - Get it at: https://nvd.nist.gov/developers/request-an-api-key")
            nvd_key = input("   Enter NVD API key (or press Enter to skip): ").strip()
            if nvd_key:
                self.config["nvd_api_key"] = nvd_key
        
        # EPSS API Key
        if not self.config.get("epss_api_key"):
            print("\n2. EPSS API Key (optional, public access available)")
            print("   - Not typically required for public EPSS API")
            epss_key = input("   Enter EPSS API key (or press Enter to skip): ").strip()
            if epss_key:
                self.config["epss_api_key"] = epss_key

        # GitHub Token
        if not self.config.get("github_token"):
            print("\n3. GitHub Personal Access Token (optional but recommended)")
            print("   - Increases search rate limit from 10 req/min to 30 req/min")
            print("   - Get it at: https://github.com/settings/tokens")
            print("   - Scopes needed: none (public data only)")
            gh_token = input("   Enter GitHub token (or press Enter to skip): ").strip()
            if gh_token:
                self.config["github_token"] = gh_token

        # VulnCheck token
        if not self.config.get("vulncheck_api_token"):
            print("\n4. VulnCheck API token (optional but recommended)")
            print("   - Adds early-exploitation KEV signal coverage")
            print("   - Get it at: https://vulncheck.com/")
            vc_token = input("   Enter VulnCheck token (or press Enter to skip): ").strip()
            if vc_token:
                self.config["vulncheck_api_token"] = vc_token
        
        # Save option
        print("\n" + "-" * 60)
        save = input("Save configuration to .env file? (y/n): ").strip().lower()
        if save == 'y':
            self.save_to_env_file()
            print("✓ Configuration saved to .env")
        
        print("=" * 60 + "\n")


# Global config instance
_config = None


def get_config() -> ConfigManager:
    """Get or create global config instance."""
    global _config
    if _config is None:
        _config = ConfigManager()
    return _config


def reset_config() -> None:
    """Reset global config instance."""
    global _config
    _config = None
