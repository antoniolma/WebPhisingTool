"""
Utility functions and helpers
"""
import re
from typing import Dict, Any
from urllib.parse import urlparse


def normalize_url(url: str) -> str:
    """
    Normalize URL format
    """
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def extract_domain(url: str) -> str:
    """
    Extract domain from URL
    """
    parsed = urlparse(url)
    return parsed.netloc


def is_valid_url(url: str) -> bool:
    """
    Check if URL is valid
    """
    pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return pattern.match(url) is not None


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe storage
    """
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Limit length
    filename = filename[:255]
    return filename


def format_bytes(bytes_count: int) -> str:
    """
    Format bytes to human-readable string
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} TB"


def truncate_string(text: str, max_length: int = 100) -> str:
    """
    Truncate string with ellipsis
    """
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + '...'
