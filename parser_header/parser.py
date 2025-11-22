"""
Core parser module for HTTP headers and cookies.

Author: Hadi Cahyadi <cumulus13@gmail.com>
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any, Iterator, overload
from urllib.parse import unquote
from .exceptions import InvalidHeaderError, InvalidCookieError, EncodingError

InputType = Union[str, bytes]

@dataclass
class HeaderValue:
    """Represents a parsed header value with optional parameters."""
    value: str
    params: Dict[str, str] = field(default_factory=dict)
    
    def __str__(self) -> str:
        if not self.params:
            return self.value
        params_str = "; ".join(f"{k}={v}" for k, v in self.params.items())
        return f"{self.value}; {params_str}"
    
    def __repr__(self) -> str:
        return f"HeaderValue(value={self.value!r}, params={self.params!r})"


class CookieParser:
    """Parser for HTTP cookies with multiple extraction methods."""
    
    def __init__(self, data: Optional[InputType] = None, **kwargs: str):
        """
        Initialize CookieParser.
        
        Args:
            data: Raw header string/bytes containing cookie entries
            **kwargs: Cookie key-value pairs to set directly
                     e.g., CookieParser(session="abc", user="john")
        """
        self._raw_data: Optional[str] = None
        self._cookies: Dict[str, str] = {}
        
        if data is not None:
            self.parse(data)
        
        if kwargs:
            self.set(**kwargs)
    
    def _normalize_input(self, data: InputType) -> str:
        """Convert bytes to string if necessary."""
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return data.decode('latin-1')
                except UnicodeDecodeError as e:
                    raise EncodingError(f"Failed to decode input: {e}")
        return data
    
    def _normalize_key(self, key: str) -> str:
        """Normalize cookie key (convert underscores to hyphens)."""
        return key.replace('_', '-')
    
    def parse(self, data: Optional[InputType] = None, **kwargs: str) -> Dict[str, str]:
        """
        Parse cookies from raw header data and/or kwargs.
        
        Args:
            data: Raw header string/bytes containing cookie entries
            **kwargs: Additional cookies as key=value pairs
            
        Returns:
            Dict of cookie name-value pairs
        """
        if data is not None:
            self._raw_data = self._normalize_input(data)
            lines = self._raw_data.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.lower().startswith('cookie:'):
                    cookie_value = line[7:].strip()
                    self._parse_cookie_string(cookie_value)
                elif '=' in line and ':' not in line.split('=')[0]:
                    self._parse_cookie_string(line)
        
        if kwargs:
            self.set(**kwargs)
        
        return self._cookies
    
    def _parse_cookie_string(self, cookie_str: str) -> None:
        """Parse a cookie string (name=value or name=value; name2=value2)."""
        parts = cookie_str.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                idx = part.index('=')
                name = part[:idx].strip()
                value = part[idx+1:].strip()
                if name:
                    self._cookies[name] = value
    
    def set(self, name: Optional[str] = None, value: Optional[str] = None, **kwargs: str) -> 'CookieParser':
        """
        Set cookie(s).
        
        Args:
            name: Cookie name (optional if using kwargs)
            value: Cookie value (required if name is provided)
            **kwargs: Cookie key=value pairs
                     Underscores in keys are converted to hyphens
                     
        Returns:
            self for chaining
            
        Examples:
            cookies.set('session', 'abc123')
            cookies.set(session='abc', user='john')
            cookies.set('token', 'xyz', refresh_token='123')
        """
        if name is not None:
            if value is None:
                raise ValueError("value is required when name is provided")
            self._cookies[name] = value
        
        for k, v in kwargs.items():
            key = self._normalize_key(k)
            self._cookies[key] = str(v)
        
        return self
    
    def remove(self, *names: str) -> 'CookieParser':
        """Remove cookie(s) by name."""
        for name in names:
            self._cookies.pop(name, None)
            self._cookies.pop(self._normalize_key(name), None)
        return self
    
    def clear(self) -> 'CookieParser':
        """Clear all cookies."""
        self._cookies.clear()
        return self
    
    def update(self, data: Optional[Dict[str, str]] = None, **kwargs: str) -> 'CookieParser':
        """
        Update cookies from dict and/or kwargs.
        
        Args:
            data: Dictionary of cookies
            **kwargs: Additional cookies
            
        Returns:
            self for chaining
        """
        if data:
            self._cookies.update(data)
        if kwargs:
            self.set(**kwargs)
        return self
    
    def to_cookie_header(self, data: Optional[InputType] = None, **kwargs: str) -> str:
        """
        Convert parsed cookies to Cookie header format.
        
        Args:
            data: Optional new data to parse first
            **kwargs: Additional cookies to include
            
        Returns:
            Cookie header string (name=value; name2=value2)
        """
        if data is not None or kwargs:
            self.parse(data, **kwargs)
        return "; ".join(f"{k}={v}" for k, v in self._cookies.items())
    
    def to_dict(self, data: Optional[InputType] = None, **kwargs: str) -> Dict[str, str]:
        """
        Get cookies as dictionary.
        
        Args:
            data: Optional new data to parse first
            **kwargs: Additional cookies to include
            
        Returns:
            Dict of cookie name-value pairs
        """
        if data is not None or kwargs:
            self.parse(data, **kwargs)
        return self._cookies.copy()
    
    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get a specific cookie value."""
        return self._cookies.get(name, self._cookies.get(self._normalize_key(name), default))
    
    def __getitem__(self, name: str) -> str:
        """Get cookie by name with bracket notation."""
        if name in self._cookies:
            return self._cookies[name]
        normalized = self._normalize_key(name)
        if normalized in self._cookies:
            return self._cookies[normalized]
        raise KeyError(f"Cookie '{name}' not found")
    
    def __setitem__(self, name: str, value: str) -> None:
        """Set cookie with bracket notation."""
        self._cookies[name] = value
    
    def __delitem__(self, name: str) -> None:
        """Delete cookie with bracket notation."""
        if name in self._cookies:
            del self._cookies[name]
        elif self._normalize_key(name) in self._cookies:
            del self._cookies[self._normalize_key(name)]
        else:
            raise KeyError(f"Cookie '{name}' not found")
    
    def __contains__(self, name: str) -> bool:
        return name in self._cookies or self._normalize_key(name) in self._cookies
    
    def __iter__(self) -> Iterator[str]:
        return iter(self._cookies)
    
    def __len__(self) -> int:
        return len(self._cookies)
    
    def __repr__(self) -> str:
        return f"CookieParser({self._cookies!r})"
    
    def keys(self) -> List[str]:
        return list(self._cookies.keys())
    
    def values(self) -> List[str]:
        return list(self._cookies.values())
    
    def items(self) -> List[tuple]:
        return list(self._cookies.items())
    
    @classmethod
    def from_dict(cls, cookies: Dict[str, str]) -> 'CookieParser':
        """Create CookieParser from dictionary."""
        parser = cls()
        parser._cookies = cookies.copy()
        return parser
    
    @classmethod
    def from_kwargs(cls, **kwargs: str) -> 'CookieParser':
        """Create CookieParser from keyword arguments."""
        return cls(**kwargs)


class HeaderParser:
    """
    Comprehensive HTTP header parser supporting all standard and custom headers.
    """
    
    SPECIAL_HEADERS = {
        'content-type', 'accept', 'cache-control', 'content-disposition',
        'authorization', 'www-authenticate', 'proxy-authenticate',
        'set-cookie', 'cookie'
    }
    
    BOOLEAN_HEADERS = {'dnt', 'sec-gpc', 'upgrade-insecure-requests'}
    
    SEC_CH_UA_PATTERN = re.compile(r'"([^"]+)";v="([^"]+)"')
    
    def __init__(self, data: Optional[InputType] = None, **kwargs: Any):
        """
        Initialize HeaderParser.
        
        Args:
            data: Raw header string/bytes
            **kwargs: Header key-value pairs to set directly
                     Underscores in keys are converted to hyphens
                     e.g., HeaderParser(content_type="application/json", user_agent="Mozilla")
        """
        self._raw_data: Optional[str] = None
        self._headers: Dict[str, Any] = {}
        self._cookies: CookieParser = CookieParser()
        self._raw_cookies: List[str] = []
        
        if data is not None:
            self.parse(data)
        
        if kwargs:
            self.set(**kwargs)
    
    def _normalize_input(self, data: InputType) -> str:
        """Convert bytes to string."""
        if isinstance(data, bytes):
            try:
                return data.decode('utf-8')
            except UnicodeDecodeError:
                try:
                    return data.decode('latin-1')
                except UnicodeDecodeError as e:
                    raise EncodingError(f"Failed to decode: {e}")
        return data
    
    def _normalize_key(self, key: str) -> str:
        """Normalize header key (lowercase, convert underscores to hyphens)."""
        return key.lower().replace('_', '-')
    
    def parse(self, data: Optional[InputType] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        Parse raw HTTP headers into structured dictionary.
        
        Args:
            data: Raw header string/bytes
            **kwargs: Additional headers as key=value pairs
                     Underscores in keys are converted to hyphens
            
        Returns:
            Dict with parsed headers
        """
        if data is not None:
            self._raw_data = self._normalize_input(data)
            self._raw_cookies = []
            cookie_lines = []
            
            lines = self._raw_data.strip().split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                if ':' not in line:
                    continue
                
                idx = line.index(':')
                name = line[:idx].strip()
                value = line[idx+1:].strip()
                name_lower = name.lower()
                
                if name_lower == 'cookie':
                    cookie_lines.append(f"cookie: {value}")
                    self._raw_cookies.append(value)
                    self._add_header(name_lower, value)
                else:
                    parsed_value = self._parse_header_value(name_lower, value)
                    self._add_header(name_lower, parsed_value)
            
            if cookie_lines:
                self._cookies.parse('\n'.join(cookie_lines))
        
        if kwargs:
            self.set(**kwargs)
        
        return self._headers
    
    def set(self, name: Optional[str] = None, value: Optional[Any] = None, **kwargs: Any) -> 'HeaderParser':
        """
        Set header(s).
        
        Args:
            name: Header name (optional if using kwargs)
            value: Header value (required if name is provided)
            **kwargs: Header key=value pairs
                     Underscores in keys are converted to hyphens
                     
        Returns:
            self for chaining
            
        Examples:
            parser.set('Content-Type', 'application/json')
            parser.set(content_type='application/json', user_agent='Mozilla')
            parser.set('X-Custom', 'value', accept='*/*')
        """
        if name is not None:
            if value is None:
                raise ValueError("value is required when name is provided")
            name_lower = self._normalize_key(name)
            if name_lower == 'cookie':
                if isinstance(value, dict):
                    self._cookies.update(value)
                else:
                    self._cookies.parse(f"cookie: {value}")
            self._headers[name_lower] = self._parse_header_value(name_lower, str(value))
        
        for k, v in kwargs.items():
            key = self._normalize_key(k)
            if key == 'cookie':
                if isinstance(v, dict):
                    self._cookies.update(v)
                else:
                    self._cookies.parse(f"cookie: {v}")
            self._headers[key] = self._parse_header_value(key, str(v))
        
        return self
    
    def set_raw(self, name: Optional[str] = None, value: Optional[Any] = None, **kwargs: Any) -> 'HeaderParser':
        """
        Set header(s) without parsing the value.
        
        Args:
            name: Header name
            value: Header value (stored as-is)
            **kwargs: Header key=value pairs
            
        Returns:
            self for chaining
        """
        if name is not None:
            if value is None:
                raise ValueError("value is required when name is provided")
            self._headers[self._normalize_key(name)] = value
        
        for k, v in kwargs.items():
            self._headers[self._normalize_key(k)] = v
        
        return self
    
    def remove(self, *names: str) -> 'HeaderParser':
        """Remove header(s) by name."""
        for name in names:
            key = self._normalize_key(name)
            self._headers.pop(key, None)
        return self
    
    def clear(self) -> 'HeaderParser':
        """Clear all headers."""
        self._headers.clear()
        self._cookies.clear()
        return self
    
    def update(self, data: Optional[Dict[str, Any]] = None, **kwargs: Any) -> 'HeaderParser':
        """
        Update headers from dict and/or kwargs.
        
        Args:
            data: Dictionary of headers
            **kwargs: Additional headers
            
        Returns:
            self for chaining
        """
        if data:
            for k, v in data.items():
                self.set(k, v)
        if kwargs:
            self.set(**kwargs)
        return self
    
    def _add_header(self, name: str, value: Any) -> None:
        """Add header, handling multiple values for same header."""
        if name in self._headers:
            existing = self._headers[name]
            if isinstance(existing, list):
                existing.append(value)
            else:
                self._headers[name] = [existing, value]
        else:
            self._headers[name] = value
    
    def _parse_header_value(self, name: str, value: str) -> Any:
        """Parse header value based on header type."""
        if name in self.BOOLEAN_HEADERS:
            return self._parse_boolean(value)
        
        if name.startswith('sec-ch-ua'):
            return self._parse_sec_ch_ua(name, value)
        
        if name in ('content-type', 'content-disposition'):
            return self._parse_parameterized(value)
        
        if name == 'accept':
            return self._parse_accept(value)
        
        if name == 'accept-language':
            return self._parse_accept_language(value)
        
        if name == 'accept-encoding':
            return self._parse_accept_encoding(value)
        
        if name == 'cache-control':
            return self._parse_cache_control(value)
        
        if name == 'priority':
            return self._parse_priority(value)
        
        if name == 'content-length':
            try:
                return int(value)
            except ValueError:
                return value
        
        return value
    
    def _parse_boolean(self, value: str) -> bool:
        """Parse boolean-like header values."""
        return value.lower() in ('1', 'true', 'yes', '?1')
    
    def _parse_sec_ch_ua(self, name: str, value: str) -> Any:
        """Parse Sec-CH-UA style headers."""
        if name == 'sec-ch-ua-mobile':
            return value == '?1'
        
        if name in ('sec-ch-ua', 'sec-ch-ua-full-version-list'):
            brands = []
            for match in self.SEC_CH_UA_PATTERN.finditer(value):
                brands.append({'brand': match.group(1), 'version': match.group(2)})
            return brands if brands else value
        
        value = value.strip('"')
        return value
    
    def _parse_parameterized(self, value: str) -> HeaderValue:
        """Parse headers with parameters (e.g., Content-Type)."""
        parts = value.split(';')
        main_value = parts[0].strip()
        params = {}
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                k, v = part.split('=', 1)
                params[k.strip()] = v.strip().strip('"')
        return HeaderValue(value=main_value, params=params)
    
    def _parse_accept(self, value: str) -> List[Dict[str, Any]]:
        """Parse Accept header."""
        if value == '*/*':
            return [{'type': '*/*', 'q': 1.0}]
        
        result = []
        for part in value.split(','):
            part = part.strip()
            if ';' in part:
                media, *params = part.split(';')
                entry = {'type': media.strip(), 'q': 1.0}
                for p in params:
                    if '=' in p:
                        k, v = p.split('=', 1)
                        k = k.strip()
                        if k == 'q':
                            try:
                                entry['q'] = float(v.strip())
                            except ValueError:
                                pass
                        else:
                            entry[k] = v.strip()
                result.append(entry)
            else:
                result.append({'type': part, 'q': 1.0})
        return sorted(result, key=lambda x: x['q'], reverse=True)
    
    def _parse_accept_language(self, value: str) -> List[Dict[str, Any]]:
        """Parse Accept-Language header."""
        result = []
        for part in value.split(','):
            part = part.strip()
            if ';' in part:
                lang, *params = part.split(';')
                entry = {'lang': lang.strip(), 'q': 1.0}
                for p in params:
                    if '=' in p and p.strip().startswith('q='):
                        try:
                            entry['q'] = float(p.split('=')[1].strip())
                        except ValueError:
                            pass
                result.append(entry)
            else:
                result.append({'lang': part, 'q': 1.0})
        return sorted(result, key=lambda x: x['q'], reverse=True)
    
    def _parse_accept_encoding(self, value: str) -> List[str]:
        """Parse Accept-Encoding header."""
        return [e.strip() for e in value.split(',')]
    
    def _parse_cache_control(self, value: str) -> Dict[str, Any]:
        """Parse Cache-Control header."""
        result = {}
        for part in value.split(','):
            part = part.strip()
            if '=' in part:
                k, v = part.split('=', 1)
                try:
                    result[k.strip()] = int(v.strip())
                except ValueError:
                    result[k.strip()] = v.strip()
            else:
                result[part] = True
        return result
    
    def _parse_priority(self, value: str) -> Dict[str, Any]:
        """Parse Priority header."""
        result = {}
        for part in value.split(','):
            part = part.strip()
            if '=' in part:
                k, v = part.split('=', 1)
                result[k.strip()] = v.strip()
            else:
                result[part] = True
        return result
    
    # === Public API ===
    
    def get(self, name: str, default: Any = None) -> Any:
        """Get header value by name (case-insensitive)."""
        return self._headers.get(self._normalize_key(name), default)
    
    def __getitem__(self, name: str) -> Any:
        name_lower = self._normalize_key(name)
        if name_lower not in self._headers:
            raise KeyError(f"Header '{name}' not found")
        return self._headers[name_lower]
    
    def __setitem__(self, name: str, value: Any) -> None:
        """Set header with bracket notation."""
        self.set(name, value)
    
    def __delitem__(self, name: str) -> None:
        """Delete header with bracket notation."""
        key = self._normalize_key(name)
        if key not in self._headers:
            raise KeyError(f"Header '{name}' not found")
        del self._headers[key]
    
    def __contains__(self, name: str) -> bool:
        return self._normalize_key(name) in self._headers
    
    def __iter__(self) -> Iterator[str]:
        return iter(self._headers)
    
    def __len__(self) -> int:
        return len(self._headers)
    
    def __repr__(self) -> str:
        return f"HeaderParser({dict(list(self._headers.items())[:5])}{'...' if len(self._headers) > 5 else ''})"
    
    def keys(self) -> List[str]:
        return list(self._headers.keys())
    
    def values(self) -> List[Any]:
        return list(self._headers.values())
    
    def items(self) -> List[tuple]:
        return list(self._headers.items())
    
    def to_dict(self, stringify: bool = False) -> Dict[str, Any]:
        """
        Get all headers as dictionary.
        
        Args:
            stringify: If True, convert all values to strings
        """
        if not stringify:
            return self._headers.copy()
        return {k: str(v) for k, v in self._headers.items()}
    
    def to_raw(self) -> str:
        """Convert parsed headers back to raw format."""
        lines = []
        for name, value in self._headers.items():
            if isinstance(value, list):
                for v in value:
                    lines.append(f"{name}: {v}")
            elif isinstance(value, HeaderValue):
                lines.append(f"{name}: {value}")
            elif isinstance(value, bool):
                lines.append(f"{name}: {'1' if value else '0'}")
            else:
                lines.append(f"{name}: {value}")
        return '\n'.join(lines)
    
    def to_requests_headers(self) -> Dict[str, str]:
        """Convert to format suitable for requests library."""
        result = {}
        for name, value in self._headers.items():
            if isinstance(value, list):
                result[name] = ', '.join(str(v) for v in value)
            else:
                result[name] = str(value)
        return result
    
    @property
    def cookies(self) -> CookieParser:
        """Access cookie parser."""
        return self._cookies
    
    def get_cookie(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """Get specific cookie value."""
        return self._cookies.get(name, default)
    
    def set_cookie(self, name: Optional[str] = None, value: Optional[str] = None, **kwargs: str) -> 'HeaderParser':
        """
        Set cookie(s).
        
        Args:
            name: Cookie name
            value: Cookie value
            **kwargs: Cookie key=value pairs
            
        Returns:
            self for chaining
        """
        self._cookies.set(name, value, **kwargs)
        return self
    
    def get_cookies_as_header(self) -> str:
        """Get all cookies formatted as Cookie header value."""
        return self._cookies.to_cookie_header()
    
    def get_cookies_as_dict(self) -> Dict[str, str]:
        """Get all cookies as dictionary."""
        return self._cookies.to_dict()
    
    @property
    def content_type(self) -> Optional[str]:
        """Get Content-Type value."""
        ct = self.get('content-type')
        if isinstance(ct, HeaderValue):
            return ct.value
        return ct
    
    @property
    def content_length(self) -> Optional[int]:
        """Get Content-Length as integer."""
        return self.get('content-length')
    
    @property
    def user_agent(self) -> Optional[str]:
        """Get User-Agent value."""
        return self.get('user-agent')
    
    @property
    def origin(self) -> Optional[str]:
        """Get Origin value."""
        return self.get('origin')
    
    @property
    def referer(self) -> Optional[str]:
        """Get Referer value."""
        return self.get('referer')
    
    def is_ajax(self) -> bool:
        """Check if request is AJAX/XHR."""
        return self.get('x-requested-with', '').lower() == 'xmlhttprequest'
    
    def is_cors(self) -> bool:
        """Check if request is CORS."""
        return self.get('origin') is not None
    
    def get_sec_fetch_metadata(self) -> Dict[str, str]:
        """Get all Sec-Fetch-* headers."""
        return {
            'site': self.get('sec-fetch-site', ''),
            'mode': self.get('sec-fetch-mode', ''),
            'dest': self.get('sec-fetch-dest', ''),
            'user': self.get('sec-fetch-user', ''),
        }
    
    def get_client_hints(self) -> Dict[str, Any]:
        """Get all Client Hints (Sec-CH-*) headers."""
        hints = {}
        for name, value in self._headers.items():
            if name.startswith('sec-ch-'):
                hints[name] = value
        return hints
    
    @classmethod
    def from_dict(cls, headers: Dict[str, Any]) -> 'HeaderParser':
        """Create HeaderParser from dictionary."""
        parser = cls()
        parser.update(headers)
        return parser
    
    @classmethod
    def from_kwargs(cls, **kwargs: Any) -> 'HeaderParser':
        """Create HeaderParser from keyword arguments."""
        return cls(**kwargs)
    
    @classmethod
    def from_requests_response(cls, response: Any) -> 'HeaderParser':
        """Create HeaderParser from requests Response object."""
        parser = cls()
        if hasattr(response, 'headers'):
            for k, v in response.headers.items():
                parser.set(k, v)
        return parser