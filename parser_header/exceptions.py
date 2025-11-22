"""Custom exceptions for parser_header package."""

class ParserError(Exception):
    """Base exception for parser errors."""
    pass

class InvalidHeaderError(ParserError):
    """Raised when header format is invalid."""
    pass

class InvalidCookieError(ParserError):
    """Raised when cookie format is invalid."""
    pass

class EncodingError(ParserError):
    """Raised when encoding/decoding fails."""
    pass