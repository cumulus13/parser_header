"""
CLI entry point for parser_header.

Author: Hadi Cahyadi <cumulus13@gmail.com>
"""

import argparse
try:
    from licface import CustomRichHelpFormatter
except:
    CustomRichHelpFormatter = argparse.RawTextHelpFormatter
import sys
import json
from pathlib import Path
from typing import Optional
from .parser import HeaderParser, CookieParser

def read_input(file_path: Optional[str] = None, stdin: bool = False) -> str:
    """Read input from file, stdin, or argument."""
    if stdin or (file_path == '-'):
        return sys.stdin.read()
    if file_path:
        path = Path(file_path)
        if not path.exists():
            print(f"Error: File '{file_path}' not found", file=sys.stderr)
            sys.exit(1)
        return path.read_text(encoding='utf-8')
    return ""

def format_output(data, fmt: str, indent: int = 2) -> str:
    """Format output based on requested format."""
    if fmt == 'json':
        def serialize(obj):
            if hasattr(obj, '__dict__'):
                return {'value': obj.value, 'params': obj.params}
            return str(obj)
        return json.dumps(data, indent=indent, default=serialize, ensure_ascii=False)
    elif fmt == 'raw':
        if isinstance(data, dict):
            lines = []
            for k, v in data.items():
                if isinstance(v, list):
                    for item in v:
                        lines.append(f"{k}: {item}")
                else:
                    lines.append(f"{k}: {v}")
            return '\n'.join(lines)
        return str(data)
    else:
        return repr(data)

def cmd_parse(args) -> None:
    """Parse headers command."""
    data = read_input(args.file, args.stdin) or args.data
    if not data:
        print("Error: No input provided. Use -f FILE, --stdin, or provide data", file=sys.stderr)
        sys.exit(1)
    
    parser = HeaderParser(data)
    
    if args.header:
        value = parser.get(args.header)
        if value is None:
            print(f"Header '{args.header}' not found", file=sys.stderr)
            sys.exit(1)
        print(format_output(value, args.format))
    else:
        print(format_output(parser.to_dict(), args.format))

def cmd_cookies(args) -> None:
    """Parse cookies command."""
    data = read_input(args.file, args.stdin) or args.data
    if not data:
        print("Error: No input provided", file=sys.stderr)
        sys.exit(1)
    
    if args.full_headers:
        parser = HeaderParser(data)
        cookies = parser.cookies
    else:
        cookies = CookieParser(data)
    
    if args.as_header:
        print(cookies.to_cookie_header())
    elif args.cookie:
        value = cookies.get(args.cookie)
        if value is None:
            print(f"Cookie '{args.cookie}' not found", file=sys.stderr)
            sys.exit(1)
        print(value)
    else:
        print(format_output(cookies.to_dict(), args.format))

def cmd_info(args) -> None:
    """Show header info/metadata."""
    data = read_input(args.file, args.stdin) or args.data
    if not data:
        print("Error: No input provided", file=sys.stderr)
        sys.exit(1)
    
    parser = HeaderParser(data)
    
    info = {
        'total_headers': len(parser),
        'total_cookies': len(parser.cookies),
        'content_type': parser.content_type,
        'content_length': parser.content_length,
        'user_agent': parser.user_agent,
        'origin': parser.origin,
        'is_cors': parser.is_cors(),
        'sec_fetch': parser.get_sec_fetch_metadata(),
        'client_hints': parser.get_client_hints(),
    }
    print(format_output(info, args.format))

def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='parser-header',
        description='Parse HTTP headers and cookies',
        formatter_class=CustomRichHelpFormatter,
        epilog="""
Examples:
  parser-header parse -f headers.txt
  parser-header parse -f headers.txt --header user-agent
  cat headers.txt | parser-header parse --stdin
  parser-header cookies -f headers.txt --full-headers
  parser-header cookies -f headers.txt --as-header
  parser-header info -f headers.txt
        """
    )
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Parse command
    parse_parser = subparsers.add_parser('parse', help='Parse HTTP headers', formatter_class=CustomRichHelpFormatter)
    parse_parser.add_argument('data', nargs='?', help='Header data string')
    parse_parser.add_argument('-f', '--file', help='Read from file')
    parse_parser.add_argument('--stdin', action='store_true', help='Read from stdin')
    parse_parser.add_argument('--header', '-H', help='Get specific header')
    parse_parser.add_argument('--format', '-F', choices=['json', 'raw', 'repr'], 
                             default='json', help='Output format')
    parse_parser.set_defaults(func=cmd_parse)
    
    # Cookies command
    cookie_parser = subparsers.add_parser('cookies', help='Parse cookies', formatter_class=CustomRichHelpFormatter)
    cookie_parser.add_argument('data', nargs='?', help='Cookie/header data')
    cookie_parser.add_argument('-f', '--file', help='Read from file')
    cookie_parser.add_argument('--stdin', action='store_true', help='Read from stdin')
    cookie_parser.add_argument('--full-headers', action='store_true',
                              help='Input is full headers (not just cookies)')
    cookie_parser.add_argument('--as-header', action='store_true',
                              help='Output as Cookie header format')
    cookie_parser.add_argument('--cookie', '-c', help='Get specific cookie')
    cookie_parser.add_argument('--format', '-F', choices=['json', 'raw', 'repr'],
                              default='json', help='Output format')
    cookie_parser.set_defaults(func=cmd_cookies)
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show header metadata', formatter_class=CustomRichHelpFormatter)
    info_parser.add_argument('data', nargs='?', help='Header data')
    info_parser.add_argument('-f', '--file', help='Read from file')
    info_parser.add_argument('--stdin', action='store_true', help='Read from stdin')
    info_parser.add_argument('--format', '-F', choices=['json', 'raw', 'repr'],
                            default='json', help='Output format')
    info_parser.set_defaults(func=cmd_info)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    args.func(args)

if __name__ == '__main__':
    main()