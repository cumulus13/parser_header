"""
Tests for parser_header package.

Author: Hadi Cahyadi <cumulus13@gmail.com>
"""

import pytest
from parser_header import HeaderParser, CookieParser, HeaderValue
from parser_header.exceptions import InvalidHeaderError, EncodingError

SAMPLE_HEADERS = """content-length: 1171
sec-ch-ua-full-version-list: "Not(A:Brand";v="8.0.0.0", "Chromium";v="144.0.7524.3", "Google Chrome";v="144.0.7524.3"
sec-ch-ua-platform: "Windows"
sec-ch-ua: "Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"
sec-ch-ua-mobile: ?0
accept: */*
content-type: application/json
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/144.0.0.0
dnt: 1
origin: https://medium.com
referer: https://medium.com/me/stats
accept-encoding: gzip, deflate, br, zstd
accept-language: en-US,en;q=0.9
cookie: nonce=Ofymgy29
cookie: sz=1490
cookie: uid=2ca13899eb7a
cookie: sid=1:KUo/b68Cp0mhPre4OYgcLFetmgSTlZLtDzaK5Fz6J4QkxDYrCuv0dl2VE/pgBYBF
sec-gpc: 1
priority: u=1, i"""


class TestHeaderParser:
    """Test HeaderParser class."""
    
    def test_parse_basic(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert len(parser) > 0
        assert 'content-length' in parser
        assert 'user-agent' in parser
    
    def test_content_length_as_int(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.content_length == 1171
        assert isinstance(parser.content_length, int)
    
    def test_content_type(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.content_type == 'application/json'
    
    def test_user_agent(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert 'Mozilla' in parser.user_agent
        assert 'Chrome' in parser.user_agent
    
    def test_origin_referer(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.origin == 'https://medium.com'
        assert parser.referer == 'https://medium.com/me/stats'
    
    def test_boolean_headers(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.get('dnt') is True
        assert parser.get('sec-gpc') is True
    
    def test_sec_ch_ua_mobile(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.get('sec-ch-ua-mobile') is False
    
    def test_sec_ch_ua_platform(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.get('sec-ch-ua-platform') == 'Windows'
    
    def test_sec_ch_ua_list(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        ua_list = parser.get('sec-ch-ua')
        assert isinstance(ua_list, list)
        assert len(ua_list) == 3
        brands = [item['brand'] for item in ua_list]
        assert 'Google Chrome' in brands
    
    def test_accept_encoding(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        encodings = parser.get('accept-encoding')
        assert 'gzip' in encodings
        assert 'br' in encodings
    
    def test_accept_language(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        langs = parser.get('accept-language')
        assert isinstance(langs, list)
        assert langs[0]['lang'] == 'en-US'
        assert langs[0]['q'] == 1.0
    
    def test_priority_header(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        priority = parser.get('priority')
        assert isinstance(priority, dict)
        assert priority.get('u') == '1'
        assert priority.get('i') is True
    
    def test_get_item_bracket(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser['content-length'] == 1171
    
    def test_get_item_missing(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        with pytest.raises(KeyError):
            _ = parser['nonexistent-header']
    
    def test_get_default(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.get('nonexistent', 'default') == 'default'
    
    def test_case_insensitive(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.get('Content-Length') == parser.get('content-length')
        assert parser.get('USER-AGENT') == parser.get('user-agent')
    
    def test_to_dict(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        d = parser.to_dict()
        assert isinstance(d, dict)
        assert 'content-length' in d
    
    def test_is_cors(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.is_cors() is True
    
    def test_client_hints(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        hints = parser.get_client_hints()
        assert 'sec-ch-ua' in hints
        assert 'sec-ch-ua-platform' in hints
    
    def test_bytes_input(self):
        data = SAMPLE_HEADERS.encode('utf-8')
        parser = HeaderParser(data)
        assert parser.content_length == 1171


class TestCookieParser:
    """Test CookieParser class."""
    
    def test_parse_multiple_cookie_lines(self):
        data = """cookie: nonce=Ofymgy29
cookie: sz=1490
cookie: uid=2ca13899eb7a"""
        parser = CookieParser(data)
        assert len(parser) == 3
        assert parser.get('nonce') == 'Ofymgy29'
        assert parser.get('sz') == '1490'
    
    def test_parse_single_line(self):
        data = "cookie: a=1; b=2; c=3"
        parser = CookieParser(data)
        assert len(parser) == 3
        assert parser['a'] == '1'
        assert parser['b'] == '2'
    
    def test_to_cookie_header(self):
        data = """cookie: nonce=test
cookie: uid=12345"""
        parser = CookieParser(data)
        header = parser.to_cookie_header()
        assert 'nonce=test' in header
        assert 'uid=12345' in header
        assert ';' in header
    
    def test_to_dict(self):
        data = "cookie: a=1; b=2"
        parser = CookieParser(data)
        d = parser.to_dict()
        assert d == {'a': '1', 'b': '2'}
    
    def test_contains(self):
        parser = CookieParser("cookie: test=value")
        assert 'test' in parser
        assert 'missing' not in parser
    
    def test_iter(self):
        parser = CookieParser("cookie: a=1; b=2")
        keys = list(parser)
        assert 'a' in keys
        assert 'b' in keys
    
    def test_keys_values_items(self):
        parser = CookieParser("cookie: x=10; y=20")
        assert 'x' in parser.keys()
        assert '10' in parser.values()
        assert ('x', '10') in parser.items()


class TestHeaderParserCookies:
    """Test cookie access via HeaderParser."""
    
    def test_cookies_property(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        cookies = parser.cookies
        assert isinstance(cookies, CookieParser)
        assert len(cookies) > 0
    
    def test_get_cookie(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        assert parser.get_cookie('nonce') == 'Ofymgy29'
        assert parser.get_cookie('sz') == '1490'
    
    def test_get_cookies_as_header(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        header = parser.get_cookies_as_header()
        assert 'nonce=Ofymgy29' in header
        assert ';' in header
    
    def test_get_cookies_as_dict(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        d = parser.get_cookies_as_dict()
        assert isinstance(d, dict)
        assert 'uid' in d


class TestHeaderValue:
    """Test HeaderValue dataclass."""
    
    def test_str_simple(self):
        hv = HeaderValue(value='application/json')
        assert str(hv) == 'application/json'
    
    def test_str_with_params(self):
        hv = HeaderValue(value='text/html', params={'charset': 'utf-8'})
        assert 'text/html' in str(hv)
        assert 'charset=utf-8' in str(hv)
    
    def test_repr(self):
        hv = HeaderValue(value='test', params={'a': '1'})
        r = repr(hv)
        assert 'HeaderValue' in r
        assert 'test' in r


class TestContentTypeWithParams:
    """Test Content-Type parsing with parameters."""
    
    def test_content_type_with_charset(self):
        data = "content-type: text/html; charset=utf-8"
        parser = HeaderParser(data)
        ct = parser.get('content-type')
        assert isinstance(ct, HeaderValue)
        assert ct.value == 'text/html'
        assert ct.params.get('charset') == 'utf-8'
    
    def test_content_disposition(self):
        data = 'content-disposition: attachment; filename="report.pdf"'
        parser = HeaderParser(data)
        cd = parser.get('content-disposition')
        assert cd.value == 'attachment'
        assert cd.params.get('filename') == 'report.pdf'


class TestKwargsSupport:
    """Test kwargs support for parsing and setting."""
    
    def test_header_parser_init_kwargs(self):
        parser = HeaderParser(
            content_type='application/json',
            user_agent='TestAgent/1.0',
            x_custom_header='custom_value'
        )
        assert parser.content_type == 'application/json'
        assert parser.user_agent == 'TestAgent/1.0'
        assert parser.get('x-custom-header') == 'custom_value'
    
    def test_header_parser_set_kwargs(self):
        parser = HeaderParser()
        parser.set(
            content_type='text/html',
            accept='*/*',
            cache_control='no-cache'
        )
        assert parser.content_type == 'text/html'
        assert parser.get('cache-control') == {'no-cache': True}
    
    def test_header_parser_set_mixed(self):
        parser = HeaderParser()
        parser.set('Content-Type', 'application/json', user_agent='Mozilla')
        assert parser.content_type == 'application/json'
        assert parser.user_agent == 'Mozilla'
    
    def test_header_parser_parse_kwargs(self):
        parser = HeaderParser()
        parser.parse("content-length: 100", accept='*/*', dnt='1')
        assert parser.content_length == 100
        assert parser.get('dnt') is True
    
    def test_header_parser_update_kwargs(self):
        parser = HeaderParser(content_type='text/plain')
        parser.update({'accept': '*/*'}, user_agent='Test')
        assert parser.content_type == 'text/plain'
        assert parser.user_agent == 'Test'
    
    def test_header_parser_from_kwargs(self):
        parser = HeaderParser.from_kwargs(
            content_type='application/xml',
            authorization='Bearer token123'
        )
        assert parser.content_type == 'application/xml'
        assert parser.get('authorization') == 'Bearer token123'
    
    def test_header_parser_from_dict(self):
        parser = HeaderParser.from_dict({
            'Content-Type': 'application/json',
            'X-Request-ID': '12345'
        })
        assert parser.content_type == 'application/json'
        assert parser.get('x-request-id') == '12345'
    
    def test_cookie_parser_init_kwargs(self):
        cookies = CookieParser(
            session='abc123',
            user_id='12345',
            auth_token='xyz'
        )
        assert cookies.get('session') == 'abc123'
        assert cookies.get('user-id') == '12345'
        assert cookies.get('auth-token') == 'xyz'
    
    def test_cookie_parser_set_kwargs(self):
        cookies = CookieParser()
        cookies.set(session='test', token='value')
        assert cookies.get('session') == 'test'
        assert cookies.get('token') == 'value'
    
    def test_cookie_parser_set_mixed(self):
        cookies = CookieParser()
        cookies.set('nonce', 'abc', user='john', refresh_token='xyz')
        assert cookies.get('nonce') == 'abc'
        assert cookies.get('user') == 'john'
        assert cookies.get('refresh-token') == 'xyz'
    
    def test_cookie_parser_to_header_kwargs(self):
        cookies = CookieParser()
        header = cookies.to_cookie_header(session='test', uid='123')
        assert 'session=test' in header
        assert 'uid=123' in header
    
    def test_cookie_parser_to_dict_kwargs(self):
        cookies = CookieParser()
        d = cookies.to_dict(a='1', b='2')
        assert d == {'a': '1', 'b': '2'}
    
    def test_cookie_parser_from_kwargs(self):
        cookies = CookieParser.from_kwargs(
            session='abc',
            token='xyz'
        )
        assert cookies.get('session') == 'abc'
        assert cookies.get('token') == 'xyz'
    
    def test_cookie_parser_chaining(self):
        cookies = CookieParser()
        result = cookies.set(a='1').set(b='2').set(c='3')
        assert len(cookies) == 3
        assert result is cookies
    
    def test_header_parser_chaining(self):
        parser = HeaderParser()
        result = parser.set(content_type='text/html').set(accept='*/*')
        assert len(parser) == 2
        assert result is parser
    
    def test_header_parser_set_cookie_kwargs(self):
        parser = HeaderParser()
        parser.set_cookie(session='abc', user='john')
        assert parser.get_cookie('session') == 'abc'
        assert parser.get_cookie('user') == 'john'
    
    def test_underscore_to_hyphen_conversion(self):
        parser = HeaderParser(
            content_type='application/json',
            x_request_id='123',
            sec_ch_ua_platform='Windows'
        )
        assert 'content-type' in parser
        assert 'x-request-id' in parser
        assert 'sec-ch-ua-platform' in parser


class TestSettersAndMutations:
    """Test setters, removers, and mutations."""
    
    def test_header_bracket_set(self):
        parser = HeaderParser()
        parser['Content-Type'] = 'application/json'
        assert parser.content_type == 'application/json'
    
    def test_header_bracket_del(self):
        parser = HeaderParser(content_type='text/html')
        del parser['content-type']
        assert 'content-type' not in parser
    
    def test_header_remove(self):
        parser = HeaderParser(content_type='text/html', accept='*/*')
        parser.remove('content-type')
        assert 'content-type' not in parser
        assert 'accept' in parser
    
    def test_header_clear(self):
        parser = HeaderParser(content_type='text/html', accept='*/*')
        parser.clear()
        assert len(parser) == 0
    
    def test_cookie_bracket_set(self):
        cookies = CookieParser()
        cookies['session'] = 'abc'
        assert cookies.get('session') == 'abc'
    
    def test_cookie_bracket_del(self):
        cookies = CookieParser(session='abc')
        del cookies['session']
        assert 'session' not in cookies
    
    def test_cookie_remove(self):
        cookies = CookieParser(a='1', b='2')
        cookies.remove('a')
        assert 'a' not in cookies
        assert 'b' in cookies
    
    def test_cookie_clear(self):
        cookies = CookieParser(a='1', b='2')
        cookies.clear()
        assert len(cookies) == 0
    
    def test_cookie_update(self):
        cookies = CookieParser(a='1')
        cookies.update({'b': '2'}, c='3')
        assert len(cookies) == 3
    
    def test_set_raw(self):
        parser = HeaderParser()
        parser.set_raw('content-type', 'application/json')
        # set_raw doesn't parse, so it stays as string
        assert parser.get('content-type') == 'application/json'


class TestConversions:
    """Test conversion methods."""
    
    def test_to_requests_headers(self):
        parser = HeaderParser(
            content_type='application/json',
            accept='*/*'
        )
        headers = parser.to_requests_headers()
        assert isinstance(headers, dict)
        assert all(isinstance(v, str) for v in headers.values())
    
    def test_to_dict_stringify(self):
        parser = HeaderParser(SAMPLE_HEADERS)
        d = parser.to_dict(stringify=True)
        assert all(isinstance(v, str) for v in d.values())


if __name__ == '__main__':
    pytest.main([__file__, '-v'])