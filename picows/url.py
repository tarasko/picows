from dataclasses import dataclass
import urllib.parse
from typing import Optional

from .types import WSError, WSHost, WSPort

# All characters from the gen-delims and sub-delims sets in RFC 3987.
DELIMS = ":/?#[]@!$&'()*+,;="


class WSInvalidURL(WSError):
    """
    Raised by :any:`ws_connect` when connecting to an URL that isn't a valid WebSocket URL.
    """
    def __init__(self, url: str, msg: str) -> None:
        super().__init__(f"{url} isn't a valid URL: {msg}")
        self.url = url


@dataclass(eq=False, frozen=True)
class WSParsedURL:
    url: str
    is_secure: bool
    netloc: str
    host: WSHost       # Normalized to lower case.
    port: WSPort       # Always set
    path: str
    query: str         # May be empty if the URL doesn't include a query component.
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def resource_name(self) -> str:
        """Resource name, for example /ws?param1=val1&param2=val2"""
        if self.path:
            resource_name = self.path
        else:
            resource_name = "/"
        if self.query:
            resource_name += "?" + self.query
        return resource_name

    @property
    def user_info(self) -> Optional[tuple[str, str]]:
        """Username and password tuple if specified, otherwise None"""
        if self.username is None:
            return None
        assert self.password is not None
        return self.username, self.password


def parse_url(url: str, check_scheme: bool = True) -> WSParsedURL:
    parsed = urllib.parse.urlparse(url)
    if check_scheme and parsed.scheme not in ["ws", "wss"]:
        raise WSInvalidURL(url, "scheme isn't ws or wss")
    if parsed.hostname is None:
        raise WSInvalidURL(url, "hostname isn't provided")
    if parsed.fragment != "":
        raise WSInvalidURL(url, "fragment identifier is meaningless")

    secure = parsed.scheme == "wss"
    netloc = parsed.netloc
    host = parsed.hostname
    port = parsed.port or (443 if secure else 80)
    path = parsed.path
    query = parsed.query
    username = parsed.username
    password = parsed.password

    try:
        url.encode("ascii")
    except UnicodeEncodeError:
        # Input contains non-ASCII characters.
        # It must be an IRI. Convert it to a WSParsedURL.
        host = host.encode("idna").decode()
        path = urllib.parse.quote(path, safe=DELIMS)
        query = urllib.parse.quote(query, safe=DELIMS)
        if username is not None:
            assert password is not None
            username = urllib.parse.quote(username, safe=DELIMS)
            password = urllib.parse.quote(password, safe=DELIMS)

    return WSParsedURL(url, secure, netloc, WSHost(host), WSPort(port), path, query, username, password)
