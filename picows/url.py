import dataclasses
import urllib.parse
from typing import Optional

from .types import WSError

# All characters from the gen-delims and sub-delims sets in RFC 3987.
DELIMS = ":/?#[]@!$&'()*+,;="


class WSInvalidURL(WSError):
    """
    Raised when connecting to a URL that isn't a valid WebSocket URL.
    """
    def __init__(self, url: str, msg: str) -> None:
        super().__init__(f"{url} isn't a valid URL: {msg}")
        self.url = url
        self.msg = msg


@dataclasses.dataclass
class ParsedURL:
    """
    Websocket URL.

    Attributes:
        secure: :obj:`True` for a ``wss`` ParsedURL, :obj:`False` for a ``ws`` URL.
        host: Normalized to lower case.
        port: Always set even if it's the default.
        path: May be empty.
        query: May be empty if the URL doesn't include a query component.
        username: Available when the URL contains `User Information`_.
        password: Available when the URL contains `User Information`_.

    .. _User Information: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1

    """

    url: str
    secure: bool
    netloc: str
    host: str
    port: int
    path: str
    query: str
    username: Optional[str] = None
    password: Optional[str] = None

    @property
    def resource_name(self) -> str:
        if self.path:
            resource_name = self.path
        else:
            resource_name = "/"
        if self.query:
            resource_name += "?" + self.query
        return resource_name

    @property
    def user_info(self) -> Optional[tuple[str, str]]:
        if self.username is None:
            return None
        assert self.password is not None
        return self.username, self.password


def parse_url(url: str) -> ParsedURL:
    """
    Parse and validate a WebSocket URL.

    Args:
        url: WebSocket URL.

    Returns:
        Parsed WebSocket ParsedURL.

    Raises:
        InvalidURL: If ``url`` isn't a valid WebSocket URL.

    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ["ws", "wss"]:
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
        # It must be an IRI. Convert it to a ParsedURL.
        host = host.encode("idna").decode()
        path = urllib.parse.quote(path, safe=DELIMS)
        query = urllib.parse.quote(query, safe=DELIMS)
        if username is not None:
            assert password is not None
            username = urllib.parse.quote(username, safe=DELIMS)
            password = urllib.parse.quote(password, safe=DELIMS)

    if username is not None or password is not None:
        raise WSInvalidURL(url, "basic authentication method is not currently supported")

    return ParsedURL(url, secure, netloc, host, port, path, query, username, password)
