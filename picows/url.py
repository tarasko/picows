from __future__ import annotations

import dataclasses
import urllib.parse


# All characters from the gen-delims and sub-delims sets in RFC 3987.
DELIMS = ":/?#[]@!$&'()*+,;="


class WSInvalidURL(ValueError):
    """
    Raised when connecting to a ParsedURL that isn't a valid WebSocket ParsedURL.
    """

    uri: str
    msg: str

    def __init__(self, uri: str, msg: str) -> None:
        self.uri = uri
        self.msg = msg

    def __str__(self) -> str:
        return f"{self.uri} isn't a valid ParsedURL: {self.msg}"


@dataclasses.dataclass
class ParsedURL:
    """
    Websocket ParsedURL.

    Attributes:
        secure: :obj:`True` for a ``wss`` ParsedURL, :obj:`False` for a ``ws`` ParsedURL.
        host: Normalized to lower case.
        port: Always set even if it's the default.
        path: May be empty.
        query: May be empty if the ParsedURL doesn't include a query component.
        username: Available when the ParsedURL contains `User Information`_.
        password: Available when the ParsedURL contains `User Information`_.

    .. _User Information: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1

    """

    url: str
    secure: bool
    netloc: str
    host: str
    port: int
    path: str
    query: str
    username: str | None = None
    password: str | None = None

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
    def user_info(self) -> tuple[str, str] | None:
        if self.username is None:
            return None
        assert self.password is not None
        return (self.username, self.password)


def parse_url(url: str) -> ParsedURL:
    """
    Parse and validate a WebSocket ParsedURL.

    Args:
        url: WebSocket ParsedURL.

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
