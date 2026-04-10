## Description

Read README.md for the basic understanding of what this project is.

picows - this is the main package

aiofastnet - Contains optimized versions of asyncio create_connection, create_server
I plan to make a separate python project for it, but I'm not there yet. It should be treated
as a separate python project. It will have its own tests, eventually its own description and docs.
The project contains very efficient repimplementation of SelectSocketTransport and SSLProtocol 
using Cython and sometimes a pure C code. create_connection, create_server are defined in aiofastnet/api.py
sslproto.pyx - hack python SSLContext to get raw SSL_CTX*, it works with openssl api directly after that.
sslproto_stdlib.pyx - is just for reference, I will delete it soon, but now it's good for comparison between
stdlib ssl and whatever is in sslproto.pyx.

tests - Contains tests for both picows and aiofastnet. Tests for aiofastnet will become a part of a separate project.

## Testing instructions
- Run lint after updating code with:
`flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics`
Fix all errors

- Run mypy after updating code with:  
`mypy picows`
Fix errors, or disable errors that seems to be mypy quirks with #ignore comments.
