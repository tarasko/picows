# Run lint after updating code, and fix all errors 
flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

# Run mypy after updating code, and fix all errors. Disable errors that seems to be mypy quirks with #ignore comments  
mypy picows