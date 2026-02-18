## Testing instructions
- Run lint after updating code with:
`flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics`
Fix all errors

- Run mypy after updating code with:  
`mypy picows`
Fix errors, or disable errors that seems to be mypy quirks with #ignore comments.