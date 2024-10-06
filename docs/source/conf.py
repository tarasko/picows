import os
import sys
sys.path.insert(0, os.path.abspath('../../'))
import picows

# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'picows'
copyright = '2024, Taras Kozlov'
author = picows.__author__
release = picows.__version__

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = ['sphinx.ext.autodoc', 'enum_tools.autoenum']

templates_path = ['_templates']
exclude_patterns = []

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
# html_theme = "agogo"

html_static_path = ['_static']

html_theme_options = {
    'page_width': '1300px',  # Set this to your desired width
    'sidebar_width': '450px',  # Adjust the sidebar width as well
}
