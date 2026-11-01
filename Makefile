# Documentation targets. `make docs` is what docs-deploy.yml runs, so a green
# local build means a green deploy. Needs mkdocs-material, pymdown-extensions,
# pyyaml and mkdocs-exclude on PATH (pip install them into a venv).

.PHONY: docs docs-check docs-serve

docs:            ## regenerate docs/ and mkdocs.yml, then build the site strictly
	python3 tools/prep_docs.py
	mkdocs build --strict

docs-check:      ## CI drift gate: fail if any generated doc is stale
	python3 tools/prep_docs.py --check
	mkdocs build --strict

docs-serve:      ## regenerate, then serve locally with live reload
	python3 tools/prep_docs.py
	mkdocs serve
