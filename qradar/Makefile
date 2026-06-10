.PHONY: test coverage clean

test:
	python3 -m pytest tests/ -v

coverage:
	coverage run -m pytest tests/ -v
	coverage report -m

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .coverage htmlcov
