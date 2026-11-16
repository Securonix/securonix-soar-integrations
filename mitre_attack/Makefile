.PHONY: test coverage clean

test:
	pytest tests/ -v

coverage:
	coverage run -m pytest tests/ -v
	coverage report -m

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov/
