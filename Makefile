# Makefile for CCS Framework

.PHONY: all install test clean docs deploy

# Variables
PYTHON = python3
PIP = pip3
PROJECT = ccs-framework
VERSION = 1.0.0

# Directories
SRC_DIR = src
TEST_DIR = tests
DOCS_DIR = docs
EXAMPLES_DIR = examples

all: install test

# Installation
install:
	$(PIP) install -r requirements.txt
	$(PYTHON) setup.py develop

# Testing
test:
	cd $(TEST_DIR) && $(PYTHON) -m pytest -v --cov=$(SRC_DIR) --cov-report=html

test-performance:
	cd $(TEST_DIR)/performance && $(PYTHON) benchmark.py

test-security:
	cd $(TEST_DIR)/security && $(PYTHON) steganalysis_test.py

test-robustness:
	cd $(TEST_DIR)/robustness && $(PYTHON) dynamic_environment_test.py

# Documentation
docs:
	cd $(DOCS_DIR) && make html

# Examples
run-example:
	cd $(EXAMPLES_DIR) && $(PYTHON) concrete_example.py

run-enterprise-example:
	cd $(EXAMPLES_DIR) && $(PYTHON) enterprise_deployment.py

# Packaging
build:
	$(PYTHON) setup.py sdist bdist_wheel

publish: build
	twine upload dist/*

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf __pycache__/
	rm -rf $(SRC_DIR)/__pycache__/
	rm -rf $(TEST_DIR)/__pycache__/
	rm -rf $(EXAMPLES_DIR)/__pycache__/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	find . -name ".DS_Store" -delete

# Docker
docker-build:
	docker build -t $(PROJECT):$(VERSION) .

docker-run:
	docker run -it --rm $(PROJECT):$(VERSION)

# Development
format:
	black $(SRC_DIR) $(TEST_DIR) $(EXAMPLES_DIR)
	isort $(SRC_DIR) $(TEST_DIR) $(EXAMPLES_DIR)

lint:
	flake8 $(SRC_DIR) $(TEST_DIR) $(EXAMPLES_DIR)
	mypy $(SRC_DIR)

# Deployment
deploy-test:
	# Deploy to test environment
	./deploy_scripts/deploy_test.sh

deploy-prod:
	# Deploy to production environment
	./deploy_scripts/deploy_prod.sh

# Help
help:
	@echo "CCS Framework Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  all          - Install dependencies and run tests"
	@echo "  install      - Install dependencies"
	@echo "  test         - Run all tests"
	@echo "  test-performance - Run performance benchmarks"
	@echo "  test-security    - Run security tests"
	@echo "  test-robustness  - Run robustness tests"
	@echo "  docs         - Generate documentation"
	@echo "  run-example  - Run concrete example"
	@echo "  build        - Build distribution packages"
	@echo "  publish      - Publish to PyPI"
	@echo "  clean        - Clean build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  format       - Format code with black/isort"
	@echo "  lint         - Lint code with flake8/mypy"
	@echo "  deploy-test  - Deploy to test environment"
	@echo "  deploy-prod  - Deploy to production environment"
