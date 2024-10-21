# Variables
PYTHON_SETUP = setup
PYTHON_APPEND = logappend
PYTHON_READ = logread
PYINSTALLER = pyinstaller
KEY_FILE = secret.key

# Default build target (run all steps in one go)
.PHONY: build
build: clean keyfile executables

# Step 1: Generate the secret.key if it doesn't exist
.PHONY: keyfile
keyfile: 
	@if [ ! -f "$(KEY_FILE)" ]; then \
		echo "Generating $(KEY_FILE)..."; \
		python3 setup.py dummy_password dummy_logfile; \
	else \
		echo "$(KEY_FILE) already exists."; \
	fi

# Step 2: Run PyInstaller to create executables for all scripts
.PHONY: executables
executables:
	$(PYINSTALLER) --onefile --add-data "$(KEY_FILE):." --distpath . logappend.py
	$(PYINSTALLER) --onefile --add-data "$(KEY_FILE):." --distpath . logread.py
	$(PYINSTALLER) --onefile --add-data "$(KEY_FILE):." --distpath . setup.py
	@echo "Executables built and located in the current directory."

# Step 3: Clean up any previous builds
.PHONY: clean
clean:
	rm -rf build dist __pycache__ *.spec
	rm -f secret.key dummy_logfile
	rm -f logappend logread setup
	rm -f log[0-9]*
