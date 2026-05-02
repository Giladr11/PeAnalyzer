# Commands
GCC_CMD = gcc -Wall -g -O0 -Isrc

# GENERAL DIRS
BUILD_DIR = build
SRC_DIR   = src

# FILES DIRS 
CORE_DIR    = core
DUMPERS_DIR = dumpers
PARSERS_DIR = parsers
TESTS_DIR   = tests
UTILS_DIR   = utils
 
#---SRC---------------------------------------

# MAIN C FILES
MAIN_C = $(SRC_DIR)/main.c

# CORE C FILES 
CORE_C = $(SRC_DIR)/$(CORE_DIR)/core.c

# PARSERS C FILES 
HEADERS_C  = $(SRC_DIR)/$(PARSERS_DIR)/headers.c
EXPORTS_C  = $(SRC_DIR)/$(PARSERS_DIR)/exports.c
IMPORTS_C  = $(SRC_DIR)/$(PARSERS_DIR)/imports.c
SECTIONS_C = $(SRC_DIR)/$(PARSERS_DIR)/sections.c

# DUMPERS C FILES


# UTILS C FILES
UTILS_C = $(SRC_DIR)/$(UTILS_DIR)/utils.c

# TESTS C FILES
TESTS_C = $(SRC_DIR)/$(TESTS_DIR)/tests.c

SOURCES_C = \
	$(wildcard src/*.c) \
	$(wildcard src/*/*.c) \
	$(wildcard src/*/*/*.c)

#---BUILD-------------------------------------

# MAIN OBJ FILES
MAIN_OBJ = $(BUILD_DIR)/main.o

# CORE OBJ FILES 
CORE_OBJ = $(BUILD_DIR)/$(CORE_DIR)/core.o

# PARSERS OBJ FILES 
HEADERS_OBJ  = $(BUILD_DIR)/$(PARSERS_DIR)/headers.o
EXPORTS_OBJ  = $(BUILD_DIR)/$(PARSERS_DIR)/exports.o
IMPORTS_OBJ  = $(BUILD_DIR)/$(PARSERS_DIR)/imports.o
SECTIONS_OBJ = $(BUILD_DIR)/$(PARSERS_DIR)/sections.o

# DUMPERS OBJ FILES


# UTILS OBJ FILES
UTILS_OBJ = $(BUILD_DIR)/$(UTILS_DIR)/utils.o

# TESTS OBJ FILES
TESTS_OBJ = $(BUILD_DIR)/$(TESTS_DIR)/tests.o

# FINAL PE ANLYZER EXE
PE_ANLYZER_EXE = $(BUILD_DIR)/PeAnalyzer.exe

OBJECTS_C = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SOURCES_C))

#-----COMPILATION-----------------------------------

all: $(UTILS_OBJ) $(PE_ANLYZER_EXE)

$(PE_ANLYZER_EXE): $(UTILS_OBJ) $(OBJECTS_C)  
	$(GCC_CMD) $(OBJECTS_C) -o $(PE_ANLYZER_EXE)
 	
$(BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(GCC_CMD) -c $< -o $@

clean:
	@echo "Cleaning '$(BUILD_DIR)' Directory..."
	powershell -Command "Get-ChildItem -Path '$(BUILD_DIR)' -File -Recurse | Where-Object { $$_.Name -ne '.gitkeep' } | Remove-Item -Force"
