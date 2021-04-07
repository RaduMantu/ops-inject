.PHONY: dirs

# important directories
SRC		 = src
BIN		 = bin
OBJ		 = obj
INCLUDE  = include

# compilation related parameters
CXX      = g++
CXXFLAGS = -std=c++17
CC       = gcc
CFLAGS   =
LDFLAGS  = -lnetfilter_queue

# identify sources and create object file targets
SOURCES_CPP = $(wildcard $(SRC)/*.cpp)
SOURCES_C   = $(wildcard $(SRC)/*.c)
OBJECTS     = $(patsubst $(SRC)/%.cpp, $(OBJ)/%.o, $(SOURCES_CPP))
OBJECTS    += $(patsubst $(SRC)/%.c,   $(OBJ)/%.o, $(SOURCES_C))

# top level rule
build: dirs $(BIN)/ops-inject

# non-persistent folder creation rule
dirs:
	@mkdir -p $(BIN) $(OBJ)

# final binary generation rule
$(BIN)/ops-inject: $(OBJECTS)
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# object generation rule
$(OBJ)/%.o: $(SRC)/%.cpp
	$(CXX) -c -I $(INCLUDE) $(CXXFLAGS) -o $@ $<

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) -c -I $(INCLUDE) $(CFLAGS) -o $@ $<

# clean rule
clean:
	@rm -rf $(BIN) $(OBJ)

