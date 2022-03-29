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
LDFLAGS  = $(shell pkg-config --libs \
		   		libnetfilter_queue)

# identify sources and create object file targets
SOURCES_CPP = $(wildcard $(SRC)/*.cpp)
SOURCES_C   = $(wildcard $(SRC)/*.c)
OBJECTS     = $(patsubst $(SRC)/%.cpp, $(OBJ)/%.o, $(SOURCES_CPP)) \
			  $(patsubst $(SRC)/%.c,   $(OBJ)/%.o, $(SOURCES_C))

# directive to prevent (attempted) itermediary file/directory deletion
.PRECIOUS: $(BIN)/ $(OBJ)/

# top level rule (specifies final binary)
build: $(BIN)/ops-inject

# generate compile_Commands.json for clangd (or other language servers)
bear:
	bear -- $(MAKE) build

# non-persistent directory creation rule
%/:
	@mkdir -p $@

# final binary generation rule
$(BIN)/ops-inject: $(OBJECTS) | $(BIN)/
	$(CXX) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# object generation rule
$(OBJ)/%.o: $(SRC)/%.cpp | $(OBJ)/
	$(CXX) -c -I $(INCLUDE) $(CXXFLAGS) -o $@ $<

$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)/
	$(CC) -c -I $(INCLUDE) $(CFLAGS) -o $@ $<

# clean rule
clean:
	@rm -rf $(BIN) $(OBJ)

