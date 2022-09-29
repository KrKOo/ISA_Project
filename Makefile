CXX = g++
CXXFLAGS = -Wall -Wextra -Werror -MMD -MP -g
LDFLAGS=-lpcap

OBJDIR := obj

SOURCES := $(wildcard *.cpp)
OBJECTS := $(patsubst %.cpp, $(OBJDIR)/%.o, $(SOURCES))
DEPENDS := $(patsubst %.o, %.d, $(OBJECTS))


all: flow

run: flow
	./flow

flow: $(OBJECTS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJDIR)/%.o: %.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS)  -c $< -o $@

$(OBJDIR):
	mkdir $(OBJDIR)

-include $(DEPENDS:.o=.d)

.PHONY: clean
clean:
	rm -rf $(OBJDIR) flow 