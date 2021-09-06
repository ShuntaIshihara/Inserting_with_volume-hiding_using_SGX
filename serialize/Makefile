COMPILER = $(CXX)
CPPFLAGS = -Wall -std=c++11
LIBS = -I/home/kdeprivacy/cereal-1.3.0/include
TARGET=$(patsubst %.cpp, %, $(wildcard *.cpp))

.PHONY: all clean run

all: $(TARGET)

%: %.cpp
	$(COMPILER) $(CPPFLAGS)  $< -o $@ $(LIBS)
