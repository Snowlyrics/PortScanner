CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17 -O2 -pthread
TARGET = PortScanner
SRCS = main.cpp scanner.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	g++ $(CXXFLAGS) -o $(TARGET) $(OBJS)

main.o: main.cpp scanner.h
	g++ $(CXXFLAGS) -c main.cpp

scanner.o: scanner.cpp scanner.h
	g++ $(CXXFLAGS) -c scanner.cpp

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
