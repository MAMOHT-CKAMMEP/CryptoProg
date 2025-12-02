CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra
LDFLAGS = -lcryptopp
TARGET = sha1_hash
SRCS = sha1_hash.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

run: $(TARGET)
	@echo "Укажите файл для хэширования:"
	@echo "Пример: ./$(TARGET) test.txt"
	@echo "Или создайте тестовый файл: make test"


test: $(TARGET)
	@echo "\n====================================="
	@echo "ТЕСТ ФРАЗЫ: SUPER TESTTT424242"
	@echo -n "SUPER TESTTT424242" > test.txt
	@./$(TARGET) test.txt
	@rm -f test.txt
	@echo "======================================\n"

clean:
	rm -f $(TARGET)

.PHONY: all run test clean