# Компилятор и флаги
CXX = g++
CXXFLAGS = -std=c++11 -O2 -Wall -Wextra
LDFLAGS = -lcryptopp

# Имя исполняемого файла
TARGET = shacal2_cbc

# Исходные файлы
SRCS = shacal2_cbc.cpp

# Основная цель
all: $(TARGET)

# Сборка исполняемого файла
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

# Запуск программы в интерактивном режиме
run: $(TARGET)
	./$(TARGET)

# Тестирование программы
test: $(TARGET)
	@echo "=============================================="
	@echo "ЗАПУСК ТЕСТИРОВАНИЯ SHACAL2-CBC"
	@echo "=============================================="
	@echo ""
	
	@# Тест 1: Шифрование текстового файла
	@echo "Тест 1: Шифрование текстового файла"
	@echo "Создание тестового файла..."
	@echo "This is a secret document." > test_document.txt
	@echo "Тест с русскими символами: Привет мир!" >> test_document.txt
	@echo "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~\`" >> test_document.txt
	
	@echo "Исходный файл создан. Размер: $$(wc -c < test_document.txt) байт"
	@echo ""
	
	@echo "Шифрование файла..."
	@if ./$(TARGET) encrypt test_document.txt encrypted.bin MyTestPassword123; then \
		echo "✓ Шифрование успешно"; \
	else \
		echo "✗ Ошибка шифрования"; exit 1; \
	fi
	@echo ""
	
	@# Тест 2: Дешифрование файла
	@echo "Тест 2: Дешифрование файла"
	@echo "Дешифрование файла..."
	@if ./$(TARGET) decrypt encrypted.bin decrypted.txt MyTestPassword123; then \
		echo "✓ Дешифрование успешно"; \
	else \
		echo "✗ Ошибка дешифрования"; exit 1; \
	fi
	@echo ""
	
	@# Тест 3: Проверка целостности данных
	@echo "Тест 3: Проверка целостности данных"
	@if diff test_document.txt decrypted.txt > /dev/null 2>&1; then \
		echo "✓ Данные полностью совпадают"; \
	else \
		echo "✗ Ошибка: данные не совпадают!"; \
		echo "Различия:"; \
		diff test_document.txt decrypted.txt || true; \
		exit 1; \
	fi
	@echo ""
	
	@# Тест 4: Тест с бинарными данными
	@echo "Тест 4: Шифрование бинарных данных"
	@echo "Создание бинарного файла..."
	@dd if=/dev/urandom of=test_binary.bin bs=1024 count=10 2>/dev/null
	@echo "Исходный файл создан. Размер: $$(wc -c < test_binary.bin) байт"
	@echo ""
	
	@echo "Шифрование бинарного файла..."
	@if ./$(TARGET) encrypt test_binary.bin encrypted_binary.bin MyTestPassword456; then \
		echo "✓ Шифрование успешно"; \
	else \
		echo "✗ Ошибка шифрования"; exit 1; \
	fi
	@echo ""
	
	@echo "Дешифрование бинарного файла..."
	@if ./$(TARGET) decrypt encrypted_binary.bin decrypted_binary.bin MyTestPassword456; then \
		echo "✓ Дешифрование успешно"; \
	else \
		echo "✗ Ошибка дешифрования"; exit 1; \
	fi
	@echo ""
	
	@echo "Проверка целостности бинарных данных..."
	@if cmp test_binary.bin decrypted_binary.bin > /dev/null 2>&1; then \
		echo "✓ Бинарные данные полностью совпадают"; \
	else \
		echo "✗ Ошибка: бинарные данные не совпадают!"; \
		exit 1; \
	fi
	@echo ""
	
	@echo "=============================================="
	@echo "ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!"
	@echo "=============================================="
	@echo ""
	@echo "Очистка тестовых файлов..."
	@rm -f test_document.txt encrypted.bin decrypted.txt
	@rm -f test_binary.bin encrypted_binary.bin decrypted_binary.bin
	@echo "Очистка завершена."

# Очистка
clean:
	rm -f $(TARGET)
	rm -f test_*.txt test_*.bin *.enc *.dec quick_*.txt quick_*.bin

# Справка
help:
	@echo "Доступные команды:"
	@echo "  make           - собрать программу"
	@echo "  make run       - собрать и запустить в интерактивном режиме"
	@echo "  make test      - запустить полное тестирование"
	@echo "  make quick-test - запустить быстрый тест"
	@echo "  make clean     - удалить скомпилированные файлы"
	@echo ""
	@echo "Использование программы:"
	@echo "  Интерактивный режим:"
	@echo "    ./shacal2_cbc"
	@echo ""
	@echo "  Пакетный режим:"
	@echo "    Шифрование: ./shacal2_cbc encrypt <input> <output> <password>"
	@echo "    Дешифрование: ./shacal2_cbc decrypt <input> <output> <password>"
	@echo ""
	@echo "  Справка:"
	@echo "    ./shacal2_cbc --help"

.PHONY: all run test clean help