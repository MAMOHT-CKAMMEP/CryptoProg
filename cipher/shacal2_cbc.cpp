#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <vector>
#include <iomanip>
#include <cryptopp/cryptlib.h>
#include <cryptopp/shacal2.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>

using namespace std;
using namespace CryptoPP;

// Константы
const size_t BLOCK_SIZE = 32;    // 256 бит для SHACAL2 (размер блока)
const size_t KEY_SIZE = 32;      // 256 бит для SHACAL2 (размер ключа)
const size_t IV_SIZE = BLOCK_SIZE; // IV должен быть равен размеру блока
const size_t SALT_SIZE = 16;     // Соль для KDF
const size_t ITERATIONS = 10000; // Количество итераций для PBKDF2

// Структура для заголовка файла
struct FileHeader {
    byte salt[SALT_SIZE];
    byte iv[IV_SIZE];
};

// Генерация ключа из пароля
void DeriveKey(const string& password, const byte* salt, size_t salt_len, byte* key, size_t key_len) {
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf;
    byte unused = 0;
    
    pbkdf.DeriveKey(key, key_len, unused, 
                   reinterpret_cast<const byte*>(password.data()), password.size(),
                   salt, salt_len, ITERATIONS);
}

// Шифрование файла
bool EncryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        // Чтение исходного файла
        ifstream inFile(inputFile, ios::binary);
        if (!inFile) {
            cerr << "Ошибка: не удалось открыть входной файл: " << inputFile << endl;
            return false;
        }
        
        // Получение размера файла
        inFile.seekg(0, ios::end);
        size_t fileSize = inFile.tellg();
        inFile.seekg(0, ios::beg);
        
        if (fileSize == 0) {
            cerr << "Ошибка: входной файл пуст" << endl;
            inFile.close();
            return false;
        }
        
        // Чтение данных
        vector<byte> plaintext(fileSize);
        inFile.read(reinterpret_cast<char*>(plaintext.data()), fileSize);
        inFile.close();
        
        // Генерация случайной соли и IV
        AutoSeededRandomPool rng;
        FileHeader header;
        rng.GenerateBlock(header.salt, SALT_SIZE);
        rng.GenerateBlock(header.iv, IV_SIZE);
        
        // Генерация ключа из пароля
        byte key[KEY_SIZE];
        DeriveKey(password, header.salt, SALT_SIZE, key, KEY_SIZE);
        
        // Шифрование
        CBC_Mode<SHACAL2>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, KEY_SIZE, header.iv, IV_SIZE);
        
        // Шифрование данных
        vector<byte> ciphertext;
        StringSource(plaintext.data(), plaintext.size(), true,
            new StreamTransformationFilter(encryptor,
                new VectorSink(ciphertext)));
        
        // Запись заголовка и шифротекста в выходной файл
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cerr << "Ошибка: не удалось создать выходной файл: " << outputFile << endl;
            return false;
        }
        
        // Запись заголовка
        outFile.write(reinterpret_cast<const char*>(&header), sizeof(FileHeader));
        
        // Запись шифротекста
        outFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
        
        outFile.close();
        
        cout << "Файл успешно зашифрован." << endl;
        cout << "Исходный файл: " << inputFile << " (" << fileSize << " байт)" << endl;
        cout << "Зашифрованный файл: " << outputFile << " (" << (sizeof(FileHeader) + ciphertext.size()) << " байт)" << endl;
        
        return true;
    }
    catch(const Exception& e) {
        cerr << "Ошибка шифрования: " << e.what() << endl;
        return false;
    }
    catch(const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return false;
    }
}

// Дешифрование файла
bool DecryptFile(const string& inputFile, const string& outputFile, const string& password) {
    try {
        // Открытие входного файла
        ifstream inFile(inputFile, ios::binary);
        if (!inFile) {
            cerr << "Ошибка: не удалось открыть входной файл: " << inputFile << endl;
            return false;
        }
        
        // Проверка размера файла
        inFile.seekg(0, ios::end);
        size_t totalSize = inFile.tellg();
        inFile.seekg(0, ios::beg);
        
        if (totalSize < sizeof(FileHeader)) {
            cerr << "Ошибка: файл слишком мал для дешифрования" << endl;
            inFile.close();
            return false;
        }
        
        // Чтение заголовка
        FileHeader header;
        inFile.read(reinterpret_cast<char*>(&header), sizeof(FileHeader));
        
        // Получение размера шифротекста
        size_t ciphertextSize = totalSize - sizeof(FileHeader);
        
        // Чтение шифротекста
        vector<byte> ciphertext(ciphertextSize);
        inFile.read(reinterpret_cast<char*>(ciphertext.data()), ciphertextSize);
        inFile.close();
        
        if (ciphertextSize == 0) {
            cerr << "Ошибка: файл не содержит данных для дешифрования" << endl;
            return false;
        }
        
        // Генерация ключа из пароля
        byte key[KEY_SIZE];
        DeriveKey(password, header.salt, SALT_SIZE, key, KEY_SIZE);
        
        // Дешифрование
        CBC_Mode<SHACAL2>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, KEY_SIZE, header.iv, IV_SIZE);
        
        // Дешифрование данных
        vector<byte> plaintext;
        StringSource(ciphertext.data(), ciphertextSize, true,
            new StreamTransformationFilter(decryptor,
                new VectorSink(plaintext)));
        
        // Запись в выходной файл
        ofstream outFile(outputFile, ios::binary);
        if (!outFile) {
            cerr << "Ошибка: не удалось создать выходной файл: " << outputFile << endl;
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
        outFile.close();
        
        cout << "Файл успешно расшифрован." << endl;
        cout << "Зашифрованный файл: " << inputFile << " (" << totalSize << " байт)" << endl;
        cout << "Расшифрованный файл: " << outputFile << " (" << plaintext.size() << " байт)" << endl;
        
        return true;
    }
    catch(const Exception& e) {
        cerr << "Ошибка дешифрования: " << e.what() << endl;
        return false;
    }
    catch(const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
        return false;
    }
}

// Показать справку
void ShowHelp() {
    cout << "SHACAL2-CBC File Encryptor/Decryptor" << endl;
    cout << "=====================================" << endl;
    cout << "Используется алгоритм: SHACAL2, режим: CBC" << endl;
    cout << "Размер блока: 256 бит" << endl;
    cout << "Размер ключа: 256 бит" << endl;
    cout << "Размер IV: 256 бит" << endl << endl;
    
    cout << "СИНТАКСИС:" << endl;
    cout << "  Интерактивный режим:" << endl;
    cout << "    " << "./shacal2_cbc" << endl << endl;
    
    cout << "  Пакетный режим:" << endl;
    cout << "    " << "./shacal2_cbc encrypt <input> <output> <password>" << endl;
    cout << "    " << "./shacal2_cbc decrypt <input> <output> <password>" << endl << endl;
    
    cout << "ПРИМЕРЫ:" << endl;
    cout << "  Шифрование:" << endl;
    cout << "    " << "./shacal2_cbc encrypt document.txt encrypted.bin MySecretPassword" << endl << endl;
    
    cout << "  Дешифрование:" << endl;
    cout << "    " << "./shacal2_cbc decrypt encrypted.bin decrypted.txt MySecretPassword" << endl;
}

// Интерактивный режим
void InteractiveMode() {
    cout << "=== SHACAL2-CBC File Encryptor/Decryptor ===" << endl;
    cout << "Используется алгоритм: SHACAL2, режим: CBC" << endl;
    cout << "Размер блока: 256 бит" << endl;
    cout << "Размер ключа: 256 бит" << endl;
    cout << "Размер IV: 256 бит" << endl << endl;
    
    while (true) {
        int choice;
        cout << "\nВыберите режим работы:" << endl;
        cout << "1. Зашифровать файл" << endl;
        cout << "2. Расшифровать файл" << endl;
        cout << "3. Показать справку" << endl;
        cout << "0. Выход" << endl;
        cout << "Ваш выбор: ";
        
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(10000, '\n');
            cout << "Неверный ввод. Пожалуйста, введите число." << endl;
            continue;
        }
        
        cin.ignore(); // Игнорируем оставшийся символ новой строки
        
        if (choice == 0) {
            cout << "Выход из программы." << endl;
            break;
        }
        
        if (choice == 3) {
            ShowHelp();
            continue;
        }
        
        string inputFile, outputFile, password;
        
        cout << "Введите путь к входному файлу: ";
        getline(cin, inputFile);
        
        if (inputFile.empty()) {
            cout << "Путь к файлу не может быть пустым!" << endl;
            continue;
        }
        
        cout << "Введите путь для выходного файла: ";
        getline(cin, outputFile);
        
        if (outputFile.empty()) {
            cout << "Путь к выходному файлу не может быть пустым!" << endl;
            continue;
        }
        
        cout << "Введите пароль: ";
        getline(cin, password);
        
        if (password.empty()) {
            cout << "Пароль не может быть пустым!" << endl;
            continue;
        }
        
        bool success = false;
        
        switch(choice) {
            case 1:
                cout << "\nНачинаю шифрование..." << endl;
                success = EncryptFile(inputFile, outputFile, password);
                break;
            case 2:
                cout << "\nНачинаю дешифрование..." << endl;
                success = DecryptFile(inputFile, outputFile, password);
                break;
            default:
                cout << "Неверный выбор! Попробуйте снова." << endl;
                continue;
        }
        
        if (success) {
            cout << "✓ Операция выполнена успешно!" << endl;
        } else {
            cout << "✗ Операция завершилась с ошибкой." << endl;
        }
    }
}

int main(int argc, char* argv[]) {
    // Проверка аргументов командной строки
    if (argc == 1) {
        // Интерактивный режим
        InteractiveMode();
    } else if (argc == 5) {
        // Пакетный режим: program mode input output password
        string mode = argv[1];
        string inputFile = argv[2];
        string outputFile = argv[3];
        string password = argv[4];
        
        cout << "SHACAL2-CBC File Encryptor/Decryptor" << endl;
        cout << "=====================================" << endl;
        
        bool success = false;
        
        if (mode == "encrypt") {
            cout << "Режим: Шифрование" << endl;
            success = EncryptFile(inputFile, outputFile, password);
        } else if (mode == "decrypt") {
            cout << "Режим: Дешифрование" << endl;
            success = DecryptFile(inputFile, outputFile, password);
        } else {
            cerr << "Ошибка: Неверный режим. Используйте 'encrypt' или 'decrypt'" << endl;
            cerr << "Для справки запустите программу без аргументов" << endl;
            return 1;
        }
        
        if (success) {
            cout << "✓ Операция выполнена успешно!" << endl;
            return 0;
        } else {
            cerr << "✗ Операция завершилась с ошибкой." << endl;
            return 1;
        }
    } else {
        // Неверное количество аргументов
        if (argc > 1 && string(argv[1]) == "--help") {
            ShowHelp();
        } else {
            cerr << "Ошибка: Неверное количество аргументов." << endl;
            cerr << "Для интерактивного режима: " << argv[0] << endl;
            cerr << "Для пакетного режима: " << argv[0] << " <encrypt|decrypt> <input> <output> <password>" << endl;
            cerr << "Для справки: " << argv[0] << " --help" << endl;
            return 1;
        }
    }
    
    return 0;
}