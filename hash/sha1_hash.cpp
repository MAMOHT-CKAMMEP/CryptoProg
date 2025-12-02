#include <iostream>
#include <fstream>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Использование: " << argv[0] << " <имя_файла>" << std::endl;
        std::cerr << "Пример: " << argv[0] << " document.txt" << std::endl;
        return 1;
    }
    
    std::string filename = argv[1];
    std::ifstream file(filename, std::ios::binary);
    
    if (!file) {
        std::cerr << "Ошибка: Не удалось открыть файл '" << filename << "'" << std::endl;
        return 1;
    }
    
    try {
        CryptoPP::SHA1 hash;
        std::string digest;
        
        CryptoPP::FileSource(file, true,
            new CryptoPP::HashFilter(hash,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(digest),
                    false
                )
            )
        );
        
        std::cout << "Файл: " << filename << std::endl;
        std::cout << "Хэш SHA-1: " << digest << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Ошибка при вычислении хэша: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}