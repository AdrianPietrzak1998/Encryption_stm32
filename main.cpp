
#include <iostream>
#include <string>
#include <windows.h>
#include <fstream>
#include <sstream>
#include <handleapi.h>
#include <aes.hpp>
#include <key.h>
#include <dirent.h>

#define POLY 0x04C11DB7
#define PACKET_SIZE_CONST 1024

uint32_t calculate_crc32(uint32_t* data, size_t length);
void alignDataTo128Bits(uint8_t* data, uint32_t* length);


struct AES_ctx ctx;

void updateIV(uint8_t* iv, const uint8_t* block) {
    for (int i = 0; i < 16; i++) {
        iv[i] ^= block[i];
    }
}


int main()
{
    AES_init_ctx_iv(&ctx, key, iv);
    union data {
        uint32_t data32[1024 * 1024 / 4 + 1];
        uint8_t data8[1024 * 1024 + 4];
    }data;

   DIR* dir = opendir(".");
    if (!dir) {
        std::cout << "Error opening directory." << std::endl;
        return 1;
    }

    std::string binFileName;

    // Przeszukaj katalog w poszukiwaniu pliku .bin
    dirent* entry;
    while ((entry = readdir(dir))) {
        std::string fileName = entry->d_name;
        if (fileName.size() >= 4 && fileName.substr(fileName.size() - 4) == ".bin") {
            binFileName = fileName;
            break;
        }
    }

    closedir(dir);

    if (binFileName.empty()) {
        std::cout << "No .bin file found." << std::endl;
        return 1;
    }

    std::ifstream binaryFile(binFileName, std::ios::binary);
    if (!binaryFile) {
        std::cout << "Error opening file: " << binFileName << std::endl;
        return 1;
    }

    std::cout << binFileName << std::endl;


    binaryFile.read(reinterpret_cast<char*>(data.data8), sizeof(data.data8));
    binaryFile.close();
    uint32_t binary_size = binaryFile.gcount();
    alignDataTo128Bits(data.data8, &binary_size);
    uint32_t FullCrc = calculate_crc32(data.data32, binary_size/4);
    std::cout << std::hex << FullCrc << "    " << binary_size <<std::endl;


    //AES_CBC_encrypt_buffer(&ctx, data.data8, binary_size);

    for(uint32_t ByteToSend = binary_size; ByteToSend > 0; )
    {
        uint16_t ActualPacketSize;
        uint32_t ActualAddress;

        if(ByteToSend >=PACKET_SIZE_CONST)
        {
            ActualPacketSize = PACKET_SIZE_CONST;
        }
        else
        {
            ActualPacketSize = ByteToSend;
        }


        AES_ctx_set_iv(&ctx, iv);
        AES_CBC_encrypt_buffer(&ctx, data.data8 + ActualAddress, ActualPacketSize);
        updateIV(iv, iv_update);





        ///
        ///PacketDone
        ///
        ByteToSend -= ActualPacketSize;
        std::cout << "Zaszyfrowano: " << ActualPacketSize <<std::endl;
        ActualAddress += ActualPacketSize;


    }





    data.data32[binary_size/4] = FullCrc;





    std::ofstream outputFile(binFileName, std::ios::binary);
    if (!outputFile) {
        std::cout << "Open output file error" << std::endl;
        return 1;
    }
    outputFile.write(reinterpret_cast<char*>(data.data8), binary_size+4);
    outputFile.close();

    return 0;
}



uint32_t calculate_crc32(uint32_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];

        for (int j = 0; j < 32; j++) {
            if (crc & 0x80000000) {
                crc = (crc << 1) ^ POLY;
            } else {
                crc = crc << 1;
            }
        }
    }

    return crc;
}

void alignDataTo128Bits(uint8_t* data, uint32_t* length) {
    uint32_t padding = 16 - (*length % 16);

    // Jeśli dane są już wyrównane, nie wykonujemy żadnej operacji
    if (padding == 16) {
        return;
    }

    // Wypełniamy wyrównaną część zerami
    for (uint32_t i = 0; i < padding; i++) {
        data[*length + i] = 0xFF;
    }

    // Aktualizujemy długość
    *length += padding;
}



