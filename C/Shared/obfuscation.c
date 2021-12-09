

void decodeSimpleXor( char *data, int dataLen, char* key, int keyLen){
    for(int i = 0; i < dataLen; i++){
        printf("%c", data);
        data[i] =  data[i] ^ key[keyLen % i];
        printf("%c", data);
    }
    data = "\x00";  //terminating string
}
