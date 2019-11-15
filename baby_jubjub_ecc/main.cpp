#include "prc.h"
#include <iostream>
using namespace std;
int main(){
    unsigned char proof1 [312];
    int d = 3;
    char* b[d];
    b[0] = "123";
    b[1] = "123";
    b[2] = "1234";
    prc_test(proof1,  b, d);
    for (int i = 0; i < d; i++){
        cout<< proof1[i] << endl;
    }
    return 0;
}