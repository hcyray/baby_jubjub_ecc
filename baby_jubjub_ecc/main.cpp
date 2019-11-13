#include "prc.h"
#include <iostream>
using namespace std;
int main(){
    unsigned char proof1 [312];
    unsigned char proof2 [312];
    int d = 3;
    bool a[d];
    char* b[d];
    a[0] = true;
    a[1] =false;
    a[2] =true;
    b[0] = "123";
    b[1] = "123";
    b[2] = "1234";
    prc_test(proof1, proof2, a, b, d);
    for (int i = 0; i < d; i++){
        cout<< proof1[i] << endl;
    }
    for (int i = 0; i < d; i++){
        cout<< proof2[i] << endl;
    }
    return 0;
}