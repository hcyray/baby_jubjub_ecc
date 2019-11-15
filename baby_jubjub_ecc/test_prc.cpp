#include <fstream>
#include <prc.h>
#include <iostream>
#include <time.h>
using namespace std;
clock_t t;
double time_used;
int n = 50;
ulong BinaryToDec(bool x[], int d) {
    ulong res = 0;
    for(int i = 0; i < d; i++){
        if (x[i]) {
            res = res << 1 + 1;
        } else {
            res = res << 1;
        }
    }
}
void test_hpc(){
    cout <<"Test pedersen commitment" <<endl;
    t = clock();
    prc_paramgen_hpc();
    t = clock() - t;
    time_used = t/CLOCKS_PER_SEC;
    cout << "initialize success--------------------------------------" << endl;
    cout << "initialize time used: " << time_used<< endl;


    unsigned char proof [312];
    char *comm_x = "18517123153863469553573384572371536953407444696640934598826194274645946323334";
    char *comm_y = "16366639365004517936716040800897479058579589069997927276858356063876961184474";
    t = clock();
    prc_prove_hpc(proof, 2, 2, comm_x, comm_y);
    t = clock() - t;
    time_used = t/CLOCKS_PER_SEC;
    cout << "prove success--------------------------------------" << endl;
    cout << "prove time used: " << time_used<< endl;

    t = clock();
    bool verify_result = prc_verify_hpc(proof, comm_x, comm_y);
    t = clock() - t;
    time_used = t/CLOCKS_PER_SEC;
    cout << "verification result : " << verify_result << endl;
    cout << "verification time used: " << time_used<< endl;
    cout << "Finish--------------------------------------" << endl;
}

void test_lp(){
    cout <<"Test leader proof" <<endl;
    char* block_hash = "1234";
    char* T = "12845949072827470624709637419912138308739243446882777103948483823386985213512";
    char* sn_x = "18517123153863469553573384572371536953407444696640934598826194274645946323334";
    char* sn_y = "16366639365004517936716040800897479058579589069997927276858356063876961184474";
    char* rep_x = "18517123153863469553573384572371536953407444696640934598826194274645946323334";
    char* rep_y = "16366639365004517936716040800897479058579589069997927276858356063876961184474";
    int sl = 1;

    t = clock();
    prc_paramgen_lp();
    t = clock() - t;
    time_used = t/CLOCKS_PER_SEC;
    cout << "initialize success--------------------------------------" << endl;
    cout << "initialize time used: " << time_used<< endl;

    unsigned char proof [312];
    t = clock();
    prc_prove_lp(proof, 2, 2, sn_x, sn_y,T, 2,2, rep_x, rep_y,block_hash, sl);
    t = clock() - t;
    time_used = t/CLOCKS_PER_SEC;
    cout << "prove success--------------------------------------" << endl;
    cout << "prove time used: " << time_used<< endl;

    t = clock();
    bool verify_result = prc_verify_lp(proof, sn_x, sn_y,T, rep_x, rep_y,block_hash, sl);
    t = clock() - t;
    time_used = t/CLOCKS_PER_SEC;
    cout << "verification result : " << verify_result << endl;
    cout << "verification time used: " << time_used<< endl;
    cout << "Finish--------------------------------------" << endl;
}

void test_iup(){
    cout <<"Test identity update proof" <<endl;
    ifstream infile;
    infile.open("merkle.txt");
    if(!infile) {
        cerr << "Unable to open file txt";
        exit(1);
    }
    int depth;
    infile >> depth;
    bool id_address_bits[depth];
    bool rep_address_bits[depth];
    ulong id_address;
    ulong rep_address;
    char* id_path[depth*2];
    char* rep_path[depth*2];
    char* id_leaf_x;
    char* id_leaf_y;
    char* id_root_x;
    char* id_root_y;
    char* rep_leaf_x;
    char* rep_leaf_y;
    char* rep_root_x;
    char* rep_root_y;

    for(int i = 0; i < depth; i++){
        infile >> id_address_bits[i];
        rep_address_bits[i] = id_address_bits[i];

    }
    string id_path_str[depth*2];
    string rep_path_str[depth*2];
    string id_leaf_x_str, id_leaf_y_str, id_root_x_str, id_root_y_str;
    string rep_leaf_x_str, rep_leaf_y_str, rep_root_x_str, rep_root_y_str;
    for(int i = 0; i < depth*2; i++){
        infile >> id_path_str[i];
        rep_path_str[i] = id_path_str[i];
        id_path[i] = &id_path_str[i][0];
        rep_path[i] = &rep_path_str[i][0];
        //strcpy(id_path[i], temp);
        //rep_path[i] = (char*) malloc( strlen( temp) + 1);
        //strcpy(rep_path[i], temp);
    }

    infile >> id_leaf_x_str;
    rep_leaf_x_str = id_leaf_x_str;
    id_leaf_x = &id_leaf_x_str[0];
    rep_leaf_x = &rep_leaf_x_str[0];
    infile >> id_leaf_y_str;
    rep_leaf_y_str = id_leaf_y_str;
    id_leaf_y = &id_leaf_y_str[0];
    rep_leaf_y = &rep_leaf_y_str[0];
    infile >> id_root_x_str;
    rep_root_x_str = id_root_x_str;
    id_root_x = &id_root_x_str[0];
    rep_root_x = &rep_root_x_str[0];
    infile >> id_root_y_str;
    rep_root_y_str = id_root_y_str;
    id_root_y = &id_root_y_str[0];
    rep_root_y = &rep_root_y_str[0];
    infile.close();

    ulong id_m = 2, id_r = 2;
    ulong rep_m = 2, rep_r = 2;
    char* id_x = "18517123153863469553573384572371536953407444696640934598826194274645946323334";
    char* id_y = "16366639365004517936716040800897479058579589069997927276858356063876961184474";
    char* rep_x = "18517123153863469553573384572371536953407444696640934598826194274645946323334";
    char* rep_y = "16366639365004517936716040800897479058579589069997927276858356063876961184474";
    id_address = BinaryToDec(id_address_bits, depth);
    rep_address = BinaryToDec(rep_address_bits, depth);

    t = clock();
    prc_paramgen_iup(depth);
    t = clock() - t;
    time_used = t/CLOCKS_PER_SEC;
    cout << "initialize success--------------------------------------" << endl;
    cout << "initialize time used: " << time_used<< endl;

    unsigned char proof [312];
    t = clock();
    prc_prove_iup(proof, depth, id_address, id_leaf_x, id_leaf_y, id_root_x, id_root_y, id_path,
            rep_address, rep_leaf_x, rep_leaf_y, rep_root_x, rep_root_y, rep_path,
            id_m, id_r, id_x, id_y, rep_m, rep_r, rep_x, rep_y);
    t = clock() - t;
    time_used = t/CLOCKS_PER_SEC;
    cout << "prove success--------------------------------------" << endl;
    cout << "prove time used: " << time_used<< endl;

    t = clock();
    bool verify_result = prc_verify_iup(proof, id_root_x, id_root_y,
            rep_root_x, rep_root_y, id_x, id_y, rep_x, rep_y);
    t = clock() - t;
    time_used = n*t/CLOCKS_PER_SEC;
    cout << "verification result : " << verify_result << endl;
    cout << "verification time used: " << time_used<< endl;
    cout << "Finish--------------------------------------" << endl;
}

int main () {
    prc_initialize();
    test_hpc();
    //test_lp();
    //test_iup();
}