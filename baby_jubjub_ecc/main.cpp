
#include <prc.h>
#include <iostream>
using namespace std;

void test_hpc(){
    cout <<"Test pedersen commitment" <<endl;
    int id = 1;
    prc_paramgen_hpc(id);
    cout << "intialize sucess--------------------------------------" << endl;
    unsigned char proof [312];
    char *comm_x = "18517123153863469553573384572371536953407444696640934598826194274645946323334";
    char *comm_y = "16366639365004517936716040800897479058579589069997927276858356063876961184474";
    prc_prove_hpc(proof, 2, 2, comm_x, comm_y,id);
    cout << "prove sucess--------------------------------------" << endl;
    cout << comm_x << endl;
    cout << comm_y << endl;
    bool verify_result = prc_verify_hpc(proof, comm_x, comm_y,id);
    cout << "verification result : " << verify_result << endl;
    cout << "Finish--------------------------------------" << endl;
}

void test_lp(){
    cout <<"Test leader proof" <<endl;
    int id = 1;
    char* block_hash = "1234";
    char* T = "12845949072827470624709637419912138308739243446882777103948483823386985213512";
    char* sn_x = "18517123153863469553573384572371536953407444696640934598826194274645946323334";
    char* sn_y = "16366639365004517936716040800897479058579589069997927276858356063876961184474";
    char* rep_x = "18517123153863469553573384572371536953407444696640934598826194274645946323334";
    char* rep_y = "16366639365004517936716040800897479058579589069997927276858356063876961184474";
    int sl = 1;
    prc_paramgen_lp(id);
    cout << "intialize sucess--------------------------------------" << endl;
    unsigned char proof [312];
    prc_prove_lp(proof, 2, 2, sn_x, sn_y,T, 2,2, rep_x, rep_y,block_hash, sl,id);
    cout << "prove sucess--------------------------------------" << endl;
    bool verify_result = prc_verify_lp(proof, sn_x, sn_y,T, rep_x, rep_y,block_hash, sl,id);
    cout << "verification result : " << verify_result << endl;
    cout << "Finish--------------------------------------" << endl;
};
int main () {
    prc_initialize();
    //test_hpc();
    test_lp();
}