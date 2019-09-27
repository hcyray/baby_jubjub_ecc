/*    
    copyright 2018 to the baby_jubjub_ecc Authors

    This file is part of baby_jubjub_ecc.

    baby_jubjub_ecc is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    baby_jubjub_ecc is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with baby_jubjub_ecc.  If not, see <https://www.gnu.org/licenses/>.
*/


#include <prc.h>
#include <iostream>
using namespace std;


int main () {
    //libff::alt_bn128_pp::init_public_params();
    prc_initialize();
    cout << "intialize sucess--------------------------------------" << endl;
    unsigned char proof [312];
    char *comm_x;
    char *comm_y;
    prc_prove_hpc(proof, 1, 1, comm_x, comm_y);
    cout << "prove sucess--------------------------------------" << endl;
    cout << comm_x << endl;
    cout << comm_y << endl;
    bool verify_result = prc_verify_hpc_with_commit(proof, comm_x, comm_y);
    cout << "verification result : " << verify_result << endl;
    cout << "verify sucess--------------------------------------" << endl;
    //test_mpz();

    return 0;
}

