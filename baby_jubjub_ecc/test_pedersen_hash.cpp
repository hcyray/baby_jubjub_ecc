
#include <iostream>
#include "identity_proof.hpp"
#include "pedersen_hash.hpp"
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
using namespace std;

int main () {
    typedef libff::Fr<libff::bn128_pp> FieldT;
    libff::bn128_pp::init_public_params();
    protoboard<FieldT> pb;
    std::shared_ptr<out_pedersen_hash<FieldT>> jubjub_pedersen_hash;




    //pb.set_input_sizes(2);

    FieldT commitment_x = FieldT("0");
    FieldT commitment_y = FieldT("1");
    FieldT m = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    FieldT r = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");
    jubjub_pedersen_hash.reset(new out_pedersen_hash<FieldT> (pb,  "Pedersen Hash"));
    jubjub_pedersen_hash->generate_r1cs_constraints();
    jubjub_pedersen_hash->generate_r1cs_witness(commitment_x, commitment_y, m, r);
    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!" << std::endl;
    } else {
        cout << "True" << endl;
    }
    /*
    r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    r1cs_ppzksnark_keypair<libff::bn128_pp> keypair = r1cs_ppzksnark_generator<libff::bn128_pp>(constraint_system);
    r1cs_ppzksnark_proof<libff::bn128_pp> proof = r1cs_ppzksnark_prover<libff::bn128_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool result = r1cs_ppzksnark_verifier_strong_IC<libff::bn128_pp>(keypair.vk, pb.primary_input(), proof);

    cout << "verification result:" << result << endl;
    cout << "actual commit value x :" << pb.val(jubjub_pedersen_hash->get_res_x()) << endl;
    cout << "actual commit value y :" << pb.val(jubjub_pedersen_hash->get_res_y()) << endl;

    std::stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();

    cout << "proof size :" << proof_str.size() << endl;

    cout <<  pb.num_variables() << endl;
    cout  <<"primary input size:" <<constraint_system.primary_input_size << endl;
    cout <<  pb.primary_input() << endl;
*/
    return 0;
}