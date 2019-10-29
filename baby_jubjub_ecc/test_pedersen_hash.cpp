
#include <iostream>
#include "merkle_tree.hpp"
#include "pedersen_hash.hpp"
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
using namespace std;

int main () {
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;
    libff::alt_bn128_pp::init_public_params();
    protoboard<FieldT> pb;
    std::shared_ptr<pedersen_hash<FieldT>> jubjub_pedersen_hash;


    pb_variable<FieldT> commitment_x;
    pb_variable<FieldT> commitment_y;
    pb_variable<FieldT> m;
    pb_variable<FieldT> r;
    commitment_x.allocate(pb, "r_x");
    commitment_y.allocate(pb, "r_y");
    m.allocate(pb, FMT("annotation_prefix", " scaler to multiply by"));
    r.allocate(pb, FMT("annotation_prefix", " scaler to multiply by"));
    //pb.set_input_sizes(2);

    pb.val(commitment_x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(commitment_y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");
    pb.val(m) = FieldT("1");
    pb.val(r) = FieldT("1");
    jubjub_pedersen_hash.reset(new pedersen_hash<FieldT> (pb,  "Pedersen Hash"));
    jubjub_pedersen_hash->generate_r1cs_constraints();
    jubjub_pedersen_hash->generate_r1cs_witness(commitment_x, commitment_y, m, r);

    r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = r1cs_ppzksnark_generator<libff::alt_bn128_pp>(constraint_system);
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool result = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(keypair.vk, pb.primary_input(), proof);

    cout << "verification result:" << result << endl;
    cout << "actual commit value x :" << pb.val(jubjub_pedersen_hash->get_res_x()) << endl;
    cout << "actual commit value y :" << pb.val(jubjub_pedersen_hash->get_res_y()) << endl;

    std::stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();

    cout << "proof size :" << proof_str.size() << endl;
    return 0;
}