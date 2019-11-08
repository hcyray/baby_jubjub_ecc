#include <iostream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include "identity_proof.hpp"
#include "pedersen_hash.hpp"
using namespace std;
using namespace libsnark;
int main () {

    libff::alt_bn128_pp::init_public_params();
    ProtoboardT pb;

    vector<FieldT> address_bits;
    address_bits.push_back(FieldT("1"));
    address_bits.push_back(FieldT("0"));


    vector<FieldT> path;
    path.push_back((FieldT("0")));
    path.push_back((FieldT("1")));
    path.push_back((FieldT("1929466062442023477725010485056302090701919258803982427606541616916556652447")));
    path.push_back((FieldT("7587806336211761577740666413129022186019067561180819251434541781727079091517")));


    FieldT leaf_x, leaf_y;

    leaf_x = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    leaf_y = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    FieldT expected_root_x, expected_root_y;

    expected_root_x = FieldT("817611879644043864748861442264909525985726192806194518178817613558921011044");
    expected_root_y = FieldT("8720015449337429074460479945549205057563695483288443522338143163742912966558");


    size_t tree_depth = 2;
    merkle_path_authenticator auth(
            pb, tree_depth,
            "authenticator");


    auth.generate_r1cs_constraints();
    auth.generate_r1cs_witness(address_bits, leaf_x, leaf_y,
                               expected_root_x, expected_root_y, path);
    if(  auth.is_valid() ) {
        cout << "Yes!" << endl;
        cout << "Acutal X:" << pb.val(auth.result_x()) << endl;
        cout << "Acutal Y:" << pb.val(auth.result_y()) << endl;
        cout << "Expect X:" << pb.val(auth.m_expected_root_x) << endl;
        cout << "Expect Y:" << pb.val(auth.m_expected_root_y) << endl;
    }

    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!" << std::endl;
    } else {
        cout << "True" << endl;
    }
    r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair = r1cs_ppzksnark_generator<libff::alt_bn128_pp>(constraint_system);
    r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof = r1cs_ppzksnark_prover<libff::alt_bn128_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool result = r1cs_ppzksnark_verifier_strong_IC<libff::alt_bn128_pp>(keypair.vk, pb.primary_input(), proof);
    cout << "verification result:" << result <<endl;
    std::stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();

    cout << "proof size :" << proof_str.size() << endl;
    cout << "primary input:" <<pb.primary_input() << endl;

    cout  << "primary input size: "<<constraint_system.primary_input_size << endl;
}

