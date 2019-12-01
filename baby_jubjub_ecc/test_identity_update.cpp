#include <iostream>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include "identity_proof.hpp"
#include "pedersen_hash.hpp"
using namespace std;
using namespace libsnark;
int main () {

    libff::bn128_pp::init_public_params();
    ProtoboardT pb;

    vector<FieldT> id_address_bits, rep_address_bits;
    vector<FieldT> id_path, rep_path;
    FieldT id_leaf_x, id_leaf_y, rep_leaf_x, rep_leaf_y;
    FieldT id_expected_root_x, id_expected_root_y, rep_expected_root_x, rep_expected_root_y;
    FieldT id_m, id_r, id_x, id_y, rep_m, rep_r, rep_x, rep_y;

    id_address_bits.push_back(FieldT("1"));
    id_address_bits.push_back(FieldT("0"));

    rep_address_bits.push_back(FieldT("1"));
    rep_address_bits.push_back(FieldT("0"));

    id_path.push_back((FieldT("0")));
    id_path.push_back((FieldT("1")));
    id_path.push_back((FieldT("1929466062442023477725010485056302090701919258803982427606541616916556652447")));
    id_path.push_back((FieldT("7587806336211761577740666413129022186019067561180819251434541781727079091517")));

    rep_path.push_back((FieldT("0")));
    rep_path.push_back((FieldT("1")));
    rep_path.push_back((FieldT("1929466062442023477725010485056302090701919258803982427606541616916556652447")));
    rep_path.push_back((FieldT("7587806336211761577740666413129022186019067561180819251434541781727079091517")));


    id_leaf_x = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    id_leaf_y = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    rep_leaf_x = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    rep_leaf_y = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");


    id_expected_root_x = FieldT("817611879644043864748861442264909525985726192806194518178817613558921011044");
    id_expected_root_y = FieldT("8720015449337429074460479945549205057563695483288443522338143163742912966558");
    rep_expected_root_x = FieldT("817611879644043864748861442264909525985726192806194518178817613558921011044");
    rep_expected_root_y = FieldT("8720015449337429074460479945549205057563695483288443522338143163742912966558");

    id_m = FieldT("2");
    id_r = FieldT("2");
    id_x = FieldT("18517123153863469553573384572371536953407444696640934598826194274645946323334");
    id_y = FieldT("16366639365004517936716040800897479058579589069997927276858356063876961184474");
    rep_m = FieldT("2");
    rep_r = FieldT("2");
    rep_x = FieldT("18517123153863469553573384572371536953407444696640934598826194274645946323334");
    rep_y = FieldT("16366639365004517936716040800897479058579589069997927276858356063876961184474");


    size_t tree_depth = 2;
    identity_update_proof auth(
            pb, tree_depth,
            " id update");


    auth.generate_r1cs_constraints();
    auth.generate_r1cs_witness(id_address_bits, id_leaf_x, id_leaf_y,
                               id_expected_root_x, id_expected_root_y, id_path,
                               rep_address_bits, rep_leaf_x, rep_leaf_y,
                               rep_expected_root_x, rep_expected_root_y, rep_path,
                               id_m, id_r, id_x, id_y, rep_m, rep_r, rep_x, rep_y);


    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!" << std::endl;
    } else {
        cout << "True" << endl;
    }
    r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    r1cs_ppzksnark_keypair<libff::bn128_pp> keypair = r1cs_ppzksnark_generator<libff::bn128_pp>(constraint_system);
    r1cs_ppzksnark_proof<libff::bn128_pp> proof = r1cs_ppzksnark_prover<libff::bn128_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
/*
    bool result = r1cs_ppzksnark_verifier_strong_IC<libff::bn128_pp>(keypair.vk, pb.primary_input(), proof);
    cout << "verification result:" << result <<endl;
    std::stringstream proof_data;
    proof_data << proof;
    auto proof_str = proof_data.str();

    cout << "proof size :" << proof_str.size() << endl;
    cout << "primary input:" <<pb.primary_input() << endl;

    cout  << "primary input size: "<<constraint_system.primary_input_size << endl;*/
}

