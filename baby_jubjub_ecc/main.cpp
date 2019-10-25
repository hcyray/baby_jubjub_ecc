#include <iostream>
//#include "stubs.hpp"
#include "merkle_tree.hpp"
#include "pedersen_hash.hpp"
using namespace std;
using namespace libsnark;
int main () {

    libff::alt_bn128_pp::init_public_params();
    ProtoboardT pb;

    VariableArrayT address_bits;
    address_bits.allocate(pb, 2, "address_bits");
    pb.val(address_bits[0]) = 1;
    pb.val(address_bits[1]) = 0;

    VariableArrayT path;
    path.allocate(pb, 4, "path");
    pb.val(path[0]) = FieldT("0");
    pb.val(path[1]) = FieldT("1");
    pb.val(path[2]) = FieldT("1929466062442023477725010485056302090701919258803982427606541616916556652447");
    pb.val(path[3]) = FieldT("7587806336211761577740666413129022186019067561180819251434541781727079091517");

    VariableT leaf_x, leaf_y;
    leaf_x.allocate(pb, "leaf_x");
    leaf_y.allocate(pb, "leaf_x");
    pb.val(leaf_x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    pb.val(leaf_y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    VariableT expected_root_x, expected_root_y;
    expected_root_x.allocate(pb, "expected_root_x");
    expected_root_y.allocate(pb, "expected_root_y");
    pb.val(expected_root_x) = FieldT("817611879644043864748861442264909525985726192806194518178817613558921011044");
    pb.val(expected_root_y) = FieldT("8720015449337429074460479945549205057563695483288443522338143163742912966558");


    size_t tree_depth = 2;
    merkle_path_authenticator auth(
            pb, tree_depth, address_bits, leaf_x, leaf_y,
            expected_root_x, expected_root_y, path,
            "authenticator");


    auth.generate_r1cs_constraints();
    auth.generate_r1cs_witness();
    if(  !auth.is_valid() ) {
        cout << "No!" << endl;
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
}

