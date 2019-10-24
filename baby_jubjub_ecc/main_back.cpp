#include <iostream>
//#include "stubs.hpp"
#include "merkle_tree.hpp"
#include "pedersen_hash.hpp"
using namespace std;

int main () {
    auto left = FieldT("3703141493535563179657531719960160174296085208671919316200479060314459804651");
    auto right = FieldT("134551314051432487569247388144051420116740427803855572138106146683954151557");
    auto root = FieldT("3075442268020138823380831368198734873612490112867968717790651410945045657947");
    auto is_right = 1;

    ProtoboardT pb;

    VariableArrayT address_bits;
    address_bits.allocate(pb, 1, "address_bits");
    pb.val(address_bits[0]) = is_right;

    VariableArrayT path;
    path.allocate(pb, 1, "path");
    pb.val(path[0]) = left;

    VariableT leaf;
    leaf.allocate(pb, "leaf");
    pb.val(leaf) = right;

    VariableT expected_root;
    expected_root.allocate(pb, "expected_root");
    pb.val(expected_root) = root;

    size_t tree_depth = 1;
    merkle_path_authenticator<pedersen_hash<libff::alt_bn128_pp>> auth(
            pb, tree_depth, address_bits,
            merkle_tree_IVs(pb),
            leaf, expected_root, path,
            "authenticator");

    auth.generate_r1cs_witness();
    auth.generate_r1cs_constraints();

    if( ! auth.is_valid() ) {
        std::cerr << "Not valid!" << std::endl;
        std::cerr << "Expected "; pb.val(expected_root).print();
        std::cerr << "Actual "; pb.val(auth.result()).print();
        return false;
    }

    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!" << std::endl;
    } else {
        cout << "True" << endl;
    }
}

