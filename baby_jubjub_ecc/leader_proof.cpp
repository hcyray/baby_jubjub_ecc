//
// Created by hcy_ray on 10/29/19.
//


#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
using namespace libff;

using namespace libsnark;


template<typename FieldT>
leader_proof::leader_proof(protoboard <FieldT> &pb, const std::string &annotation_prefix) {
  sn_x.allocate(pb, FMT(annotation_prefix), "sn x");
  sn_y.allocate(pb, FMT(annotation_prefix), "sn y");
  m.allocate(pb, 253, FMT(annotation_prefix, "m"));
  r.allocate(pb, 253, FMT(annotation_prefix, "r"));
  n = 63;
  less.allocate(pb, FMT(annotation_prefix, "less"));
  less_or_eq.allocate(pb, FMT(annotation_prefix, "less_or_eq"));
  commit.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, "Pedersen Commitment")));
  randomCommit.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, "random number")));
  repRN.allocate(pb, FMT(annotation_prefix, "rep times random"));
  rangeProof.reset(new comparison_gadget<FieldT>(pb, n, T, repRN, less, less_or_equal, FMT(this->annotation_prefix, "cmp"));
  
}

template<typename FieldT>
void leader_proof<FieldT>::generate_r1cs_constraints(){
  commit->generate_r1cs_constraints();
  randomCommit->generate_r1cs_constraints();
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>( x, ,  repRN),
                           FMT(annotation_prefix, "repRN"));
  rangeProof->generate_r1cs_constraints();
}

template<typename FieldT>
void leader_proof<FieldT>::generate_r1cs_witness(ulong &in_m, ulong &in_r, 
                           pb_variable<FieldT> &commit_x, pb_vairalbe<FieldT> &commit_y){
  pb.val(sn_x) = pb.val(commit_x);
  pb.val(sn_y) = pb.val(commit_y);
  m.fill_with_bits_of_ulong(pb, in_m);
  r.fill_with_bits_of_ulong(pb, in_r);
  pb.val(x) = FieldT(in_m);
  pb.val(T) = FieldT("99999999999999999");
  commit->generate_r1cs_witness(sn_x, sn_y, in_m, in_r);
  randomCommit->generate_r1cs_witness();
  rangeProof->generate_r1cs_witness();
}
