//
// Created by hcy_ray on 10/11/19.
//




using namespace libsnark;


template<typename FieldT>
pow_proof<FieldT>::pow_proof(protoboard<FieldT> &pb, const std::string &annotation_prefix):
        gadget<FieldT>(pb, "mul_cmp") {

    rep_x.allocate(pb, FMT(annotation_prefix, "rep x"));
    rep_y.allocate(pb, FMT(annotation_prefix, "rep y"));
    block.allocate(pb, FMT(annotation_prefix,  "block"));
    pb.set_input_sizes(verifying_field_element_size());
    rep.allocate(pb, FMT(annotation_prefix, "rep"));
    target.allocate(pb, FMT(annotation_prefix, " hash target"));
    rep_m.allocate(pb,253, FMT(annotation_prefix, "rep m"));
    rep_r.allocate(pb,253, FMT(annotation_prefix, "rep r"));
    nonce.allocate(pb, FMT(annotation_prefix,  "nonce"));
    n_cmp = 20; // number of comparision
    rep_T.allocate(pb, n_cmp, FMT(this->annotation_prefix, " T for rep"));
    diff_T.allocate(pb,n_cmp, FMT(this->annotation_prefix, " T for diff"));
    for (int i = 0; i < n_cmp; i ++) {
        this -> pb.val(rep_T[i]) = FieldT((i+1)*10);
        this -> pb.val(diff_T[i]) = FieldT((i+1)*10);
    }

    rep_relation.allocate(pb, n_cmp * 2, FMT(this->annotation_prefix, " rep less and less_or_eq"));
    diff_relation.allocate(pb, n_cmp * 2, FMT(this->annotation_prefix, " diff less and less_or_eq"));
    repCommit.reset(new pedersen_commitment<FieldT>(pb, FMT(annotation_prefix, "Rep Pedersen Commitment")));
    target_hash.reset(new pedersen_hash<FieldT>(pb, FMT(annotation_prefix, " pedersen hash"), false));

    for (int i = 0; i < n_cmp; i++){
        cmp_rep.emplace_back(new comparison_gadget<FieldT>(pb, 253, rep, rep_T[i], rep_relation[i*2], rep_relation[i*2+1],
                                                            FMT(this->annotation_prefix, "cmp_rep"+std::to_string(i))));
        cmp_diff.emplace_back(new comparison_gadget<FieldT>(pb, 253, target, diff_T[i], diff_relation[i*2], diff_relation[i*2+1],
                                                            FMT(this->annotation_prefix, "cmp_diff"+std::to_string(i))));
    }
}

template<typename FieldT>
void  pow_proof<FieldT>::generate_r1cs_constraints()
{
    repCommit->generate_r1cs_constraints(true);
    target_hash->generate_r1cs_constraints();
    for (int i = 0; i < n_cmp; i++) {
        cmp_rep[i] -> generate_r1cs_constraints();
        cmp_diff[i] -> generate_r1cs_constraints();
    }
    for (int i = 0; i < n_cmp; i++) {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(rep_relation[i*2+1], FieldT::one(), diff_relation[i*2+1]),
                                     FMT(this-> annotation_prefix, " check comparison [%zu]", i));
    }

}


template<typename FieldT>
void  pow_proof<FieldT>::generate_r1cs_witness(const FieldT &in_rep_m, const FieldT &in_rep_r,
                                               const FieldT &rep_commit_x, const FieldT &rep_commit_y,
                                               const FieldT &in_nonce, const FieldT &in_block)
{
    this -> pb.val(rep_x) = rep_commit_x;
    this -> pb.val(rep_y) = rep_commit_y;
    this -> pb.val(rep) = FieldT(20);
    this -> pb.val(nonce) = in_nonce;
    this -> pb.val(block) = in_block;
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this -> pb, rep_m, in_rep_m);
    fill_with_bits_of_field_element_baby_jubjub<FieldT>(this -> pb, rep_r, in_rep_r);
    repCommit->generate_r1cs_witness(rep_x, rep_y, rep_m, rep_r);
    target_hash->generate_r1cs_witness(rep_x, rep_y, block, nonce);
    this->pb.val(target) = FieldT(20);
    //this->pb.val(target) = this->pb.val(target_hash->get_res_x());
    for (int i = 0; i < n_cmp; i++){
        cmp_rep[i] -> generate_r1cs_witness();
        cmp_diff[i]-> generate_r1cs_witness();
    }
}