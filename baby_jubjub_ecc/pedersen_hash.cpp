//
// Created by hcy_ray on 10/23/19.


#include "libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp" //hold key
#include <gmp.h>

using namespace libff;
using namespace libsnark;

template<typename FieldT>
pedersen_hash<FieldT>:: pedersen_hash(protoboard<FieldT> &pb,
        const pb_variable<FieldT> &left_x, const pb_variable<FieldT> &left_y,
        const pb_variable<FieldT> &right_x, const pb_variable<FieldT> &right_y
        ):
        gadget<FieldT>(pb, " pedersen_hash") , left_x(left_x), left_y(left_y), right_x(right_x), right_y(right_y)
{
    m.allocate(pb, 253,  FMT("annotation_prefix", " scaler to multiply by"));
    r.allocate(pb, 253,  FMT("annotation_prefix", " scaler to multiply by"));
    m_var.allocate(pb, "m_var");
    r_var.allocate(pb, "r_var");
    hash_pointAddition.reset( new pointAddition <FieldT> (pb, FieldT("168700"), FieldT("168696"), left_x, left_y , right_x , right_y, m_var, r_var , "rhs addition"));
    commit.reset(new pedersen_commitment<FieldT>(pb, FieldT("0"), FieldT("0"), m, r));
}



template<typename FieldT>
void  pedersen_hash<FieldT>::generate_r1cs_constraints()
{
    hash_pointAddition -> generate_r1cs_constraints();
    commit -> generate_r1cs_constraints(false);
}


template<typename FieldT>
void  pedersen_hash<FieldT>::generate_r1cs_witness()
{
    hash_pointAddition -> generate_r1cs_witness();
    FieldT temp_m = this->pb.val(m_var);
    FieldT temp_r = this->pb.val(r_var);

    std::stringstream comm_data_m, comm_data_r;
    comm_data_m << temp_m;
    std::string comm_str_m = comm_data_m.str();

    comm_data_r << temp_r;
    std::string comm_str_r = comm_data_r.str();


    mpz_t m_mpz, r_mpz;
    mpz_init(m_mpz);
    mpz_init(r_mpz);
    mpz_set_str(m_mpz,comm_str_m.c_str(), 10);
    mpz_set_str(r_mpz,comm_str_r.c_str(), 10);


    unsigned long int rm_mpz, rr_mpz;
    int i = 252;
    bool flagm = true;
    bool flagr = true;
    while(i >= 0) {
        if (flagm){
            rm_mpz = mpz_tdiv_q_ui(m_mpz, m_mpz, 2);
            if (rm_mpz == 0){
                this -> pb.val(m[i]) = FieldT::zero();
            } else {
                this -> pb.val(m[i]) = FieldT::one();
            }
        } else {
            this -> pb.val(m[i]) = FieldT::zero();
        }

        if (mpz_cmp_ui(m_mpz, 0) == 0) {
            flagm = false;
        }
        if (flagr){
            rr_mpz = mpz_tdiv_q_ui(r_mpz, r_mpz, 2);
            if (rr_mpz == 0){
                this -> pb.val(r[i]) = FieldT::zero();
            } else {
                this -> pb.val(r[i]) = FieldT::one();
            }
        } else {
            this -> pb.val(r[i]) = FieldT::zero();
        }

        if (mpz_cmp_ui(r_mpz, 0) == 0) {
            flagr = false;
        }
        i--;
    }
    commit -> generate_r1cs_witness();
}
template<typename FieldT>
pb_variable<FieldT>  pedersen_hash<FieldT>::get_res_x(){
    return this->commit->get_res_x();

}
template<typename FieldT>
pb_variable<FieldT>  pedersen_hash<FieldT>::get_res_y(){
    return this->commit->get_res_y();

}

