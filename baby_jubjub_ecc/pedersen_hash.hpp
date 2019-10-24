//
// Created by hcy_ray on 10/23/19.
//

#include <cassert>
#include <memory>
#include "pedersen_commitment.hpp"
#include <libsnark/gadgetlib1/gadget.hpp>




using namespace libsnark;

template<typename FieldT>
class  pedersen_hash : public gadget<FieldT> {

private:
    pb_variable_array<FieldT> m;
    pb_variable_array<FieldT> r;
    pb_variable<FieldT> left_x;
    pb_variable<FieldT> left_y;
    pb_variable<FieldT> right_x;
    pb_variable<FieldT> right_y;
    pb_variable<FieldT> m_var;
    pb_variable<FieldT> r_var;
    std::shared_ptr<pedersen_commitment<FieldT>> commit;
    std::shared_ptr<pointAddition<FieldT>> hash_pointAddition;
    //pb_variable<FieldT> res_x;
    //pb_variable<FieldT> res_y;
public:


    pedersen_hash(protoboard<FieldT> &pb,
            //const pb_linear_combination_array<FieldT> &bits,
                  const pb_variable<FieldT> &left_x,
                  const pb_variable<FieldT> &left_y,
                  const pb_variable<FieldT> &right_x,
                  const pb_variable<FieldT> &right_y
    );

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    pb_variable<FieldT> get_res_x();
    pb_variable<FieldT> get_res_y();
};





#include "pedersen_hash.cpp"