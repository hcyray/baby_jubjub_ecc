// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "baby_jubjub_ecc.hpp"
#include "utils.hpp"




merkle_path_selector::merkle_path_selector(
    ProtoboardT &in_pb,
    const VariableT& in_input_x,
    const VariableT& in_input_y,
    const VariableT& in_pathvar_x,
    const VariableT& in_pathvar_y,
    const VariableT& in_is_right,
    const std::string &in_annotation_prefix
) :
    GadgetT(in_pb, in_annotation_prefix),
    m_input_x(in_input_x),
    m_input_y(in_input_y),
    m_pathvar_x(in_pathvar_x),
    m_pathvar_y(in_pathvar_y),
    m_is_right(in_is_right)
{
    m_left_a_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_a_x"));
    m_left_b_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_b_x"));
    m_left_x.allocate(in_pb, FMT(this->annotation_prefix, ".left_x"));

    m_left_a_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_a_y"));
    m_left_b_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_b_y"));
    m_left_y.allocate(in_pb, FMT(this->annotation_prefix, ".left_y"));

    m_right_a_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_a_x"));
    m_right_b_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_b_x"));
    m_right_x.allocate(in_pb, FMT(this->annotation_prefix, ".right_x"));

    m_right_a_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_a_y"));
    m_right_b_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_b_y"));
    m_right_y.allocate(in_pb, FMT(this->annotation_prefix, ".right_y"));
}

void merkle_path_selector::generate_r1cs_constraints()
{
    // left x commitment
    this->pb.add_r1cs_constraint(
        ConstraintT(1 - m_is_right, m_input_x, m_left_a_x),
        FMT(this->annotation_prefix, "1-is_right_x * input_x = left_a_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_pathvar_x, m_left_b_x),
        FMT(this->annotation_prefix, "is_right * pathvar_x = left_b_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_left_a_x + m_left_b_x, 1, m_left_x),
        FMT(this->annotation_prefix, "1 * left_a_x + left_b_x = left_x"));

    // left y commitment
    this->pb.add_r1cs_constraint(
            ConstraintT(1 - m_is_right, m_input_y, m_left_a_y),
            FMT(this->annotation_prefix, "1-is_right_y * input_y = left_a_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_pathvar_y, m_left_b_y),
                                 FMT(this->annotation_prefix, "is_right * pathvar_y = left_b_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_left_a_y + m_left_b_y, 1, m_left_y),
                                 FMT(this->annotation_prefix, "1 * left_a_y + left_b_y = left_y"));

    // right x commitment
    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_input_x, m_right_a_x),
        FMT(this->annotation_prefix, "is_right * input_x = right_a_x"));

    this->pb.add_r1cs_constraint(ConstraintT(1 - m_is_right, m_pathvar_x, m_right_b_x),
        FMT(this->annotation_prefix, "1-is_right * pathvar_x = right_b_x"));

    this->pb.add_r1cs_constraint(ConstraintT(m_right_a_x + m_right_b_x, 1, m_right_x),
        FMT(this->annotation_prefix, "1 * right_a_x + right_b_x = right_x"));

    // right y commitment
    this->pb.add_r1cs_constraint(ConstraintT(m_is_right, m_input_y, m_right_a_y),
                                 FMT(this->annotation_prefix, "is_right * input_y = right_a_y"));

    this->pb.add_r1cs_constraint(ConstraintT(1 - m_is_right, m_pathvar_y, m_right_b_y),
                                 FMT(this->annotation_prefix, "1-is_right * pathvar_y = right_b_y"));

    this->pb.add_r1cs_constraint(ConstraintT(m_right_a_y + m_right_b_y, 1, m_right_y),
                                 FMT(this->annotation_prefix, "1 * right_a_y + right_b_y = right_y"));


}

void merkle_path_selector::generate_r1cs_witness() const
{
    this->pb.val(m_left_a_x) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_input_x);
    this->pb.val(m_left_b_x) = this->pb.val(m_is_right) * this->pb.val(m_pathvar_x);
    this->pb.val(m_left_x) = this->pb.val(m_left_a_x) + this->pb.val(m_left_b_x);

    this->pb.val(m_left_a_y) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_input_y);
    this->pb.val(m_left_b_y) = this->pb.val(m_is_right) * this->pb.val(m_pathvar_y);
    this->pb.val(m_left_y) = this->pb.val(m_left_a_y) + this->pb.val(m_left_b_y);

    this->pb.val(m_right_a_x) = this->pb.val(m_is_right) * this->pb.val(m_input_x);
    this->pb.val(m_right_b_x) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_pathvar_x);
    this->pb.val(m_right_x) = this->pb.val(m_right_a_x) + this->pb.val(m_right_b_x);

    this->pb.val(m_right_a_y) = this->pb.val(m_is_right) * this->pb.val(m_input_y);
    this->pb.val(m_right_b_y) = (FieldT::one() - this->pb.val(m_is_right)) * this->pb.val(m_pathvar_y);
    this->pb.val(m_right_y) = this->pb.val(m_right_a_y) + this->pb.val(m_right_b_y);
}

const VariableT& merkle_path_selector::left_x() const {
    return m_left_x;
}
const VariableT& merkle_path_selector::left_y() const {
    return m_left_y;
}
const VariableT& merkle_path_selector::right_x() const {
    return m_right_x;
}
const VariableT& merkle_path_selector::right_y() const {
    return m_right_y;
}
/*
const VariableArrayT merkle_tree_IVs (ProtoboardT &in_pb)
{

    // or remove the merkle tree IVs entirely...
    auto x = make_var_array(in_pb, 29, "IVs");
    std::vector<FieldT> level_IVs = {
        FieldT("149674538925118052205057075966660054952481571156186698930522557832224430770"),
        FieldT("9670701465464311903249220692483401938888498641874948577387207195814981706974"),
        FieldT("18318710344500308168304415114839554107298291987930233567781901093928276468271"),
        FieldT("6597209388525824933845812104623007130464197923269180086306970975123437805179"),
        FieldT("21720956803147356712695575768577036859892220417043839172295094119877855004262"),
        FieldT("10330261616520855230513677034606076056972336573153777401182178891807369896722"),
        FieldT("17466547730316258748333298168566143799241073466140136663575045164199607937939"),
        FieldT("18881017304615283094648494495339883533502299318365959655029893746755475886610"),
        FieldT("21580915712563378725413940003372103925756594604076607277692074507345076595494"),
        FieldT("12316305934357579015754723412431647910012873427291630993042374701002287130550"),
        FieldT("18905410889238873726515380969411495891004493295170115920825550288019118582494"),
        FieldT("12819107342879320352602391015489840916114959026915005817918724958237245903353"),
        FieldT("8245796392944118634696709403074300923517437202166861682117022548371601758802"),
        FieldT("16953062784314687781686527153155644849196472783922227794465158787843281909585"),
        FieldT("19346880451250915556764413197424554385509847473349107460608536657852472800734"),
        FieldT("14486794857958402714787584825989957493343996287314210390323617462452254101347"),
        FieldT("11127491343750635061768291849689189917973916562037173191089384809465548650641"),
        FieldT("12217916643258751952878742936579902345100885664187835381214622522318889050675"),
        FieldT("722025110834410790007814375535296040832778338853544117497481480537806506496"),
        FieldT("15115624438829798766134408951193645901537753720219896384705782209102859383951"),
        FieldT("11495230981884427516908372448237146604382590904456048258839160861769955046544"),
        FieldT("16867999085723044773810250829569850875786210932876177117428755424200948460050"),
        FieldT("1884116508014449609846749684134533293456072152192763829918284704109129550542"),
        FieldT("14643335163846663204197941112945447472862168442334003800621296569318670799451"),
        FieldT("1933387276732345916104540506251808516402995586485132246682941535467305930334"),
        FieldT("7286414555941977227951257572976885370489143210539802284740420664558593616067"),
        FieldT("16932161189449419608528042274282099409408565503929504242784173714823499212410"),
        FieldT("16562533130736679030886586765487416082772837813468081467237161865787494093536"),
        FieldT("6037428193077828806710267464232314380014232668931818917272972397574634037180")
    };
    x.fill_with_field_elements(in_pb, level_IVs);

    return x;
}
*/
