#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "risc_v_disassembler.h"

// Type for pointers to functions
typedef void (*command)(command_data *cmd);

typedef struct {
    const char * const name;
    const command parse_func;
    const char * const format;
} rv_opcode_data;

//================================================================
//=========Source and Destination Register Listings===============
//================================================================

static const char rv_fmt_none[]                   = "O\t";
static const char rv_fmt_rs1[]                    = "O\t1";
static const char rv_fmt_offset[]                 = "O\to";
static const char rv_fmt_pred_succ[]              = "O\tp,s";
static const char rv_fmt_rs1_rs2[]                = "O\t1,2";
static const char rv_fmt_rd_imm[]                 = "O\t0,i";
static const char rv_fmt_rd_offset[]              = "O\t0,o";
static const char rv_fmt_rd_rs1_rs2[]             = "O\t0,1,2";
static const char rv_fmt_frd_rs1[]                = "O\t3,1";
static const char rv_fmt_rd_frs1[]                = "O\t0,4";
static const char rv_fmt_rd_frs1_frs2[]           = "O\t0,4,5";
static const char rv_fmt_frd_frs1_frs2[]          = "O\t3,4,5";
static const char rv_fmt_rm_frd_frs1[]            = "O\tr,3,4";
static const char rv_fmt_rm_frd_rs1[]             = "O\tr,3,1";
static const char rv_fmt_rm_rd_frs1[]             = "O\tr,0,4";
static const char rv_fmt_rm_frd_frs1_frs2[]       = "O\tr,3,4,5";
static const char rv_fmt_rm_frd_frs1_frs2_frs3[]  = "O\tr,3,4,5,6";
static const char rv_fmt_rd_rs1_imm[]             = "O\t0,1,i";
static const char rv_fmt_rd_rs1_offset[]          = "O\t0,1,i";
static const char rv_fmt_rd_offset_rs1[]          = "O\t0,i(1)";
static const char rv_fmt_frd_offset_rs1[]         = "O\t3,i(1)";
static const char rv_fmt_rd_csr_rs1[]             = "O\t0,c,1";
static const char rv_fmt_rd_csr_zimm[]            = "O\t0,c,7";
static const char rv_fmt_rs2_offset_rs1[]         = "O\t2,i(1)";
static const char rv_fmt_frs2_offset_rs1[]        = "O\t5,i(1)";
static const char rv_fmt_rs1_rs2_offset[]         = "O\t1,2,o";
static const char rv_fmt_rs2_rs1_offset[]         = "O\t2,1,o";
static const char rv_fmt_aqrl_rd_rs2_rs1[]        = "OAR\t0,2,(1)";
static const char rv_fmt_aqrl_rd_rs1[]            = "OAR\t0,(1)";
static const char rv_fmt_rd[]                     = "O\t0";
static const char rv_fmt_rd_zimm[]                = "O\t0,7";
static const char rv_fmt_rd_rs1[]                 = "O\t0,1";
static const char rv_fmt_rd_rs2[]                 = "O\t0,2";
static const char rv_fmt_rs1_offset[]             = "O\t1,o";
static const char rv_fmt_rs2_offset[]             = "O\t2,o";

//================================================================
//===================== Operand Extractors =======================
//================================================================

static uint32_t operand_rd(uint32_t byte_data) {
    return (byte_data << 20) >> 27;
}

static uint32_t operand_rs1(uint32_t byte_data) {
    return (byte_data << 12) >> 27;
}

static uint32_t operand_rs2(uint32_t byte_data) {
    return (byte_data << 7) >> 27;
}

static uint32_t operand_rs3(uint32_t byte_data) {
    return byte_data >> 27;
}

static uint32_t operand_aq(uint32_t byte_data) {
    return (byte_data << 5) >> 31;
}

static uint32_t operand_rl(uint32_t byte_data) {
    return (byte_data << 6) >> 31;
}

static uint32_t operand_pred(uint32_t byte_data) {
    return (byte_data << 4) >> 28;
}

static uint32_t operand_succ(uint32_t byte_data) {
    return (byte_data << 8) >> 28;
}

static uint32_t operand_rm(uint32_t byte_data) {
    return (byte_data << 17) >> 29;
}

static uint32_t operand_shamt5(uint32_t byte_data) {
    return (byte_data << 7) >> 27;
}

static uint32_t operand_shamt6(uint32_t byte_data) {
    return (byte_data << 6) >> 26;
}

static uint32_t operand_shamt7(uint32_t byte_data) {
    return (byte_data << 5) >> 25;
}

static uint32_t operand_crdq(uint32_t byte_data) {
    return (byte_data << 27) >> 29;
}

static uint32_t operand_crs1q(uint32_t byte_data) {
    return (byte_data << 22) >> 29;
}

static uint32_t operand_crs1rdq(uint32_t byte_data) {
    return (byte_data << 22) >> 29;
}

static uint32_t operand_crs2q(uint32_t byte_data) {
    return (byte_data << 27) >> 29;
}

static uint32_t operand_crd(uint32_t byte_data) {
    return (byte_data << 20) >> 27;
}

static uint32_t operand_crs1(uint32_t byte_data) {
    return (byte_data << 20) >> 27;
}

static uint32_t operand_crs1rd(uint32_t byte_data) {
    return (byte_data << 20) >> 27;
}

static uint32_t operand_crs2(uint32_t byte_data) {
    return (byte_data << 25) >> 27;
}

static uint32_t operand_cimmsh5(uint32_t byte_data) {
    return (byte_data << 25) >> 27;
}

static uint32_t operand_csr12(uint32_t byte_data) {
    return byte_data >> 20;
}

static int32_t operand_imm12(uint32_t byte_data) {
    return ((int32_t)byte_data) >> 20;
}

static int32_t operand_imm20(uint32_t byte_data) {
    return (((int32_t)byte_data) >> 12) << 12;
}

static int32_t operand_jimm20(uint32_t byte_data) {
    return (((int32_t)byte_data) >> 31) << 20 |
        ((byte_data << 1) >> 22) << 1 |
        ((byte_data << 11) >> 31) << 11 |
        ((byte_data << 12) >> 24) << 12;
}

static int32_t operand_simm12(uint32_t byte_data) {
    return (((int32_t)byte_data) >> 25) << 5 |
        (byte_data << 20) >> 27;
}

static int32_t operand_sbimm12(uint32_t byte_data) {
    return (((int32_t)byte_data) >> 31) << 12 |
        ((byte_data << 1) >> 26) << 5 |
        ((byte_data << 20) >> 28) << 1 |
        ((byte_data << 24) >> 31) << 11;
}

static uint32_t operand_cimmsh6(uint32_t byte_data) {
    return ((byte_data << 19) >> 31) << 5 |
        (byte_data << 25) >> 27;
}

static int32_t operand_cimmi(uint32_t byte_data) {
    return (((int32_t)byte_data << 19) >> 31) << 5 |
        (byte_data << 25) >> 27;
}

static int32_t operand_cimmui(uint32_t byte_data) {
    return (((int32_t)byte_data << 19) >> 31) << 17 |
        ((byte_data << 25) >> 27) << 12;
}

static uint32_t operand_cimmlwsp(uint32_t byte_data) {
    return ((byte_data << 19) >> 31) << 5 |
        ((byte_data << 25) >> 29) << 2 |
        ((byte_data << 28) >> 30) << 6;
}

static uint32_t operand_cimmldsp(uint32_t byte_data) {
    return ((byte_data << 19) >> 31) << 5 |
        ((byte_data << 25) >> 30) << 3 |
        ((byte_data << 27) >> 29) << 6;
}

static uint32_t operand_cimmlqsp(uint32_t byte_data) {
    return ((byte_data << 19) >> 31) << 5 |
        ((byte_data << 25) >> 31) << 4 |
        ((byte_data << 26) >> 28) << 6;
}

static int32_t operand_cimm16sp(uint32_t byte_data) {
    return (((int32_t)byte_data << 19) >> 31) << 9 |
        ((byte_data << 25) >> 31) << 4 |
        ((byte_data << 26) >> 31) << 6 |
        ((byte_data << 27) >> 30) << 7 |
        ((byte_data << 29) >> 31) << 5;
}

static int32_t operand_cimmj(uint32_t byte_data) {
    return (((int32_t)byte_data << 19) >> 31) << 11 |
        ((byte_data << 20) >> 31) << 4 |
        ((byte_data << 21) >> 30) << 8 |
        ((byte_data << 23) >> 31) << 10 |
        ((byte_data << 24) >> 31) << 6 |
        ((byte_data << 25) >> 31) << 7 |
        ((byte_data << 26) >> 29) << 1 |
        ((byte_data << 29) >> 31) << 5;
}

static int32_t operand_cimmb(uint32_t byte_data) {
    return (((int32_t)byte_data << 19) >> 31) << 8 |
        ((byte_data << 20) >> 30) << 3 |
        ((byte_data << 25) >> 30) << 6 |
        ((byte_data << 27) >> 30) << 1 |
        ((byte_data << 29) >> 31) << 5;
}

static uint32_t operand_cimmswsp(uint32_t byte_data) {
    return ((byte_data << 19) >> 28) << 2 |
        ((byte_data << 23) >> 30) << 6;
}

static uint32_t operand_cimmsdsp(uint32_t byte_data) {
    return ((byte_data << 19) >> 29) << 3 |
        ((byte_data << 22) >> 29) << 6;
}

static uint32_t operand_cimmsqsp(uint32_t byte_data) {
    return ((byte_data << 19) >> 30) << 4 |
        ((byte_data << 21) >> 28) << 6;
}

static uint32_t operand_cimm4spn(uint32_t byte_data) {
    return ((byte_data << 19) >> 30) << 4 |
        ((byte_data << 21) >> 28) << 6 |
        ((byte_data << 25) >> 31) << 2 |
        ((byte_data << 26) >> 31) << 3;
}

static uint32_t operand_cimmw(uint32_t byte_data) {
    return ((byte_data << 19) >> 29) << 3 |
        ((byte_data << 25) >> 31) << 2 |
        ((byte_data << 26) >> 31) << 6;
}

static uint32_t operand_cimmd(uint32_t byte_data) {
    return ((byte_data << 19) >> 29) << 3 |
        ((byte_data << 25) >> 30) << 6;
}

static uint32_t operand_cimmq(uint32_t byte_data) {
    return ((byte_data << 19) >> 30) << 4 |
        ((byte_data << 21) >> 31) << 8 |
        ((byte_data << 25) >> 30) << 6;
}
//================================================================
//======================= Codec Functions ========================
//================================================================

static void rv_codec_none(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = rv_reg_zero;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = 0;
}

static void rv_codec_u(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = rv_reg_zero;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_imm20((*cd).byte_data);
}

static void rv_codec_uj(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = rv_reg_zero;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_jimm20((*cd).byte_data);
}

static void rv_codec_i(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_imm12((*cd).byte_data);
}

static void rv_codec_i_sh5(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_shamt5((*cd).byte_data);
}

static void rv_codec_i_sh6(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_shamt6((*cd).byte_data);
}

static void rv_codec_i_sh7(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_shamt7((*cd).byte_data);
}

static void rv_codec_i_csr(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_csr12((*cd).byte_data);
}

static void rv_codec_s(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = operand_rs2((*cd).byte_data);
    (*cd).imm = operand_simm12((*cd).byte_data);
}

static void rv_codec_sb(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = operand_rs2((*cd).byte_data);
    (*cd).imm = operand_sbimm12((*cd).byte_data);
}

static void rv_codec_r(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = operand_rs2((*cd).byte_data);
    (*cd).imm = 0;
}

static void rv_codec_r_m(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = operand_rs2((*cd).byte_data);
    (*cd).imm = 0;
    (*cd).rm = operand_rm((*cd).byte_data);
}

static void rv_codec_r4_m(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = operand_rs2((*cd).byte_data);
    (*cd).rs3 = operand_rs3((*cd).byte_data);
    (*cd).imm = 0;
    (*cd).rm = operand_rm((*cd).byte_data);
}

static void rv_codec_r_a(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = operand_rs2((*cd).byte_data);
    (*cd).imm = 0;
    (*cd).aq = operand_aq((*cd).byte_data);
    (*cd).rl = operand_rl((*cd).byte_data);
}

static void rv_codec_r_l(command_data* cd) {
    (*cd).rd = operand_rd((*cd).byte_data);
    (*cd).rs1 = operand_rs1((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = 0;
    (*cd).aq = operand_aq((*cd).byte_data);
    (*cd).rl = operand_rl((*cd).byte_data);
}

static void rv_codec_r_f(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = rv_reg_zero;
    (*cd).rs2 = rv_reg_zero;
    (*cd).pred = operand_pred((*cd).byte_data);
    (*cd).succ = operand_succ((*cd).byte_data);
    (*cd).imm = 0;
}

static void rv_codec_cb(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = operand_crs1q((*cd).byte_data) + 8;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmb((*cd).byte_data);
}

static void rv_codec_cb_imm(command_data* cd) {
    (*cd).rd = (*cd).rs1 = operand_crs1rdq((*cd).byte_data) + 8;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmi((*cd).byte_data);
}

static void rv_codec_cb_sh5(command_data* cd) {
    (*cd).rd = (*cd).rs1 = operand_crs1rdq((*cd).byte_data) + 8;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmsh5((*cd).byte_data);
}

static void rv_codec_cb_sh6(command_data* cd) {
    (*cd).rd = (*cd).rs1 = operand_crs1rdq((*cd).byte_data) + 8;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmsh6((*cd).byte_data);
}

static void rv_codec_ci(command_data* cd) {
    (*cd).rd = (*cd).rs1 = operand_crs1rd((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmi((*cd).byte_data);
}

static void rv_codec_ci_sh5(command_data* cd) {
    (*cd).rd = (*cd).rs1 = operand_crs1rd((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmsh5((*cd).byte_data);
}

static void rv_codec_ci_sh6(command_data* cd) {
    (*cd).rd = (*cd).rs1 = operand_crs1rd((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmsh6((*cd).byte_data);
}

static void rv_codec_ci_16sp(command_data* cd) {
    (*cd).rd = rv_reg_sp;
    (*cd).rs1 = rv_reg_sp;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimm16sp((*cd).byte_data);
}

static void rv_codec_ci_lwsp(command_data* cd) {
    (*cd).rd = operand_crd((*cd).byte_data);
    (*cd).rs1 = rv_reg_sp;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmlwsp((*cd).byte_data);
}

static void rv_codec_ci_ldsp(command_data* cd) {
    (*cd).rd = operand_crd((*cd).byte_data);
    (*cd).rs1 = rv_reg_sp;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmldsp((*cd).byte_data);
}

static void rv_codec_ci_lqsp(command_data* cd) {
    (*cd).rd = operand_crd((*cd).byte_data);
    (*cd).rs1 = rv_reg_sp;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmlqsp((*cd).byte_data);
}

static void rv_codec_ci_li(command_data* cd) {
    (*cd).rd = operand_crd((*cd).byte_data);
    (*cd).rs1 = rv_reg_zero;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmi((*cd).byte_data);
}

static void rv_codec_ci_lui(command_data* cd) {
    (*cd).rd = operand_crd((*cd).byte_data);
    (*cd).rs1 = rv_reg_zero;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmui((*cd).byte_data);
}

static void rv_codec_ci_none(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = rv_reg_zero;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = 0;
}

static void rv_codec_ciw_4spn(command_data* cd) {
    (*cd).rd = operand_crdq((*cd).byte_data) + 8;
    (*cd).rs1 = rv_reg_sp;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimm4spn((*cd).byte_data);
}

static void rv_codec_cj(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = rv_reg_zero;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmj((*cd).byte_data);
}

static void rv_codec_cj_jal(command_data* cd) {
    (*cd).rd = rv_reg_ra;
    (*cd).rs1 = (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmj((*cd).byte_data);
}

static void rv_codec_cl_lw(command_data* cd) {
    (*cd).rd = operand_crdq((*cd).byte_data) + 8;
    (*cd).rs1 = operand_crs1q((*cd).byte_data) + 8;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmw((*cd).byte_data);
}

static void rv_codec_cl_ld(command_data* cd) {
    (*cd).rd = operand_crdq((*cd).byte_data) + 8;
    (*cd).rs1 = operand_crs1q((*cd).byte_data) + 8;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmd((*cd).byte_data);
}

static void rv_codec_cl_lq(command_data* cd) {
    (*cd).rd = operand_crdq((*cd).byte_data) + 8;
    (*cd).rs1 = operand_crs1q((*cd).byte_data) + 8;
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = operand_cimmq((*cd).byte_data);
}

static void rv_codec_cr(command_data* cd) {
    (*cd).rd = (*cd).rs1 = operand_crs1rd((*cd).byte_data);
    (*cd).rs2 = operand_crs2((*cd).byte_data);
    (*cd).imm = 0;
}

static void rv_codec_cr_mv(command_data* cd) {
    (*cd).rd = operand_crd((*cd).byte_data);
    (*cd).rs1 = operand_crs2((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = 0;
}

static void rv_codec_cr_jalr(command_data* cd) {
    (*cd).rd = rv_reg_ra;
    (*cd).rs1 = operand_crs1((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = 0;
}

static void rv_codec_cr_jr(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = operand_crs1((*cd).byte_data);
    (*cd).rs2 = rv_reg_zero;
    (*cd).imm = 0;
}

static void rv_codec_cs(command_data* cd) {
    (*cd).rd = (*cd).rs1 = operand_crs1rdq((*cd).byte_data) + 8;
    (*cd).rs2 = operand_crs2q((*cd).byte_data) + 8;
    (*cd).imm = 0;
}

static void rv_codec_cs_sw(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = operand_crs1q((*cd).byte_data) + 8;
    (*cd).rs2 = operand_crs2q((*cd).byte_data) + 8;
    (*cd).imm = operand_cimmw((*cd).byte_data);
}

static void rv_codec_cs_sd(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = operand_crs1q((*cd).byte_data) + 8;
    (*cd).rs2 = operand_crs2q((*cd).byte_data) + 8;
    (*cd).imm = operand_cimmd((*cd).byte_data);
}

static void rv_codec_cs_sq(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = operand_crs1q((*cd).byte_data) + 8;
    (*cd).rs2 = operand_crs2q((*cd).byte_data) + 8;
    (*cd).imm = operand_cimmq((*cd).byte_data);
}

static void rv_codec_css_swsp(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = rv_reg_sp;
    (*cd).rs2 = operand_crs2((*cd).byte_data);
    (*cd).imm = operand_cimmswsp((*cd).byte_data);
}

static void rv_codec_css_sdsp(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = rv_reg_sp;
    (*cd).rs2 = operand_crs2((*cd).byte_data);
    (*cd).imm = operand_cimmsdsp((*cd).byte_data);
}

static void rv_codec_css_sqsp(command_data* cd) {
    (*cd).rd = rv_reg_zero;
    (*cd).rs1 = rv_reg_sp;
    (*cd).rs2 = operand_crs2((*cd).byte_data);
    (*cd).imm = operand_cimmsqsp((*cd).byte_data);
}

//================================================================
//======================== Opcode Data ===========================
//================================================================

const rv_opcode_data opcode_data[] = {
    { "illegal", rv_codec_none, rv_fmt_none }, // op_illegal
    { "addi", rv_codec_ciw_4spn, rv_fmt_rd_rs1_imm }, // op_c_addi4spn
    { "fld", rv_codec_cl_ld, rv_fmt_frd_offset_rs1}, // op_c_fld
    { "lq", rv_codec_cl_lq, rv_fmt_rd_offset_rs1 }, // op_c_lq
    { "lw", rv_codec_cl_lw, rv_fmt_rd_offset_rs1 }, // op_c_lw
    { "flw", rv_codec_cl_lw, rv_fmt_frd_offset_rs1 }, // op_c_flw
    { "ld", rv_codec_cl_ld, rv_fmt_rd_offset_rs1 }, // op_c_ld
    { "fsd", rv_codec_cs_sd, rv_fmt_frs2_offset_rs1 }, // op_c_fsd
    { "sq", rv_codec_cs_sq, rv_fmt_rs2_offset_rs1 }, // op_c_sq
    { "sw", rv_codec_cs_sw, rv_fmt_rs2_offset_rs1 }, // op_c_sw
    { "fsw", rv_codec_cs_sw, rv_fmt_frs2_offset_rs1 }, // op_c_fsw
    { "sd", rv_codec_cs_sd, rv_fmt_rs2_offset_rs1 }, // op_c_sd
    { "nop", rv_codec_ci_none, rv_fmt_none }, // op_c_nop
    { "addi", rv_codec_ci, rv_fmt_rd_rs1_imm }, // op_c_addi
    { "jal", rv_codec_cj_jal, rv_fmt_rd_offset }, // op_c_jal
    { "addiw", rv_codec_ci, rv_fmt_rd_rs1_imm }, // op_c_addiw
    { "addi", rv_codec_ci_li, rv_fmt_rd_rs1_imm }, // op_c_li
    { "addi", rv_codec_ci_16sp, rv_fmt_rd_rs1_imm }, // op_c_addi16sp
    { "lui", rv_codec_ci_lui, rv_fmt_rd_imm }, // op_c_lui
    { "srli", rv_codec_cb_sh6, rv_fmt_rd_rs1_imm }, // op_c_srli
    { "srai", rv_codec_cb_sh6, rv_fmt_rd_rs1_imm}, // op_c_srai
    { "andi", rv_codec_cb_imm, rv_fmt_rd_rs1_imm }, // op_c_andi
    { "sub", rv_codec_cs, rv_fmt_rd_rs1_rs2 }, // op_c_sub
    { "xor", rv_codec_cs, rv_fmt_rd_rs1_rs2 }, // op_c_xor
    { "or", rv_codec_cs, rv_fmt_rd_rs1_rs2 }, // op_c_or
    { "and", rv_codec_cs, rv_fmt_rd_rs1_rs2}, // op_c_and
    { "subw", rv_codec_cs, rv_fmt_rd_rs1_rs2 }, // op_c_subw
    { "addw", rv_codec_cs, rv_fmt_rd_rs1_rs2 }, // op_c_addw
    { "j", rv_codec_cj, rv_fmt_offset }, // op_c_j
    { "beqz", rv_codec_cb, rv_fmt_rs1_offset}, // op_c_beqz
    { "bnez", rv_codec_cb, rv_fmt_rs1_offset}, // op_c_bnez
    { "slli", rv_codec_ci_sh6, rv_fmt_rd_rs1_imm }, // op_c_slli
    { "fld", rv_codec_ci_ldsp, rv_fmt_frd_offset_rs1 }, // op_c_fldsp
    { "lq", rv_codec_ci_lqsp, rv_fmt_rd_offset_rs1}, // op_c_lqsp
    { "lw", rv_codec_ci_lwsp, rv_fmt_rd_offset_rs1}, // op_c_lwsp
    { "flw", rv_codec_ci_lwsp, rv_fmt_frd_offset_rs1}, // op_c_flwsp
    { "ld", rv_codec_ci_ldsp, rv_fmt_rd_offset_rs1 }, // op_c_ldsp
    { "jr", rv_codec_cr_jr, rv_fmt_rs1 }, // op_c_jr
    { "mv", rv_codec_cr_mv, rv_fmt_rd_rs1 }, // op_c_mv
    { "ebreak", rv_codec_ci_none, rv_fmt_none }, // op_c_ebreak
    { "jalr", rv_codec_cr_jalr, rv_fmt_rd_rs1_offset }, // op_c_jalr
    { "add", rv_codec_cr, rv_fmt_rd_rs1_rs2 }, // op_c_add
    { "fsd", rv_codec_css_sdsp, rv_fmt_frs2_offset_rs1 }, // op_c_fsdsp
    { "sq", rv_codec_css_sqsp, rv_fmt_rs2_offset_rs1 }, // op_c_sqsp
    { "sw", rv_codec_css_swsp, rv_fmt_rs2_offset_rs1 }, // op_c_swsp
    { "fsw", rv_codec_css_swsp, rv_fmt_frs2_offset_rs1 }, // op_c_fswsp
    { "sd", rv_codec_css_sdsp, rv_fmt_rs2_offset_rs1 }, // op_c_sdsp // LAST OF COMPRESSED
    { "lui", rv_codec_u, rv_fmt_rd_imm }, // op_lui
    { "auipc", rv_codec_u, rv_fmt_rd_offset }, // op_auipc
    { "jal", rv_codec_uj, rv_fmt_rd_offset }, // op_jal
    { "jalr", rv_codec_i, rv_fmt_rd_rs1_offset }, // op_jalr
    { "beq", rv_codec_sb, rv_fmt_rs1_rs2_offset }, // op_beq
    { "bne", rv_codec_sb, rv_fmt_rs1_rs2_offset }, // op_bne
    { "blt", rv_codec_sb, rv_fmt_rs1_rs2_offset }, // op_blt
    { "bge", rv_codec_sb, rv_fmt_rs1_rs2_offset }, // op_bge
    { "bltu", rv_codec_sb, rv_fmt_rs1_rs2_offset }, // op_bltu
    { "bgeu", rv_codec_sb, rv_fmt_rs1_rs2_offset }, // op_bgeu
    { "lb", rv_codec_i, rv_fmt_rd_offset_rs1 }, // op_lb
    { "lh", rv_codec_i, rv_fmt_rd_offset_rs1 }, // op_lh
    { "lw", rv_codec_i, rv_fmt_rd_offset_rs1 }, // op_lw
    { "lbu", rv_codec_i, rv_fmt_rd_offset_rs1 }, // op_lbu
    { "lhu", rv_codec_i, rv_fmt_rd_offset_rs1 }, // op_lhu
    { "sb", rv_codec_s, rv_fmt_rs2_offset_rs1 }, // op_sb
    { "sh", rv_codec_s, rv_fmt_rs2_offset_rs1 }, // op_sh
    { "sw", rv_codec_s, rv_fmt_rs2_offset_rs1 }, // op_sw
    { "addi", rv_codec_i, rv_fmt_rd_rs1_imm }, // op_addi
    { "slti", rv_codec_i, rv_fmt_rd_rs1_imm }, // op_slti
    { "sltiu", rv_codec_i, rv_fmt_rd_rs1_imm }, // op_sltiu
    { "xori", rv_codec_i, rv_fmt_rd_rs1_imm }, // op_xori
    { "ori", rv_codec_i, rv_fmt_rd_rs1_imm }, // op_ori
    { "andi", rv_codec_i, rv_fmt_rd_rs1_imm }, // op_andi
    { "slli", rv_codec_i_sh7, rv_fmt_rd_rs1_imm }, // op_slli
    { "srli", rv_codec_i_sh7, rv_fmt_rd_rs1_imm }, // op_srli
    { "srai", rv_codec_i_sh7, rv_fmt_rd_rs1_imm }, // op_srai
    { "add", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_add
    { "sub", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_sub
    { "sll", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_sll
    { "slt", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_slt
    { "sltu", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_sltu
    { "xor", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_xor
    { "srl", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_srl
    { "sra", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_sra
    { "or", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_or
    { "and", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_and
    { "fence", rv_codec_r_f, rv_fmt_pred_succ }, // op_fence
    { "ecall", rv_codec_none, rv_fmt_none }, // op_ecall
    { "ebreak", rv_codec_none, rv_fmt_none }, // op_ebreak
    { "lwu", rv_codec_i, rv_fmt_rd_offset_rs1 }, // op_lwu
    { "ld", rv_codec_i, rv_fmt_rd_offset_rs1 }, // op_ld
    { "sd", rv_codec_s, rv_fmt_rs2_offset_rs1 }, // op_sd
    { "addiw", rv_codec_i, rv_fmt_rd_rs1_imm}, // op_addiw
    { "slliw", rv_codec_i_sh5, rv_fmt_rd_rs1_imm }, // op_slliw
    { "srliw", rv_codec_i_sh5, rv_fmt_rd_rs1_imm }, // op_srliw
    { "sraiw", rv_codec_i_sh5, rv_fmt_rd_rs1_imm }, // op_sraiw
    { "addw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_addw
    { "subw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_subw
    { "sllw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_sllw
    { "srlw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_srlw
    { "sraw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_sraw
    { "fence.i", rv_codec_none, rv_fmt_none }, // op_fence_i
    { "csrrw", rv_codec_i_csr, rv_fmt_rd_csr_rs1 }, // op_csrrw
    { "csrrs", rv_codec_i_csr, rv_fmt_rd_csr_rs1 }, // op_csrrs
    { "csrrc", rv_codec_i_csr, rv_fmt_rd_csr_rs1 }, // op_csrrc
    { "csrrwi", rv_codec_i_csr, rv_fmt_rd_csr_zimm }, // op_csrrwi
    { "csrrsi", rv_codec_i_csr, rv_fmt_rd_csr_zimm }, // op_csrrsi
    { "csrrci", rv_codec_i_csr, rv_fmt_rd_csr_zimm }, // op_csrrci
    { "mul", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_mul
    { "mulh", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_mulh
    { "mulhsu", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_mulhsu
    { "mulhu", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_mulhu
    { "div", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_div
    { "divu", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_divu
    { "rem", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_rem
    { "remu", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_remu
    { "mulw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_mulw
    { "divw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_divw
    { "divuw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_divuw
    { "remw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_remw
    { "remuw", rv_codec_r, rv_fmt_rd_rs1_rs2 }, // op_remuw
    { "lr.w", rv_codec_r_l, rv_fmt_aqrl_rd_rs1 }, // op_lr_w
    { "sc.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_sc_w
    { "amoswap.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoswap_w
    { "amoadd.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoadd_w
    { "amoxor.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoxor_w
    { "amoand.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoand_w
    { "amoor.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoor_w
    { "amomin.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amomin_w
    { "amomax.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amomax_w
    { "amominu.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amominu_w
    { "amomaxu.w", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amomaxu_w
    { "lr.d", rv_codec_r_l, rv_fmt_aqrl_rd_rs1 }, // op_lr_d
    { "sc.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_sc_d
    { "amoswap.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoswap_d
    { "amoadd.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoadd_d
    { "amoxor.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoxor_d
    { "amoand.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoand_d
    { "amoor.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amoor_d
    { "amomin.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amomin_d
    { "amomax.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amomax_d
    { "amominu.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amominu_d
    { "amomaxu.d", rv_codec_r_a, rv_fmt_aqrl_rd_rs2_rs1 }, // op_amomaxu_d
    { "flw", rv_codec_i, rv_fmt_frd_offset_rs1 }, // op_flw
    { "fsw", rv_codec_s, rv_fmt_frs2_offset_rs1 }, // op_fsw
    { "fmadd.s", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fmadd_s
    { "fmsum.s", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fmsub_s
    { "fnmsub.s", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fnmsub_s
    { "fnmadd.s", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fnmadd_s
    { "fadd.s", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fadd_s
    { "fsub.s", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fsub_s
    { "fmul.s", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fmul_s
    { "fdiv.s", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fdiv_s
    { "fsqrt.s", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fsqrt_s
    { "fsgnj.s", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnj_s
    { "fsgnjn.s", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnjn_s
    { "fsgnjx.s", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnjx_s
    { "fmin.s", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fmin_s
    { "fmax.s", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fmax_s
    { "fcvt.w.s", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_w_s
    { "fcvt.wu.s", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_wu_s
    { "fmv.x.w", rv_codec_r, rv_fmt_rd_frs1 }, // op_fmv_x_w
    { "feq.s", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_feq_s
    { "flt.s", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_flt_s
    { "fle.s", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_fle_s
    { "fclass.s", rv_codec_r, rv_fmt_rd_frs1 }, // op_fclass_s
    { "fcvt.s.w", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_s_w
    { "fcvt.s.wu", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_s_wu
    { "fmv.w.x", rv_codec_r, rv_fmt_frd_rs1 }, // op_fmv_w_x
    { "fcvt.l.s", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_l_s
    { "fcvt.lu.s", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_lu_s
    { "fcvt.s.l", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_s_l
    { "fcvt.s.lu", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_s_lu
    { "fld", rv_codec_i, rv_fmt_frd_offset_rs1 }, // op_fld
    { "fsd", rv_codec_s, rv_fmt_frs2_offset_rs1 }, // op_fsd
    { "fmadd.d", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fmadd_d
    { "fmsub.d", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3}, // op_fmsub_d
    { "fnmsub.d", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3}, // op_fnmsub_d
    { "fnmadd.d", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3}, // op_fnmadd_d
    { "fadd.d", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fadd_d
    { "fsub.d", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fsub_d
    { "fmul.d", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fmul_d
    { "fdiv.d", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fdiv_d
    { "fsqrt.d", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fsqrt_d
    { "fsgnj.d", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnj_d
    { "fsgnjn.d", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnjn_d
    { "fsgnjx.d", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnjx_d
    { "fmin.d", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fmin_d
    { "fmax.d", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fmax_d
    { "fcvt.s.d", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_s_d
    { "fcvt.d.s", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_d_s
    { "feq.d", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_feq_d
    { "flt.d", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_flt_d
    { "fle.d", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_fle_d
    { "fclass.d", rv_codec_r, rv_fmt_rd_frs1 }, // op_fclass_d
    { "fcvt.w.d", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_w_d
    { "fcvt.wu.d", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_wu_d
    { "fcvt.d.w", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_d_w
    { "fcvt.d.wu", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_d_wu
    { "fcvt.l.d", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_l_d
    { "fcvt.lu.d", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_lu_d
    { "fmv.x.d", rv_codec_r, rv_fmt_rd_frs1 }, // op_fmv_x_d
    { "fcvt.d.l", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_d_l
    { "fcvt.d.lu", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_d_lu
    { "fmv.d.x", rv_codec_r, rv_fmt_frd_rs1 }, // op_fmv_d_x
    { "flq", rv_codec_i, rv_fmt_frd_offset_rs1 }, // op_flq
    { "fsq", rv_codec_s, rv_fmt_frs2_offset_rs1 }, // op_fsq
    { "fmadd.q", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fmadd_q
    { "fmsub.q", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fmsub_q
    { "fnmsub.q", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fnmsub_q
    { "fnmadd.q", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fnmadd_q
    { "fadd.q", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fadd_q
    { "fsub.q", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fsub_q
    { "fmul.q", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fmul_q
    { "fdiv.q", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fdiv_q
    { "fsqrt.q", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fsqrt_q
    { "fsgnj.q", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnj_q
    { "fsgnjn.q", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnjn_q
    { "fsgnjx.q", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnjx_q
    { "fmin.q", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fmin_q
    { "fmax.q", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fmax_q
    { "fcvt.s.q", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_s_q
    { "fcvt.q.s", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_q_s
    { "fcvt.d.q", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_d_q
    { "fcvt.q.d", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_q_d
    { "feq.q", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_feq_q
    { "flt.q", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_flt_q
    { "fle.q", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_fle_q
    { "fclass.q", rv_codec_r, rv_fmt_rd_frs1 }, // op_fclass_q
    { "fcvt.w.q", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_w_q
    { "fcvt.wu.q", rv_codec_r_m, rv_fmt_rm_rd_frs1}, // op_fcvt_wu_q
    { "fcvt.q.w", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_q_w
    { "fcvt.q.wu", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_q_wu
    { "fcvt.l.q", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_l_q
    { "fcvt.lu.q", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_lu_q
    { "fcvt.q.l", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_q_l
    { "fcvt.q.lu", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_q_lu
    { "flh", rv_codec_i, rv_fmt_frd_offset_rs1 }, // op_flh
    { "fsh", rv_codec_s, rv_fmt_frs2_offset_rs1 }, // op_fsh
    { "fmadd.h", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fmadd_h
    { "fmsub.h", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fmsub_h
    { "fnmsub.h", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fnmsub_h
    { "fnmadd.h", rv_codec_r4_m, rv_fmt_rm_frd_frs1_frs2_frs3 }, // op_fnmadd_h
    { "fadd.h", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fadd_h
    { "fsub.h", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fsub_h
    { "fmul.h", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fmul_h
    { "fdiv.h", rv_codec_r_m, rv_fmt_rm_frd_frs1_frs2 }, // op_fdiv_h
    { "fsqrt.h", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fsqrt_h
    { "fsgnj.h", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnj_h
    { "fsgnjn.h", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnjn_h
    { "fsgnjx.h", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fsgnjx_h
    { "fmin.h", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fmin_h
    { "fmax.h", rv_codec_r, rv_fmt_frd_frs1_frs2 }, // op_fmax_h
    { "fcvt.s.h", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_s_h
    { "fcvt.h.s", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_h_s
    { "fcvt.d.h", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_d_h
    { "fcvt.h.d", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_h_d
    { "fcvt.q.h", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_q_h
    { "fcvt.h.q", rv_codec_r_m, rv_fmt_rm_frd_frs1 }, // op_fcvt_h_q
    { "feq.h", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_feq_h
    { "flt.h", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_flt_h
    { "fle.h", rv_codec_r, rv_fmt_rd_frs1_frs2 }, // op_fle_h
    { "fclass.h", rv_codec_r, rv_fmt_rd_frs1 }, // op_fclass_h
    { "fcvt.w.h", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_w_h
    { "fcvt.wu.h", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_wu_h
    { "fmv.x.h", rv_codec_r, rv_fmt_rd_frs1 }, // op_fmv_x_h
    { "fcvt.h.w", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_h_w
    { "fcvt.h.wu", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_h_wu
    { "fmv.h.x", rv_codec_r, rv_fmt_frd_rs1 }, // op_fmv_h_x
    { "fcvt.l.h", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_l_h
    { "fcvt.lu.h", rv_codec_r_m, rv_fmt_rm_rd_frs1 }, // op_fcvt_lu_h
    { "fcvt.h.l", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_h_l
    { "fcvt.h.lu", rv_codec_r_m, rv_fmt_rm_frd_rs1 }, // op_fcvt_h_lu
    { "wrs.nto", rv_codec_ci_none, rv_fmt_none }, // op_wrs_nto
    { "wrs.sto", rv_codec_ci_none, rv_fmt_none } // op_wrs_sto
};

//================================================================
//========================= CSR NAME =============================
//================================================================

static const char *csr_name(int csrno)
{
    switch (csrno) {
    case 0x0000: return "ustatus";
    case 0x0001: return "fflags";
    case 0x0002: return "frm";
    case 0x0003: return "fcsr";
    case 0x0004: return "uie";
    case 0x0005: return "utvec";
    case 0x0007: return "utvt";
    case 0x0008: return "vstart";
    case 0x0009: return "vxsat";
    case 0x000a: return "vxrm";
    case 0x000f: return "vcsr";
    case 0x0040: return "uscratch";
    case 0x0041: return "uepc";
    case 0x0042: return "ucause";
    case 0x0043: return "utval";
    case 0x0044: return "uip";
    case 0x0045: return "unxti";
    case 0x0046: return "uintstatus";
    case 0x0048: return "uscratchcsw";
    case 0x0049: return "uscratchcswl";
    case 0x0100: return "sstatus";
    case 0x0102: return "sedeleg";
    case 0x0103: return "sideleg";
    case 0x0104: return "sie";
    case 0x0105: return "stvec";
    case 0x0106: return "scounteren";
    case 0x0107: return "stvt";
    case 0x0140: return "sscratch";
    case 0x0141: return "sepc";
    case 0x0142: return "scause";
    case 0x0143: return "stval";
    case 0x0144: return "sip";
    case 0x0145: return "snxti";
    case 0x0146: return "sintstatus";
    case 0x0148: return "sscratchcsw";
    case 0x0149: return "sscratchcswl";
    case 0x0180: return "satp";
    case 0x0200: return "vsstatus";
    case 0x0204: return "vsie";
    case 0x0205: return "vstvec";
    case 0x0240: return "vsscratch";
    case 0x0241: return "vsepc";
    case 0x0242: return "vscause";
    case 0x0243: return "vstval";
    case 0x0244: return "vsip";
    case 0x0280: return "vsatp";
    case 0x0300: return "mstatus";
    case 0x0301: return "misa";
    case 0x0302: return "medeleg";
    case 0x0303: return "mideleg";
    case 0x0304: return "mie";
    case 0x0305: return "mtvec";
    case 0x0306: return "mcounteren";
    case 0x0307: return "mtvt";
    case 0x0310: return "mstatush";
    case 0x0320: return "mcountinhibit";
    case 0x0323: return "mhpmevent3";
    case 0x0324: return "mhpmevent4";
    case 0x0325: return "mhpmevent5";
    case 0x0326: return "mhpmevent6";
    case 0x0327: return "mhpmevent7";
    case 0x0328: return "mhpmevent8";
    case 0x0329: return "mhpmevent9";
    case 0x032a: return "mhpmevent10";
    case 0x032b: return "mhpmevent11";
    case 0x032c: return "mhpmevent12";
    case 0x032d: return "mhpmevent13";
    case 0x032e: return "mhpmevent14";
    case 0x032f: return "mhpmevent15";
    case 0x0330: return "mhpmevent16";
    case 0x0331: return "mhpmevent17";
    case 0x0332: return "mhpmevent18";
    case 0x0333: return "mhpmevent19";
    case 0x0334: return "mhpmevent20";
    case 0x0335: return "mhpmevent21";
    case 0x0336: return "mhpmevent22";
    case 0x0337: return "mhpmevent23";
    case 0x0338: return "mhpmevent24";
    case 0x0339: return "mhpmevent25";
    case 0x033a: return "mhpmevent26";
    case 0x033b: return "mhpmevent27";
    case 0x033c: return "mhpmevent28";
    case 0x033d: return "mhpmevent29";
    case 0x033e: return "mhpmevent30";
    case 0x033f: return "mhpmevent31";
    case 0x0340: return "mscratch";
    case 0x0341: return "mepc";
    case 0x0342: return "mcause";
    case 0x0343: return "mtval";
    case 0x0344: return "mip";
    case 0x0345: return "mnxti";
    case 0x0346: return "mintstatus";
    case 0x0348: return "mscratchcsw";
    case 0x0349: return "mscratchcswl";
    case 0x034a: return "mtinst";
    case 0x034b: return "mtval2";
    case 0x03a0: return "pmpcfg0";
    case 0x03a1: return "pmpcfg1";
    case 0x03a2: return "pmpcfg2";
    case 0x03a3: return "pmpcfg3";
    case 0x03b0: return "pmpaddr0";
    case 0x03b1: return "pmpaddr1";
    case 0x03b2: return "pmpaddr2";
    case 0x03b3: return "pmpaddr3";
    case 0x03b4: return "pmpaddr4";
    case 0x03b5: return "pmpaddr5";
    case 0x03b6: return "pmpaddr6";
    case 0x03b7: return "pmpaddr7";
    case 0x03b8: return "pmpaddr8";
    case 0x03b9: return "pmpaddr9";
    case 0x03ba: return "pmpaddr10";
    case 0x03bb: return "pmpaddr11";
    case 0x03bc: return "pmpaddr12";
    case 0x03bd: return "pmpaddr13";
    case 0x03be: return "pmpaddr14";
    case 0x03bf: return "pmpaddr15";
    case 0x0600: return "hstatus";
    case 0x0602: return "hedeleg";
    case 0x0603: return "hideleg";
    case 0x0604: return "hie";
    case 0x0605: return "htimedelta";
    case 0x0606: return "hcounteren";
    case 0x0607: return "hgeie";
    case 0x0615: return "htimedeltah";
    case 0x0643: return "htval";
    case 0x0644: return "hip";
    case 0x0645: return "hvip";
    case 0x064a: return "htinst";
    case 0x0680: return "hgatp";
    case 0x07a0: return "tselect";
    case 0x07a1: return "tdata1";
    case 0x07a2: return "tdata2";
    case 0x07a3: return "tdata3";
    case 0x07a4: return "tinfo";
    case 0x07a5: return "tcontrol";
    case 0x07a8: return "mcontext";
    case 0x07a9: return "mnoise";
    case 0x07aa: return "scontext";
    case 0x07b0: return "dcsr";
    case 0x07b1: return "dpc";
    case 0x07b2: return "dscratch0";
    case 0x07b3: return "dscratch1";
    case 0x0b00: return "mcycle";
    case 0x0b02: return "minstret";
    case 0x0b03: return "mhpmcounter3";
    case 0x0b04: return "mhpmcounter4";
    case 0x0b05: return "mhpmcounter5";
    case 0x0b06: return "mhpmcounter6";
    case 0x0b07: return "mhpmcounter7";
    case 0x0b08: return "mhpmcounter8";
    case 0x0b09: return "mhpmcounter9";
    case 0x0b0a: return "mhpmcounter10";
    case 0x0b0b: return "mhpmcounter11";
    case 0x0b0c: return "mhpmcounter12";
    case 0x0b0d: return "mhpmcounter13";
    case 0x0b0e: return "mhpmcounter14";
    case 0x0b0f: return "mhpmcounter15";
    case 0x0b10: return "mhpmcounter16";
    case 0x0b11: return "mhpmcounter17";
    case 0x0b12: return "mhpmcounter18";
    case 0x0b13: return "mhpmcounter19";
    case 0x0b14: return "mhpmcounter20";
    case 0x0b15: return "mhpmcounter21";
    case 0x0b16: return "mhpmcounter22";
    case 0x0b17: return "mhpmcounter23";
    case 0x0b18: return "mhpmcounter24";
    case 0x0b19: return "mhpmcounter25";
    case 0x0b1a: return "mhpmcounter26";
    case 0x0b1b: return "mhpmcounter27";
    case 0x0b1c: return "mhpmcounter28";
    case 0x0b1d: return "mhpmcounter29";
    case 0x0b1e: return "mhpmcounter30";
    case 0x0b1f: return "mhpmcounter31";
    case 0x0b80: return "mcycleh";
    case 0x0b82: return "minstreth";
    case 0x0b83: return "mhpmcounter3h";
    case 0x0b84: return "mhpmcounter4h";
    case 0x0b85: return "mhpmcounter5h";
    case 0x0b86: return "mhpmcounter6h";
    case 0x0b87: return "mhpmcounter7h";
    case 0x0b88: return "mhpmcounter8h";
    case 0x0b89: return "mhpmcounter9h";
    case 0x0b8a: return "mhpmcounter10h";
    case 0x0b8b: return "mhpmcounter11h";
    case 0x0b8c: return "mhpmcounter12h";
    case 0x0b8d: return "mhpmcounter13h";
    case 0x0b8e: return "mhpmcounter14h";
    case 0x0b8f: return "mhpmcounter15h";
    case 0x0b90: return "mhpmcounter16h";
    case 0x0b91: return "mhpmcounter17h";
    case 0x0b92: return "mhpmcounter18h";
    case 0x0b93: return "mhpmcounter19h";
    case 0x0b94: return "mhpmcounter20h";
    case 0x0b95: return "mhpmcounter21h";
    case 0x0b96: return "mhpmcounter22h";
    case 0x0b97: return "mhpmcounter23h";
    case 0x0b98: return "mhpmcounter24h";
    case 0x0b99: return "mhpmcounter25h";
    case 0x0b9a: return "mhpmcounter26h";
    case 0x0b9b: return "mhpmcounter27h";
    case 0x0b9c: return "mhpmcounter28h";
    case 0x0b9d: return "mhpmcounter29h";
    case 0x0b9e: return "mhpmcounter30h";
    case 0x0b9f: return "mhpmcounter31h";
    case 0x0c00: return "cycle";
    case 0x0c01: return "time";
    case 0x0c02: return "instret";
    case 0x0c03: return "hpmcounter3";
    case 0x0c04: return "hpmcounter4";
    case 0x0c05: return "hpmcounter5";
    case 0x0c06: return "hpmcounter6";
    case 0x0c07: return "hpmcounter7";
    case 0x0c08: return "hpmcounter8";
    case 0x0c09: return "hpmcounter9";
    case 0x0c0a: return "hpmcounter10";
    case 0x0c0b: return "hpmcounter11";
    case 0x0c0c: return "hpmcounter12";
    case 0x0c0d: return "hpmcounter13";
    case 0x0c0e: return "hpmcounter14";
    case 0x0c0f: return "hpmcounter15";
    case 0x0c10: return "hpmcounter16";
    case 0x0c11: return "hpmcounter17";
    case 0x0c12: return "hpmcounter18";
    case 0x0c13: return "hpmcounter19";
    case 0x0c14: return "hpmcounter20";
    case 0x0c15: return "hpmcounter21";
    case 0x0c16: return "hpmcounter22";
    case 0x0c17: return "hpmcounter23";
    case 0x0c18: return "hpmcounter24";
    case 0x0c19: return "hpmcounter25";
    case 0x0c1a: return "hpmcounter26";
    case 0x0c1b: return "hpmcounter27";
    case 0x0c1c: return "hpmcounter28";
    case 0x0c1d: return "hpmcounter29";
    case 0x0c1e: return "hpmcounter30";
    case 0x0c1f: return "hpmcounter31";
    case 0x0c20: return "vl";
    case 0x0c21: return "vtype";
    case 0x0c22: return "vlenb";
    case 0x0c80: return "cycleh";
    case 0x0c81: return "timeh";
    case 0x0c82: return "instreth";
    case 0x0c83: return "hpmcounter3h";
    case 0x0c84: return "hpmcounter4h";
    case 0x0c85: return "hpmcounter5h";
    case 0x0c86: return "hpmcounter6h";
    case 0x0c87: return "hpmcounter7h";
    case 0x0c88: return "hpmcounter8h";
    case 0x0c89: return "hpmcounter9h";
    case 0x0c8a: return "hpmcounter10h";
    case 0x0c8b: return "hpmcounter11h";
    case 0x0c8c: return "hpmcounter12h";
    case 0x0c8d: return "hpmcounter13h";
    case 0x0c8e: return "hpmcounter14h";
    case 0x0c8f: return "hpmcounter15h";
    case 0x0c90: return "hpmcounter16h";
    case 0x0c91: return "hpmcounter17h";
    case 0x0c92: return "hpmcounter18h";
    case 0x0c93: return "hpmcounter19h";
    case 0x0c94: return "hpmcounter20h";
    case 0x0c95: return "hpmcounter21h";
    case 0x0c96: return "hpmcounter22h";
    case 0x0c97: return "hpmcounter23h";
    case 0x0c98: return "hpmcounter24h";
    case 0x0c99: return "hpmcounter25h";
    case 0x0c9a: return "hpmcounter26h";
    case 0x0c9b: return "hpmcounter27h";
    case 0x0c9c: return "hpmcounter28h";
    case 0x0c9d: return "hpmcounter29h";
    case 0x0c9e: return "hpmcounter30h";
    case 0x0c9f: return "hpmcounter31h";
    case 0x0e12: return "hgeip";
    case 0x0f11: return "mvendorid";
    case 0x0f12: return "marchid";
    case 0x0f13: return "mimpid";
    case 0x0f14: return "mhartid";
    case 0x0f15: return "mentropy";
    default: return NULL;
    }
}

//================================================================
//====================== Register Names ==========================
//================================================================

static const char rv_ireg_name_sym[32][5] = {
    "zero", "ra",   "sp",   "gp",   "tp",   "t0",   "t1",   "t2",
    "s0",   "s1",   "a0",   "a1",   "a2",   "a3",   "a4",   "a5",
    "a6",   "a7",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
    "s8",   "s9",   "s10",  "s11",  "t3",   "t4",   "t5",   "t6",
};

static const char rv_freg_name_sym[32][5] = {
    "ft0",  "ft1",  "ft2",  "ft3",  "ft4",  "ft5",  "ft6",  "ft7",
    "fs0",  "fs1",  "fa0",  "fa1",  "fa2",  "fa3",  "fa4",  "fa5",
    "fa6",  "fa7",  "fs2",  "fs3",  "fs4",  "fs5",  "fs6",  "fs7",
    "fs8",  "fs9",  "fs10", "fs11", "ft8",  "ft9",  "ft10", "ft11",
};

static void print_decoded(command_data *cd)
{
    char tmp[80] = {0};
    char *tmp_ptr = tmp;
    const char *read_ptr;
    const char *fmt;

    fmt = opcode_data[(*cd).opcode].format;
    while (*fmt) {
        switch (*fmt) {
        case 'O':
            read_ptr = opcode_data[(*cd).opcode].name;
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }            
            break;
        case '(':
            *tmp_ptr = '(';
            tmp_ptr++;
            break;
        case ',':
            *tmp_ptr = ',';
            tmp_ptr++;
            break;
        case ')':
            *tmp_ptr = ')';
            tmp_ptr++;
            break;
        case '0':
            read_ptr = rv_ireg_name_sym[(*cd).rd];
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }            
            break;
        case '1':
            read_ptr = rv_ireg_name_sym[(*cd).rs1];
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }            
            break;
        case '2':
            read_ptr = rv_ireg_name_sym[(*cd).rs2];
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }            
            break;
        case '3':
            read_ptr = rv_ireg_name_sym[(*cd).rd];
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }            
            break;
        case '4':
            read_ptr = rv_freg_name_sym[(*cd).rs1];
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }            
            break;
        case '5':
            read_ptr = rv_freg_name_sym[(*cd).rs2];
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }            
            break;
        case '6':
            read_ptr = rv_freg_name_sym[(*cd).rs3];
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }            
            break;
        case '7':
            snprintf(tmp_ptr, 16, "%d", (*cd).rs1);
            while (*tmp_ptr)
            {
                tmp_ptr++;
            }            
            break;
        case 'i':
            snprintf(tmp_ptr, 16, "%d", (*cd).imm);
            while (*tmp_ptr)
            {
                tmp_ptr++;
            }
            break;
        case 'o':
            snprintf(tmp_ptr, 16, "0x%lx", (*cd).imm + (*cd).offset);
            while (*tmp_ptr)
            {
                tmp_ptr++;
            }
            break;
        case 'c': {
            read_ptr = csr_name((*cd).imm & 0xfff);
            if (read_ptr) {
                while (read_ptr)
                {
                    *tmp_ptr = *read_ptr;
                    tmp_ptr++;
                    read_ptr++;
                }
                
            } else {
                snprintf(tmp_ptr, 6, "0x%03x", (*cd).imm & 0xfff);
                while (*tmp_ptr)
                {
                    tmp_ptr++;
                }
            }
            break;
        }
        case 'r':
            switch ((*cd).rm) {
            case rv_rm_rne:
                read_ptr = "rne";
                while (*read_ptr)
                {
                    *tmp_ptr = *read_ptr;
                    tmp_ptr++;
                    read_ptr++;
                }            
                break;
            case rv_rm_rtz:
                read_ptr = "rtz";
                while (*read_ptr)
                {
                    *tmp_ptr = *read_ptr;
                    tmp_ptr++;
                    read_ptr++;
                }            
                break;
            case rv_rm_rdn:
                read_ptr = "rdn";
                while (*read_ptr)
                {
                    *tmp_ptr = *read_ptr;
                    tmp_ptr++;
                    read_ptr++;
                }            
                break;
            case rv_rm_rup:
                read_ptr = "rup";
                while (*read_ptr)
                {
                    *tmp_ptr = *read_ptr;
                    tmp_ptr++;
                    read_ptr++;
                }            
                break;
            case rv_rm_rmm:
                read_ptr = "rmm";
                while (*read_ptr)
                {
                    *tmp_ptr = *read_ptr;
                    tmp_ptr++;
                    read_ptr++;
                }            
                break;
            case rv_rm_dyn:
                read_ptr = "dyn";
                while (*read_ptr)
                {
                    *tmp_ptr = *read_ptr;
                    tmp_ptr++;
                    read_ptr++;
                }            
                break;
            default:
                read_ptr = "inv";
                while (*read_ptr)
                {
                    *tmp_ptr = *read_ptr;
                    tmp_ptr++;
                    read_ptr++;
                }            
                break;
            }
            break;
        case 'p':
            if ((*cd).pred & rv_fence_i) {
                *tmp_ptr = 'i';
                tmp_ptr++;
            }
            if ((*cd).pred & rv_fence_o) {
                *tmp_ptr = 'o';
                tmp_ptr++;
            }
            if ((*cd).pred & rv_fence_r) {
                *tmp_ptr = 'r';
                tmp_ptr++;
            }
            if ((*cd).pred & rv_fence_w) {
                *tmp_ptr = 'W';
                tmp_ptr++;
            }
            break;
        case 's':
            if ((*cd).succ & rv_fence_i) {
                *tmp_ptr = 'i';
                tmp_ptr++;
            }
            if ((*cd).succ & rv_fence_o) {
                *tmp_ptr = 'o';
                tmp_ptr++;
            }
            if ((*cd).succ & rv_fence_r) {
                *tmp_ptr = 'r';
                tmp_ptr++;
            }
            if ((*cd).succ & rv_fence_w) {
                *tmp_ptr = 'w';
                tmp_ptr++;
            }
            break;
        case '\t':
            *tmp_ptr = '\t';
            tmp_ptr++;
            break;
        case 'A':
            read_ptr = ".aq";
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }
            break;
        case 'R':
            read_ptr = ".rl";
            while (*read_ptr)
            {
                *tmp_ptr = *read_ptr;
                tmp_ptr++;
                read_ptr++;
            }
            break;
        default:
            break;
        }
        fmt++;
    }
    printf("0x%.8x\t", (*cd).offset);
    printf("%s\n", tmp);
}

//================================================================
//======================= Main Function ==========================
//================================================================

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <hex_file> <rv32/rv64/rv128>\n", argv[0]);
        goto error;
    }

    if ((strcmp(argv[2], "rv32") != 0) && (strcmp(argv[2], "rv64") != 0) && (strcmp(argv[2], "rv128") != 0)) {
        printf("Usage: %s <hex_file> <rv32/rv64/rv128>\n", argv[0]);
        goto error;
    }

    FILE *input;
    if ((input = fopen(argv[1], "rb")) == NULL) {
        printf("Can't open file.\n");
        goto error;
    }

    hex_string h_str;
    //MAKE SURE
    h_str.cur_ptr = 0;
    h_str.destruct_flag = 0;

    //FIND START OFFSET
    uint16_t r_cs = 0;
    uint16_t r_ip = 0;

    while (h_str.flags != 0x01 && feof(input) == 0)
    {
        if (h_str.flags == 0x03) {
            r_cs = h_str.data[0] << 8;
            r_cs += h_str.data[1];
            r_ip = h_str.data[2] << 8;
            r_ip += h_str.data[3];
            break;
        }
        if (read_next_str(&h_str, input)) {
            goto error_while_file_read;
        }
    }
    
    if (r_cs == 0 && r_ip == 0) {
        goto error_while_file_read;
    }

    if(find_offset(&h_str, input, r_ip)) {
        goto error_while_file_read;
    }

    command_data cd;
    if (strcmp(argv[2], "rv32") == 0) {
        cd.pc = rv32;
    } else if (strcmp(argv[2], "rv64") == 0) {
        cd.pc = rv64;
    } else if (strcmp(argv[2], "rv128") == 0) {
        cd.pc = rv128;
    } else {
        goto error_while_file_read;
    }

    printf("OFFSET\t\tCOMMAND\n");

    cd.offset = h_str.offset + h_str.cur_ptr;
    while ((cd.byte_data = get_next_command(&h_str, input)) != 0)
    {
        bp_opcode(&cd);
        if (opcode_data[cd.opcode].parse_func != NULL) {
            opcode_data[cd.opcode].parse_func(&cd);
            print_decoded(&cd);
        }
        cd.offset = h_str.offset + h_str.cur_ptr;
    }
    

    fclose(input);
    return 0;

    error_while_file_read:
    printf("ERROR: ERROR WHILE FILE READ\n");
    fclose(input);
    error:
    return 1;
}

//================================================================
//================================================================
//================================================================
// GET HEX BYTE FROM .HEX FILE STRING
uint8_t fgetc_hex(FILE *file) {
    uint8_t hex = 0;
    hex = str_byte_to_hex(fgetc(file)) << 4;
    hex += str_byte_to_hex(fgetc(file));
    return hex;
}

// GET HEX STRING FROM .HEX FILE STRING
uint8_t fgets_hex(uint8_t* buf, size_t num, FILE *file) {
    for (size_t i = 0; i < num; i++) {
        *buf = fgetc_hex(file);
        buf++;
    }
}

// TRANSLATE .HEX FILE STRING BYTE(2 char) TO HEX FORMAT
uint8_t str_byte_to_hex(uint8_t str_byte) {
    if ((0x30 <= str_byte) && (str_byte <= 0x39)) {
        return str_byte - 0x30;
    } else if ((0x41 <= str_byte) && (str_byte <= 0x46)) {
        return str_byte - 0x37;
    } else if ((0x61 <= str_byte) && (str_byte <= 0x66)) {
        return str_byte - 0x57;
    }
}

uint32_t get_next_command(hex_string *h_str, FILE *file) {

    uint32_t data = 0;
    uint8_t num_of_bytes_to_read;
    if ((*h_str).cur_ptr == (*h_str).length) {
        read_next_str(h_str, file);
    }
    data = (*h_str).data[(*h_str).cur_ptr];
    (*h_str).cur_ptr = (*h_str).cur_ptr + 1;


    if ((data & 0b11) != 0b11)
    {
        num_of_bytes_to_read = 2;
    } else {
        num_of_bytes_to_read = 4;
    }

    for (int i = 1; i < num_of_bytes_to_read; i++) {
        if ((*h_str).cur_ptr == (*h_str).length) {
            read_next_str(h_str, file);
        }
        data += ((*h_str).data[(*h_str).cur_ptr]) << (8 * i);
        (*h_str).cur_ptr = (*h_str).cur_ptr + 1;
    }

    switch (data)
    {
    case 0b01:
        (*h_str).destruct_flag = 1;
        break;
    case 0b10:
        if ((*h_str).destruct_flag == 1) {
            goto error;
        }
        break;
    case 0b00:
        printf("================END OF SEGMENT================\n");
        data = 0b101; // MAKE NOP INSTEAD OF ERROR
    default:
        (*h_str).destruct_flag = 0;
        break;
    }
        
    return data;

    error:
    return 0;
}

uint8_t read_next_str(hex_string* h_str, FILE *file) {
    if (((*h_str).legit = fgetc(file)) == ':')
    {
        (*h_str).length = fgetc_hex(file);
        (*h_str).offset = fgetc_hex(file) << 8;
        (*h_str).offset += fgetc_hex(file);
        (*h_str).flags = fgetc_hex(file);
        fgets_hex((*h_str).data, (*h_str).length, file);
        (*h_str).checksum = fgetc_hex(file);
        (*h_str).cur_ptr = 0;
        // IGNORE '\n'
        while (fgetc(file) != 0x0a);
        return 0;
    }

    error:
    return 1;
}

uint8_t find_offset(hex_string *h_str, FILE *file, uint16_t offset) {
    fseek(file, 0, SEEK_SET);
    do {
        read_next_str(h_str, file);
        if ( ((*h_str).offset <= offset) && (((*h_str).offset + (*h_str).length) > offset)) {
            (*h_str).cur_ptr = offset - (*h_str).offset;
            return 0;
        }
    }   while (feof(file) == 0);
    fseek(file, 0, SEEK_SET);
    printf("ERROR: CAN'T FIND OFFSET");
    return 1;
}

void bp_opcode(command_data* cd) {
    rv_isa isa = (*cd).pc;
    rv_op op = op_illegal;
    uint32_t byte_data = (*cd).byte_data;
    
    switch (byte_data & 0b11)
    {
    // RVC Instruction Set Listings
    case 0b00:
        switch ((byte_data >> 13) & 0b111)
        {
        case 0b000: // 0b0000000000000000 parse via get_next_command()
            op = op_c_addi4spn;
            break;
        case 0b001:
            if (isa == rv128) {
                op = op_c_lq;
            } else {
                op = op_c_fld;
            }
            break;
        case 0b010:
            op = op_c_lw;
            break;
        case 0b011:
            if (isa = rv32) {
                op = op_c_flw;
            } else {
                op = op_c_ld;
            }
            break;
        case 0b101:
            if (isa = rv128) {
                op = op_c_sq;
            } else {
                op = op_c_fsd;
            }
            break;
        case 0b110:
            op = op_c_sw;
            break;
        case 0b111:
            if (isa = rv32) {
                op = op_c_fsw;
            } else {
                op = op_c_sd;
            }
            break;
        }
        break;
    case 0b01:
        switch ((byte_data >> 13) & 0b111) {
            case 0b000: // 0b0000000000000001 parse via get_next_command()
                switch ((byte_data >> 7) & 0b11111)
                {
                case 0b00000:
                    op = op_c_nop;
                    break;
                default:
                    op = op_c_addi;
                    break;
                }
                break;
            case 0b001:
                if (isa = rv32) {
                    op = op_c_jal;
                } else {
                    op = op_c_addiw;
                }
                break;
            case 0b010:
                op = op_c_li;
                break;
            case 0b011:
                switch ((byte_data >> 7) & 0b11111)
                {
                case 0b00010:
                    op = op_c_addi16sp;
                    break;
                default:
                    op = op_c_lui;
                    break;
                }
                break;
            case 0b100:
                switch ((byte_data >> 10) & 0b11)
                {
                case 0b00:
                    op = op_c_srli;
                    break;
                case 0b01:
                    op = op_c_srai;
                    break;
                case 0b10:
                    op = op_c_andi;
                    break;
                case 0b11:
                    switch (((byte_data >> 10) & 0b100) | ((byte_data >> 5) & 0b011))
                    {
                    case 0b000:
                        op = op_c_sub;
                        break;
                    case 0b001:
                        op = op_c_xor;
                        break;
                    case 0b010:
                        op = op_c_or;
                        break;
                    case 0b011:
                        op = op_c_and;
                        break;
                    case 0b100:
                        op = op_c_subw;
                        break;
                    case 0b101:
                        op = op_c_addw;
                        break;
                    }
                    break;
                }
                break;
            case 0b101:
                op = op_c_j;
                break;
            case 0b110:
                op = op_c_beqz;
                break;
            case 0b111:
                op = op_c_bnez;
                break;
        }
        break;
    case 0b10:
        switch ((byte_data >> 13) & 0b111)
        {
        case 0b000: // 0b0000000000000010 parse via get_next_command()
            op = op_c_slli;
            break;
        case 0b001:
            if (isa = rv128) {
                op = op_c_lqsp;
            } else {
                op = op_c_fldsp;
            }
            break;
        case 0b010:
            op = op_c_lwsp;
            break;
        case 0b011:
            if (isa = rv32) {
                op = op_c_flwsp;
            } else {
                op = op_c_ldsp;
            }
            break;
        case 0b100:
            switch ((byte_data >> 12) & 0b1)
            {
            case 0b0:
                op = (((byte_data >> 2) & 0b11111) == 0) ? op_c_jr : op_c_mv;
                break;
            case 0b1:
                switch ((byte_data >> 2) & 0b1111111111)
                {
                case 0b0000000000:
                    op = op_c_ebreak;
                    break;
                default:
                    op = (((byte_data >> 2) & 0b11111) == 0) ? op_c_jalr : op_c_add;
                    break;
                }
                break;
            }
            break;
        case 0b101:
            if (isa = rv128) {
                op = op_c_sqsp;
            } else {
                op = op_c_fsdsp;
            }
            break;
        case 0b110:
            op = op_c_swsp;
            break;
        case 0b111:
            if (isa = rv32) {
                op = op_c_fswsp;
            } else {
                op = op_c_sdsp;
            }
            break;
        }
        break;
    // RV32/64G Instruction Set Listings
    case 0b11:
        switch ((byte_data >> 2) & 0b11111)
        {
        case 0b01101:
            op = op_lui;
            break;
        case 0b00101:
            op = op_auipc;
            break;
        case 0b11011:
            op = op_jal;
            break;
        case 0b11001:
            op = op_jalr;
            break;
        case 0b11000:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                op = op_beq;
                break;
            case 0b001:
                op = op_bne;
                break;
            case 0b100:
                op = op_blt;
                break;
            case 0b101:
                op = op_bge;
                break;
            case 0b110:
                op = op_bltu;
                break;
            case 0b111:
                op = op_bgeu;
                break;
            }
            break;
        case 0b00000:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                op = op_lb;
                break;
            case 0b001:
                op = op_lh;
                break;
            case 0b010:
                op = op_lw;
                break;
            case 0b011:
                op = op_ld;
                break;
            case 0b100:
                op = op_lbu;
                break;
            case 0b101:
                op = op_lhu;
                break;
            case 0b110:
                op = op_lwu;
                break;
            }
            break;
        case 0b01000:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                op = op_sb;
                break;
            case 0b001:
                op = op_sh;
                break;
            case 0b010:
                op = op_sw;
                break;
            case 0b011:
                op = op_sd;
                break;
            }
            break;
        case 0b00100:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                op = op_addi;
                break;
            case 0b010:
                op = op_slti;
                break;
            case 0b011:
                op = op_sltiu;
                break;
            case 0b100:
                op = op_xori;
                break;
            case 0b110:
                op = op_ori;
                break;
            case 0b111:
                op = op_andi;
                break;
            case 0b001:
                op = op_slli;
                break;
            case 0b101:
                op = (((byte_data >> 30) & 0b1) == 0b0) ? op_srli : op_srai;
                break;
            }
            break;
        case 0b01100:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_add;
                    break;
                case 0b0100000:
                    op = op_sub;
                    break;
                case 0b0000001:
                    op = op_mul;
                    break;
                }
                break;
            case 0b001:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_sll;
                    break;
                case 0b0000001:
                    op = op_mulh;
                    break;
                }
                break;
            case 0b010:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_slt;
                    break;
                case 0b0000001:
                    op = op_mulhsu;
                    break;
                }
                break;
            case 0b011:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_sltu;
                    break;
                case 0b0000001:
                    op = op_mulhu;
                    break;
                }
                break;
            case 0b100:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_xor;
                    break;
                case 0b0000001:
                    op = op_div;
                    break;
                }
                break;
            case 0b101:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_srl;
                    break;
                case 0b0100000:
                    op = op_sra;
                    break;
                case 0b0000001:
                    op = op_divu;
                    break;
                }
                break;
            case 0b110:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_or;
                    break;
                case 0b0000001:
                    op = op_rem;
                    break;
                }
                break;
            case 0b111:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_and;
                    break;
                case 0b0000001:
                    op = op_remu;
                    break;
                }
                break;
            }
            break;
        case 0b00011:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                op = op_fence;
                break;
            default:
                op = op_fence_i;
                break;
            }
            break;
        case 0b11100:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                switch ((byte_data >> 20) & 0b111111111111)
                {
                case 0b000000000000:
                    op = op_ecall;
                    break;
                case 0b000000000001:
                    op = op_ebreak;
                    break;
                case 0b000000001101:
                    op = op_wrs_nto;
                    break;
                case 0b000000011101:
                    op = op_wrs_sto;
                    break;
                }
                break;
            case 0b001:
                op = op_csrrw;
                break;
            case 0b010:
                op = op_csrrs;
                break;
            case 0b011:
                op = op_csrrc;
                break;
            case 0b101:
                op = op_csrrwi;
                break;
            case 0b110:
                op = op_csrrsi;
                break;
            case 0b111:
                op = op_csrrci;
                break;
            }
            break;
        case 0b00110:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                op = op_addiw;
                break;
            case 0b001:
                op = op_slliw;
                break;
            case 0b101:
                op = (((byte_data >> 30) & 0b1) == 0) ? op_srliw : op_sraiw;
                break;
            }
            break;
        case 0b01110:
            switch ((byte_data >> 12) & 0b111)
            {
            case 0b000:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_addw;
                    break;
                case 0b0100000:
                    op = op_subw;
                    break;
                case 0b0000001:
                    op = op_mulw;
                    break;
                }
                break;
            case 0b001:
                op = op_sllw;
                break;
            case 0b100:
                op = op_divw;
                break;
            case 0b101:
                switch ((byte_data >> 25) & 0b1111111)
                {
                case 0b0000000:
                    op = op_srlw;
                    break;
                case 0b0100000:
                    op = op_sraw;
                    break;
                case 0b0000001:
                    op = op_divuw;
                    break;
                }
                break;
            case 0b110:
                op = op_remw;
                break;
            case 0b111:
                op = op_remuw;
                break;
            }
            break;
        case 0b01011:
            switch ((byte_data >> 12) & 0b111)
            {
                case 0b010:
                    switch ((byte_data >> 27) & 0b11111)
                    {
                    case 0b00010:
                        op = op_lr_w;
                        break;
                    case 0b00011:
                        op = op_sc_w;
                        break;
                    case 0b00001:
                        op = op_amoswap_w;
                        break;
                    case 0b00000:
                        op = op_amoadd_w;
                        break;
                    case 0b00100:
                        op = op_amoxor_w;
                        break;
                    case 0b01100:
                        op = op_amoand_w;
                        break;
                    case 0b01000:
                        op = op_amoor_w;
                        break;
                    case 0b10000:
                        op = op_amomin_w;
                        break;
                    case 0b10100:
                        op = op_amomax_w;
                        break;
                    case 0b11000:
                        op = op_amominu_w;
                        break;
                    case 0b11100:
                        op = op_amomaxu_w;
                        break;
                    }
                    break;
                case 0b011:
                    switch ((byte_data >> 27) & 0b11111)
                    {
                    case 0b00010:
                        op = op_lr_d;
                        break;
                    case 0b00011:
                        op = op_sc_d;
                        break;
                    case 0b00001:
                        op = op_amoswap_d;
                        break;
                    case 0b00000:
                        op = op_amoadd_d;
                        break;
                    case 0b00100:
                        op = op_amoxor_d;
                        break;
                    case 0b01100:
                        op = op_amoand_d;
                        break;
                    case 0b01000:
                        op = op_amoor_d;
                        break;
                    case 0b10000:
                        op = op_amomin_d;
                        break;
                    case 0b10100:
                        op = op_amomax_d;
                        break;
                    case 0b11000:
                        op = op_amominu_d;
                        break;
                    case 0b11100:
                        op = op_amomaxu_d;
                        break;
                    }
                    break;
            }
            break;
        case 0b00001:
            switch ((byte_data >> 12) & 0b111)
            {
                case 0b010:
                    op = op_flw;
                    break;
                case 0b011:
                    op = op_fld;
                    break;
                case 0b100:
                    op = op_flq;
                    break;
                case 0b001:
                    op = op_flh;
                    break;
            }
            break;
        case 0b01001:
            switch ((byte_data >> 12) & 0b111)
            {
                case 0b010:
                    op = op_fsw;
                    break;
                case 0b011:
                    op = op_fsd;
                    break;
                case 0b100:
                    op = op_fsq;
                    break;
                case 0b001:
                    op = op_fsh;
                    break;
            }
            break;
        case 0b10000:
            switch ((byte_data >> 25) & 0b11)
            {
                case 0b00:
                    op = op_fmadd_s;
                    break;
                case 0b01:
                    op = op_fmadd_d;
                    break;
                case 0b11:
                    op = op_fmadd_q;
                    break;
                case 0b10:
                    op = op_fmadd_h;
                    break;
            }
            break;
        case 0b10001:
            switch ((byte_data >> 25) & 0b11)
            {
                case 0b00:
                    op = op_fmsub_s;
                    break;
                case 0b01:
                    op = op_fmsub_d;
                    break;
                case 0b10:
                    op = op_fmsub_q;
                    break;
                case 0b11:
                    op = op_fmsub_h;
                    break;
            }
            break;
        case 0b10010:
            switch ((byte_data >> 25) & 0b11)
            {
                case 0b00:
                    op = op_fnmsub_s;
                    break;
                case 0b01:
                    op = op_fnmsub_d;
                    break;
                case 0b10:
                    op = op_fnmsub_q;
                    break;
                case 0b11:
                    op = op_fnmsub_h;
                    break;
            }
            break;
        case 0b10011:
            switch ((byte_data >> 25) & 0b11)
            {
                case 0b00:
                    op = op_fnmadd_s;
                    break;
                case 0b01:
                    op = op_fnmadd_d;
                    break;
                case 0b10:
                    op = op_fnmadd_q;
                    break;
                case 0b11:
                    op = op_fnmadd_h;
                    break;
            }
            break;
        case 0b10100:
            switch ((byte_data >> 27) & 0b11111)
            {
            case 0b00000:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    op = op_fadd_s;
                    break;
                case 0b01:
                    op = op_fadd_d;
                    break;
                case 0b11:
                    op = op_fadd_q;
                    break;
                case 0b10:
                    op = op_fadd_h;
                    break;
                }
                break;
            case 0b00001:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    op = op_fsub_s;
                    break;
                case 0b01:
                    op = op_fsub_d;
                    break;
                case 0b11:
                    op = op_fsub_q;
                    break;
                case 0b10:
                    op = op_fsub_h;
                    break;
                }
                break;
            case 0b00010:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    op = op_fmul_s;
                    break;
                case 0b01:
                    op = op_fmul_d;
                    break;
                case 0b11:
                    op = op_fmul_q;
                    break;
                case 0b10:
                    op = op_fmul_h;
                    break;
                }
                break;
            case 0b00011:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    op = op_fdiv_s;
                    break;
                case 0b01:
                    op = op_fdiv_d;
                    break;
                case 0b11:
                    op = op_fdiv_q;
                    break;
                case 0b10:
                    op = op_fdiv_h;
                    break;
                }
                break;
            case 0b01011:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    op = op_fsqrt_s;
                    break;
                case 0b01:
                    op = op_fsqrt_d;
                    break;
                case 0b11:
                    op = op_fsqrt_q;
                    break;
                case 0b10:
                    op = op_fsqrt_h;
                    break;
                }
                break;
            case 0b00100:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    switch ((byte_data >> 12) & 0b111)
                    {
                    case 0b000:
                        op = op_fsgnj_s;
                        break;
                    case 0b001:
                        op = op_fsgnjn_s;
                        break;
                    case 0b010:
                        op = op_fsgnjx_s;
                        break;
                    }
                    break;
                case 0b01:
                    switch ((byte_data >> 12) & 0b111)
                    {
                    case 0b000:
                        op = op_fsgnj_d;
                        break;
                    case 0b001:
                        op = op_fsgnjn_d;
                        break;
                    case 0b010:
                        op = op_fsgnjx_d;
                        break;
                    }
                    break;
                case 0b11:
                    switch ((byte_data >> 12) & 0b111)
                    {
                    case 0b000:
                        op = op_fsgnj_q;
                        break;
                    case 0b001:
                        op = op_fsgnjn_q;
                        break;
                    case 0b010:
                        op = op_fsgnjx_q;
                        break;
                    }
                    break;
                case 0b10:
                    switch ((byte_data >> 12) & 0b111)
                    {
                    case 0b000:
                        op = op_fsgnj_h;
                        break;
                    case 0b001:
                        op = op_fsgnjn_h;
                        break;
                    case 0b010:
                        op = op_fsgnjx_h;
                        break;
                    }
                    break;
                }
                break;
            case 0b00101:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    op = (((byte_data >> 12) & 0b111) == 0b000) ? op_fmin_s : op_fmax_s;
                    break;
                case 0b01:
                    op = (((byte_data >> 12) & 0b111) == 0b000) ? op_fmin_d : op_fmax_d;
                    break;
                case 0b11:
                    op = (((byte_data >> 12) & 0b111) == 0b000) ? op_fmin_q : op_fmax_q;
                    break;
                case 0b10:
                    op = (((byte_data >> 12) & 0b111) == 0b000) ? op_fmin_h : op_fmax_h;
                    break;
                }
                break;
            case 0b11100:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    op = (((byte_data >> 12) & 0b111) == 0b000) ? op_fmv_x_w : op_fclass_s;
                    break;
                case 0b01:
                    op = (((byte_data >> 12) & 0b111) == 0b000) ? op_fmv_x_d : op_fclass_d;
                    break;
                case 0b11:
                    op = op_fclass_q;
                    break;
                case 0b10:
                    op = (((byte_data >> 12) & 0b111) == 0b000) ? op_fmv_x_h : op_fclass_h;
                    break;
                }
                break;
            case 0b11110:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    op = op_fmv_w_x;
                    break;
                case 0b01:
                    op = op_fmv_d_x;
                    break;
                case 0b10:
                    op = op_fmv_h_x;
                    break;
                }
                break;
            case 0b10100:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    switch ((byte_data >> 12) & 0b111)
                    {
                    case 0b000:
                        op = op_fle_s;
                        break;
                    case 0b001:
                        op = op_flt_s;
                        break;
                    case 0b010:
                        op = op_feq_s;
                        break;
                    }
                    break;
                case 0b01:
                    switch ((byte_data >> 12) & 0b111)
                    {
                    case 0b000:
                        op = op_fle_d;
                        break;
                    case 0b001:
                        op = op_flt_d;
                        break;
                    case 0b010:
                        op = op_feq_d;
                        break;
                    }
                    break;
                case 0b11:
                    switch ((byte_data >> 12) & 0b111)
                    {
                    case 0b000:
                        op = op_fle_q;
                        break;
                    case 0b001:
                        op = op_flt_q;
                        break;
                    case 0b010:
                        op = op_feq_q;
                        break;
                    }
                    break;
                case 0b10:
                    switch ((byte_data >> 12) & 0b111)
                    {
                    case 0b000:
                        op = op_fle_h;
                        break;
                    case 0b001:
                        op = op_flt_h;
                        break;
                    case 0b010:
                        op = op_feq_h;
                        break;
                    }
                    break;
                }
                break;
            case 0b01000:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00001:
                        op = op_fcvt_s_d;
                        break;
                    case 0b00010:
                        op = op_fcvt_s_h;
                        break;
                    case 0b00011:
                        op = op_fcvt_s_q;
                        break;
                    }
                    break;
                case 0b01:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_d_s;
                        break;
                    case 0b00010:
                        op = op_fcvt_d_h;
                        break;
                    case 0b00011:
                        op = op_fcvt_d_q;
                        break;
                    }
                    break;
                case 0b11:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_q_s;
                        break;
                    case 0b00001:
                        op = op_fcvt_q_d;
                        break;
                    case 0b00010:
                        op = op_fcvt_q_h;
                        break;
                    }
                    break;
                case 0b10:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_h_s;
                        break;
                    case 0b00001:
                        op = op_fcvt_h_d;
                        break;
                    case 0b00011:
                        op = op_fcvt_h_q;
                        break;
                    }
                    break;
                }
                break;
            case 0b11000:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_w_s;
                        break;
                    case 0b00001:
                        op = op_fcvt_wu_s;
                        break;
                    case 0b00010:
                        op = op_fcvt_l_s;
                        break;
                    case 0b00011:
                        op = op_fcvt_lu_s;
                        break;
                    }
                    break;
                case 0b01:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_w_d;
                        break;
                    case 0b00001:
                        op = op_fcvt_wu_d;
                        break;
                    case 0b00010:
                        op = op_fcvt_l_d;
                        break;
                    case 0b00011:
                        op = op_fcvt_lu_d;
                        break;
                    }
                    break;
                case 0b11:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_w_q;
                        break;
                    case 0b00001:
                        op = op_fcvt_wu_q;
                        break;
                    case 0b00010:
                        op = op_fcvt_l_q;
                        break;
                    case 0b00011:
                        op = op_fcvt_lu_q;
                        break;
                    }
                    break;
                case 0b10:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_w_h;
                        break;
                    case 0b00001:
                        op = op_fcvt_wu_h;
                        break;
                    case 0b00010:
                        op = op_fcvt_l_h;
                        break;
                    case 0b00011:
                        op = op_fcvt_lu_h;
                        break;
                    }
                    break;
                }
                break;
            case 0b11010:
                switch ((byte_data >> 25) & 0b11)
                {
                case 0b00:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_s_w;
                        break;
                    case 0b00001:
                        op = op_fcvt_s_wu;
                        break;
                    case 0b00010:
                        op = op_fcvt_s_l;
                        break;
                    case 0b00011:
                        op = op_fcvt_s_lu;
                        break;
                    }
                    break;
                case 0b01:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_d_w;
                        break;
                    case 0b00001:
                        op = op_fcvt_d_wu;
                        break;
                    case 0b00010:
                        op = op_fcvt_d_l;
                        break;
                    case 0b00011:
                        op = op_fcvt_d_lu;
                        break;
                    }
                    break;
                case 0b11:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_q_w;
                        break;
                    case 0b00001:
                        op = op_fcvt_q_wu;
                        break;
                    case 0b00010:
                        op = op_fcvt_q_l;
                        break;
                    case 0b00011:
                        op = op_fcvt_q_lu;
                        break;
                    }
                    break;
                case 0b10:
                    switch ((byte_data >> 20) & 0b11111)
                    {
                    case 0b00000:
                        op = op_fcvt_h_w;
                        break;
                    case 0b00001:
                        op = op_fcvt_h_wu;
                        break;
                    case 0b00010:
                        op = op_fcvt_h_l;
                        break;
                    case 0b00011:
                        op = op_fcvt_h_lu;
                        break;
                    }
                    break;
                }
                break;
            }
            break;
        }
        break;
    }
    (*cd).opcode = op;
}