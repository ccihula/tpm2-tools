/* SPDX-License-Identifier: BSD-3-Clause */
#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_auth_util.h"
#include "tpm2_options.h"

typedef struct tpm_ecdhzgen_ctx tpm_ecdhzgen_ctx;
struct tpm_ecdhzgen_ctx {
    /*
     * Inputs
     */
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } ecc_key;

    TPM2B_ECC_POINT Q;
    const char *ecdh_pub_path;

    /*
     * Outputs
     */
    const char *ecdh_Z_path;
    TPM2B_ECC_POINT *Z;
};

static tpm_ecdhzgen_ctx ctx;

static tool_rc ecdhzgen(ESYS_CONTEXT *ectx) {

    return tpm2_ecdhzgen(ectx, &ctx.ecc_key.object, &ctx.Z, &ctx.Q);
}

static tool_rc process_outputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Outputs that do not require TPM2_CC_<command> dispatch
     */

    /*
     * 2. Outputs generated after TPM2_CC_<command> dispatch
     */
    bool is_file_op_success = files_save_ecc_point(ctx.Z, ctx.ecdh_Z_path);
    if (!is_file_op_success) {
        LOG_ERR("Failed to write out the public");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc process_inputs(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);
    /*
     * 1. Object and auth initializations
     */

    /*
     * 1.a Add the new-auth values to be set for the object.
     */

    /*
     * 1.b Add object names and their auth sessions
     */
    tool_rc  rc = tpm2_util_object_load_auth(ectx, ctx.ecc_key.ctx_path,
        ctx.ecc_key.auth_str, &ctx.ecc_key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to load object/ auth");
        return rc;
    }
    /*
     * 2. Restore auxiliary sessions
     */

    /*
     * 3. Command specific initializations
     */
    bool is_file_op_success = true;
    is_file_op_success = files_load_ecc_point(ctx.ecdh_pub_path, &ctx.Q);
    if (!is_file_op_success) {
        LOG_ERR("Failed to load public input ECC point Q");
        return tool_rc_general_error;
    }
    /*
     * 4. Configuration for calculating the pHash
     */

    /*
     * 4.a Determine pHash length and alg
     */

    /*
     * 4.b Determine if TPM2_CC_<command> is to be dispatched
     */

    return rc;
}

static tool_rc check_options(void) {

    if (!ctx.ecc_key.ctx_path) {
        LOG_ERR("Specify an ecc public key handle for context");
        return tool_rc_option_error;
    }

    if (!ctx.ecdh_Z_path) {
        LOG_ERR("Specify path to save the ecdh secret or Z point");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static bool on_option(char key, char *value) {

    switch (key) {

        case 'c':
            ctx.ecc_key.ctx_path = value;
            break;
        case 'p':
            ctx.ecc_key.auth_str = value;
            break;
        case 'u':
            ctx.ecdh_pub_path = value;
            break;
        case 'o':
            ctx.ecdh_Z_path = value;
            break;
    };

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "key-context", required_argument, 0, 'c' },
      { "key-auth",    required_argument, 0, 'p' },
      { "public",      required_argument, 0, 'u' },
      { "output",      required_argument, 0, 'o' },
    };

    *opts = tpm2_options_new("c:p:u:o:", ARRAY_LEN(topts), topts,
            on_option, 0, 0);

    return *opts != 0;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    /*
     * 1. Process options
     */
    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 2. Process inputs
     */
    rc = process_inputs(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 3. TPM2_CC_<command> call
     */
    rc = ecdhzgen(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    /*
     * 4. Process outputs
     */
    return process_outputs(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {

    UNUSED(ectx);

    /*
     * 1. Free objects
     */

    /*
     * 2. Close authorization sessions
     */

    /*
     * 3. Close auxiliary sessions
     */

    return tool_rc_success;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("ecdhzgen", tpm2_tool_onstart, tpm2_tool_onrun,
    tpm2_tool_onstop, 0)
