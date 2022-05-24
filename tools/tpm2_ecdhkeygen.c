/* SPDX-License-Identifier: BSD-3-Clause */
#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_options.h"

typedef struct tpm_ecdhkeygen_ctx tpm_ecdhkeygen_ctx;
struct tpm_ecdhkeygen_ctx {

    struct {
        const char *ctx_path;
        tpm2_loaded_object object;
    } ecc_public_key;

    const char *ecdh_pub_path;
    const char *ecdh_Z_path;

    TPM2B_ECC_POINT *Z;
    TPM2B_ECC_POINT *Q;

    char *cp_hash_path;
    TPM2B_DIGEST *cphash;
    TPM2B_DIGEST cp_hash;
    bool is_command_dispatch;

};

static tpm_ecdhkeygen_ctx ctx;

static bool on_option(char key, char *value) {

    switch (key) {

        case 'c':
            ctx.ecc_public_key.ctx_path = value;
            break;
        case 'u':
            ctx.ecdh_pub_path = value;
            break;
        case 'o':
            ctx.ecdh_Z_path = value;
            break;
        case 0:
            ctx.cp_hash_path = value;
        break;
    };

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static struct option topts[] = {
      { "context", required_argument, NULL, 'c' },
      { "public",  required_argument, NULL, 'u' },
      { "output",  required_argument, NULL, 'o' },
      { "cphash", required_argument, NULL, 0 },
    };

    *opts = tpm2_options_new("c:u:o:", ARRAY_LEN(topts), topts,
            on_option, NULL, 0);

    return *opts != 0;
}

static tool_rc check_options(void) {

    if (!ctx.ecc_public_key.ctx_path) {
        LOG_ERR("Specify an ecc public key handle for context");
        return tool_rc_option_error;
    }

    if (!ctx.ecdh_Z_path) {
        LOG_ERR("Specify path to save the ecdh secret or Z point");
        return tool_rc_option_error;
    }

    return tool_rc_success;
}

static tool_rc process_outputs(void) {

    bool is_file_op_success = true;
    if (ctx.cp_hash_path) {
        is_file_op_success = files_save_digest(&ctx.cp_hash, ctx.cp_hash_path);

        if (!is_file_op_success) {
            return tool_rc_general_error;
        }
    }

    tool_rc rc = tool_rc_success;
    if (!ctx.is_command_dispatch) {
        return rc;
    }

    bool result = files_save_ecc_point(ctx.Q, ctx.ecdh_pub_path);
    if (!result) {
        LOG_ERR("Failed to write out the public");
        return tool_rc_general_error;
    }

    result = files_save_ecc_point(ctx.Z, ctx.ecdh_Z_path);
    if (!result) {
        LOG_ERR("Failed to write out the public");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    // Check input options and arguments
    tool_rc rc = check_options();
    if (rc != tool_rc_success) {
        return rc;
    }

    // Process inputs
    rc = tpm2_util_object_load(ectx, ctx.ecc_public_key.ctx_path,
        &ctx.ecc_public_key.object,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        return rc;
    }

    // ESAPI call
    rc = tpm2_ecdhkeygen(ectx, &ctx.ecc_public_key.object, &ctx.Z, &ctx.Q);
    if (rc != tool_rc_success) {
        return rc;
    }

    // Process outputs
    rc = process_outputs();

    return rc;
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("ecdhkeygen", tpm2_tool_onstart, tpm2_tool_onrun, NULL, 0)
