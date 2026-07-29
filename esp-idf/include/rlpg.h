/* rlpg — RLPG mailbox node service.
 *
 * Hosts one or more RLPG mailbox destinations (aspect "rlpg.mailbox"), each
 * bound to a single served LXMF address by an owner-signed certificate.
 * Strangers deposit destination-encrypted LXMF messages; the owner picks
 * them up over an authenticated session on the same aspect. See
 * plans/RLPG.md in the workspace and the lxmf straddle's rlpg_wire.h for
 * the wire formats.
 */
#pragma once

#include "service.h"

class RlpgService : public Service {
public:
    void onInit() override;
};
