/* packet-secio.c
 * Routines for Secure I/O dissection
 * Copyright 201x, Maciej Krüger <mkg20001@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * (A short description of the protocol including links to specifications,
 *  detailed documentation, etc.)
 */

#include <config.h>

#if 0
/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */
#include <protos/secio.pb-c.h>
#include <secio.offset.h>
#include <protos/key.pb-c.h>
#include <epan/conversation.h>
#include <stdio.h>
#include "length-prefixed.h"
#include "addr-pair.h"
#include "proto-util.h"

#if 0
/* IF AND ONLY IF your protocol dissector exposes code to other dissectors
 * (which most dissectors don't need to do) then the 'public' prototypes and
 * data structures can go in the header file packet-secio.h. If not, then
 * a header file is not needed at all and this #include statement can be
 * removed. */
#include "packet-secio.h"
#endif

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_secio(void);
void proto_register_secio(void);

/* Initialize the protocol and registered fields */
static int proto_secio = -1;
static int hf_secio_dialer = -1;
static int hf_secio_listener = -1;
static int hf_secio_handshake = -1;
static int hf_secio_data = -1;
static int hf_secio_propose = -1;
static int hf_secio_propose_rand = -1;
static int hf_secio_propose_pubkey = -1;
static int hf_secio_propose_exchanges = -1;
static int hf_secio_propose_ciphers = -1;
static int hf_secio_propose_hashes = -1;
static int hf_secio_exchange = -1;
static int hf_secio_version = -1;
static expert_field ei_secio_pbuf_error = EI_INIT;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_hex = FALSE;
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
#define secio_TCP_PORT 4001
static guint tcp_port_pref = secio_TCP_PORT;

/* Initialize the subtree pointers */
static gint ett_secio = -1;
static gint ett_propose = -1;
static gint ett_exchange = -1;

typedef struct _secio_conv_info_t {
    addr_pair* dialer;
    struct _secio_conn_state_t* dialerState;
    addr_pair* listener;
    struct _secio_conn_state_t* listenerState;
    gboolean handshaked;
} secio_conv_info_t;

typedef struct _secio_conn_state_t {
    Propose* propose;
    guint32 proposePacket;
    Exchange* exchange;
    guint32 exchangePacket;
    PublicKey* key;
    PublicKey* ekey;
    PrivateKey* ePrivKey; // from key dump
    gchar* sharedSecret; // from key dump
} secio_conn_state_t;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define secio_MIN_LENGTH 8

/* Code to actually dissect the packets */
static int
dissect_secio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
              void *data _U_)
{
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti; //, *expert_ti;
  proto_tree *secio_tree;
  /* Other misc. local variables. */
  // guint       offset = 0;
  int         len    = tvb_captured_length(tvb);
#if 0
  /*** HEURISTICS ***/

    /* First, if at all possible, do some heuristics to check if the packet
     * cannot possibly belong to your protocol.  This is especially important
     * for protocols directly on top of TCP or UDP where port collisions are
     * common place (e.g., even though your protocol uses a well known port,
     * someone else may set up, for example, a web server on that port which,
     * if someone analyzed that web server's traffic in Wireshark, would result
     * in Wireshark handing an HTTP packet to your dissector).
     *
     * For example:
     */

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < secio_MIN_LENGTH)
        return 0;

    /* Check that there's enough data present to run the heuristics. If there
     * isn't, reject the packet; it will probably be dissected as data and if
     * the user wants it dissected despite it being short they can use the
     * "Decode-As" functionality. If your heuristic needs to look very deep into
     * the packet you may not want to require *all* data to be present, but you
     * should ensure that the heuristic does not access beyond the captured
     * length of the packet regardless. */
    if (tvb_captured_length(tvb) < MAX_NEEDED_FOR_HEURISTICS)
        return 0;

    /* Fetch some values from the packet header using tvb_get_*(). If these
     * values are not valid/possible in your protocol then return 0 to give
     * some other dissector a chance to dissect it. */
    if ( TEST_HEURISTICS_FAIL )
        return 0;
#endif

  /* Set the Protocol column to the constant string of secio */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "secio");

  conversation_t *conversation = find_or_create_conversation(pinfo);
  secio_conv_info_t* conv = (secio_conv_info_t *)conversation_get_proto_data(conversation, proto_secio);
  if (!conv) {
    conv = wmem_new(wmem_file_scope(), secio_conv_info_t);
    conv->dialer = NULL;
    conv->listener = NULL;
  }

  gboolean listener = 0;
  gboolean dialer = 0;
  secio_conn_state_t *state = NULL;

  if (conv->listener && addrpair_cmp(pinfo, conv->listener)) listener = 1;
  if (conv->dialer && addrpair_cmp(pinfo, conv->dialer)) dialer = 1;

  if (!conv->handshaked) {
    if (!conv->listener && !listener && !dialer) {
      conv->listener = addrpair_create(wmem_file_scope(), pinfo);
      listener = 1;
    }

    if (!conv->dialer && !listener && !dialer && !addrpair_cmp(pinfo, conv->dialer)) {
      conv->dialer = addrpair_create(wmem_file_scope(), pinfo);
      dialer = 1;
    }
  }

  if (!dialer && !listener) {
    // fprintf(stderr, "Could not determine listener/dialer");
    return 0;
  }

  if (dialer) state = conv->dialerState;
  else state = conv->listenerState;

  if (!state) {
    state = wmem_new(wmem_file_scope(), secio_conn_state_t);
    state->proposePacket = 0;
    state->exchangePacket = 0;
    if (dialer) conv->dialerState = state;
    else conv->listenerState = state;
  }

  if (!conv->handshaked) {
    int bytesCount;
    gchar* buf;
    if (!state->proposePacket) {
      buf = lp_decode_fixed(tvb, 0, 4, &bytesCount);
      if (!buf) {
        pinfo->desegment_len = (guint32)bytesCount - len;
      } else {
        guint8* pbData = tvb_get_raw_string(wmem_packet_scope(), tvb, 4, bytesCount - 4);
        state->proposePacket = pinfo->num;
        state->propose = propose__unpack(pbuf_alloc(wmem_file_scope()), (size_t)bytesCount - 4, pbData);
        if (state->propose && state->propose->has_pubkey) {
          state->key = public_key__unpack(pbuf_alloc(wmem_file_scope()), state->propose->pubkey.len, state->propose->pubkey.data);
        }
      }
    } else if (!state->exchangePacket) {
      buf = lp_decode_fixed(tvb, 0, 4, &bytesCount);
      if (!buf) {
        pinfo->desegment_len = (guint32)bytesCount - len;
      } else {
        guint8* pbData = tvb_get_raw_string(wmem_packet_scope(), tvb, 4, bytesCount - 4);
        state->exchangePacket = pinfo->num;
        state->exchange = exchange__unpack(pbuf_alloc(wmem_file_scope()), (size_t)bytesCount - 4, pbData);
        if (state->exchange && state->exchange->has_epubkey) {
          state->ekey = public_key__unpack(pbuf_alloc(wmem_file_scope()), state->exchange->epubkey.len, state->exchange->epubkey.data);
        }
      }
    }
  }

  if (conv->handshaked && pinfo->num != state->proposePacket && pinfo->num != state->exchangePacket) {
    gchar* buf;
    int bytesCount;
    buf = lp_decode_fixed(tvb, 0, 4, &bytesCount);
    if (!buf) {
      pinfo->desegment_len = (guint32)bytesCount - len;
    } else {
      // guint8* encData = tvb_get_raw_string(wmem_packet_scope(), tvb, 4, bytesCount - 4);
    }
  }

  /*** COLUMN DATA ***/

  /* There are two normal columns to fill in: the 'Protocol' column which
   * is narrow and generally just contains the constant string 'multistream',
   * and the 'Info' column which can be much wider and contain misc. summary
   * information (for example, the port number for TCP packets).
   *
   * If you are setting the column to a constant string, use "col_set_str()",
   * as it's more efficient than the other "col_set_XXX()" calls.
   *
   * If
   * - you may be appending to the column later OR
   * - you have constructed the string locally OR
   * - the string was returned from a call to val_to_str()
   * then use "col_add_str()" instead, as that takes a copy of the string.
   *
   * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
   * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
   * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
   * more efficient than "col_add_fstr()".
   *
   * For full details see section 1.4 of README.dissector.
   */

  if (!pinfo->desegment_len) {
    if (pinfo->num == state->proposePacket) {
      col_set_str(pinfo->cinfo, COL_INFO, "SECIO Propose");
    } else if (pinfo->num == state->exchangePacket) {
      col_set_str(pinfo->cinfo, COL_INFO, "SECIO Exchange");
    } else if (conv->handshaked) {
      col_set_str(pinfo->cinfo, COL_INFO, "SECIO Data");
    }
  }

  /*** PROTOCOL TREE ***/

  /* Now we will create a sub-tree for our protocol and start adding fields
   * to display under that sub-tree. Most of the time the only functions you
   * will need are proto_tree_add_item() and proto_item_add_subtree().
   *
   * NOTE: The offset and length values in the call to proto_tree_add_item()
   * define what data bytes to highlight in the hex display window when the
   * line in the protocol tree display corresponding to that item is selected.
   *
   * Supplying a length of -1 tells Wireshark to highlight all data from the
   * offset to the end of the packet.
   */

  if (tree && !pinfo->desegment_len) {
    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_secio, tvb, 0, -1, ENC_NA);

    secio_tree = proto_item_add_subtree(ti, ett_secio);

    proto_item* hidden = NULL;
    if (dialer) {
      hidden = proto_tree_add_boolean(secio_tree, hf_secio_dialer, tvb, 0, 0, 1);
    }
    if (listener) {
      hidden = proto_tree_add_boolean(secio_tree, hf_secio_listener, tvb, 0, 0, 1);
    }
    if (hidden) {
      PROTO_ITEM_SET_HIDDEN(hidden);
      PROTO_ITEM_SET_GENERATED(hidden);
    }

    if (pinfo->num == state->proposePacket) {
      if (state->propose) {
        // TODO: add _real_ tvb positions
        ProposeCount* count = countPropose(4, state->propose);
        proto_tree *propose_tree = proto_item_add_subtree(proto_tree_add_boolean(secio_tree, hf_secio_propose, tvb, 4, len - 4, 1), ett_propose);
        proto_tree_add_bytes(propose_tree, hf_secio_propose_rand, tvb, (gint)(count->off_rand + (count->len_rand - state->propose->rand.len)), (gint)state->propose->rand.len, state->propose->rand.data); // TODO: fix this
        proto_tree_add_boolean(propose_tree, hf_secio_propose_pubkey, tvb, (gint)count->off_pubkey, (gint)count->len_pubkey, 1); // TODO: extend this
        proto_tree_add_string(propose_tree, hf_secio_propose_exchanges, tvb, (gint)count->off_pubkey, (gint)count->len_pubkey, state->propose->exchanges);
        proto_tree_add_string(propose_tree, hf_secio_propose_ciphers, tvb, (gint)count->off_pubkey, (gint)count->len_pubkey, state->propose->ciphers);
        proto_tree_add_string(propose_tree, hf_secio_propose_hashes, tvb, (gint)count->off_pubkey, (gint)count->len_pubkey, state->propose->hashes);
      } else {
        expert_add_info(pinfo, proto_tree_add_item(secio_tree, hf_secio_data, tvb, 4, -1, ENC_NA), &ei_secio_pbuf_error);
      }
    } else if (pinfo->num == state->exchangePacket) {
      if (state->exchange) {
        // TODO: add
      } else {
        expert_add_info(pinfo, proto_tree_add_item(secio_tree, hf_secio_data, tvb, 4, -1, ENC_NA), &ei_secio_pbuf_error);
      }
    } else if (conv->handshaked) {
      proto_tree_add_item(secio_tree, hf_secio_data, tvb, 0, -1, ENC_NA);
    }
  }

  conversation_add_proto_data(conversation, proto_secio, conv);

  /* Continue adding tree items to process the packet here... */

  /* If this protocol has a sub-dissector call it here, see section 1.8 of
   * README.dissector for more information. */

  /* Return the amount of data this dissector was able to dissect (which may
   * or may not be the total captured packet as we return here). */
  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_secio(void)
{
  module_t        *secio_module;
  expert_module_t *expert_secio;

  /* Setup list of header fields  See Section 1.5 of README.dissector for
   * details. */
  static hf_register_info hf[] = {
          { &hf_secio_dialer,
                  { "Dialer",    "secio.dialer",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "TRUE if the packet is sent from the dialer", HFILL }},
          { &hf_secio_listener,
                  { "Listener",    "secio.listener",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "TRUE if the packet is sent from the listener", HFILL }},
          { &hf_secio_handshake,
                  { "Handshake",    "secio.handshake",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "TRUE if the packet is part of the handshake process", HFILL }},
          { &hf_secio_data,
                  { "Data",    "secio.data",
                          FT_BYTES,       BASE_NONE,      NULL,   0x0,
                          "Raw, decrypted bytes transferred (WIP)", HFILL }},
          { &hf_secio_propose,
                  { "Propose",    "secio.propose",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "Propose Request", HFILL }},
          { &hf_secio_propose_rand,
                  { "Random",    "secio.propose.rand",
                          FT_BYTES,       BASE_NONE,      NULL,   0x0,
                          "Propose Random bytes", HFILL }},
          { &hf_secio_propose_pubkey,
                  { "Public Key",    "secio.propose.pubkey",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "Propose Public key", HFILL }},
          { &hf_secio_propose_exchanges,
                  { "Exchanges",    "secio.propose.exchanges",
                          FT_STRING,       BASE_NONE,      NULL,   0x0,
                          "Propose Exchanges", HFILL }},
          { &hf_secio_propose_ciphers,
                  { "Ciphers",    "secio.propose.ciphers",
                          FT_STRING,       BASE_NONE,      NULL,   0x0,
                          "Propose Ciphers", HFILL }},
          { &hf_secio_propose_hashes,
                  { "Hashes",    "secio.propose.hashes",
                          FT_STRING,       BASE_NONE,      NULL,   0x0,
                          "Propose Hashes", HFILL }},
          { &hf_secio_exchange,
                  { "Exchange",    "secio.exchange",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "Exchange Request Data", HFILL }},
          { &hf_secio_version,
                  { "Version",    "secio.version",
                          FT_STRING,       BASE_NONE,      NULL,   0x0,
                          "SECIO version used", HFILL }}
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
          &ett_secio,
          &ett_propose,
          &ett_exchange
  };

  /* Setup protocol expert items */
  static ei_register_info ei[] = {
          { &ei_secio_pbuf_error, { "secio.protocolBuffers.malformed", PI_MALFORMED, PI_ERROR, "Protocol Buffers Object is malformed and couldn't be parsed", EXPFILL }}
  };

  /* Register the protocol name and description */
  proto_secio = proto_register_protocol("Libp2p Secure Input/Output",
                                        "Secure I/O", "secio");

  /* Required function calls to register the header fields and subtrees */
  proto_register_field_array(proto_secio, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Required function calls to register expert items */
  expert_secio = expert_register_protocol(proto_secio);
  expert_register_field_array(expert_secio, ei, array_length(ei));

  /* Register a preferences module (see section 2.6 of README.dissector
   * for more details). Registration of a prefs callback is not required
   * if there are no preferences that affect protocol registration (an example
   * of a preference that would affect registration is a port preference).
   * If the prefs callback is not needed, use NULL instead of
   * proto_reg_handoff_secio in the following.
   */
  secio_module = prefs_register_protocol(proto_secio,
                                         proto_reg_handoff_secio);
#if 0
  /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     *
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><Secure I/O>
     * preferences node.
     */
    secio_module = prefs_register_protocol_subtree(const char *subtree,
            proto_secio, proto_reg_handoff_secio);
#endif
  /* Register a simple example preference */
  prefs_register_bool_preference(secio_module, "show_hex",
                                 "Display numbers in Hex",
                                 "Enable to display numerical values in hexadecimal.",
                                 &pref_hex);

  /* Register an example port preference */
  prefs_register_uint_preference(secio_module, "tcp.port", "secio TCP Port",
                                 " secio TCP port if other than the default",
                                 10, &tcp_port_pref);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
void
proto_reg_handoff_secio(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t secio_handle;
  static int current_port;

  if (!initialized) {
    /* Use create_dissector_handle() to indicate that
     * dissect_secio() returns the number of bytes it dissected (or 0
     * if it thinks the packet does not belong to Secure I/O).
     */
    secio_handle = create_dissector_handle(dissect_secio,
                                           proto_secio);
    initialized = TRUE;

  } else {
    /* If you perform registration functions which are dependent upon
     * prefs then you should de-register everything which was associated
     * with the previous settings and re-register using the new prefs
     * settings here. In general this means you need to keep track of
     * the secio_handle and the value the preference had at the time
     * you registered.  The secio_handle value and the value of the
     * preference can be saved using local statics in this
     * function (proto_reg_handoff).
     */
    dissector_delete_uint("tcp.port", current_port, secio_handle);
  }

  current_port = tcp_port_pref;

  dissector_add_string("multistream.protocol", "/secio/1.0.0", secio_handle);
}

#if 0

/* Simpler form of proto_reg_handoff_secio which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_secio(void)
{
    dissector_handle_t secio_handle;

    /* Use create_dissector_handle() to indicate that dissect_secio()
     * returns the number of bytes it dissected (or 0 if it thinks the packet
     * does not belong to Secure I/O).
     */
    secio_handle = create_dissector_handle(dissect_secio,
            proto_secio);
    dissector_add_uint_with_preference("tcp.port", secio_TCP_PORT, secio_handle);
}
#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
