/* packet-multistream.c
 * Routines for Multistream 1.0.0 dissection
 * Copyright 2018, Maciej Krüger <mkg20001@gmail.com>
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

/* "System" includes used only as needed */
#include <stdio.h>
#include <stdlib.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/conversation.h>

#include "length-prefixed.h"

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_multistream(void);
void proto_register_multistream(void);

/* Initialize the protocol and registered fields */
static int proto_multistream = -1;
static int hf_multistream_protocol = -1;
static int hf_multistream_listener = -1;
static int hf_multistream_dialer = -1;
static int hf_multistream_handshake = -1;
static int hf_multistream_data = -1;
static int hf_multistream_version = -1;
// static expert_field ei_multistream_EXPERTABBREV = EI_INIT;

/* Global sample preference ("controls" display of numbers) */
static gboolean pref_hex = FALSE;
/* Global sample port preference - real port preferences should generally
 * default to 0 unless there is an IANA-registered (or equivalent) port for your
 * protocol. */
#define multistream_TCP_PORT 4001 // IPFS Port
static guint tcp_port_pref = multistream_TCP_PORT;

/* Initialize the subtree pointers */
static gint ett_multistream = -1;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
// #define multistream_MIN_LENGTH 8

typedef struct _ms_conv_info_t {
    gboolean handshaked;
    address dialerAddr;
    address listenerAddr;
    gchar* listenerMSVer;
    gchar* dialerMSVer;
    gchar* protocol;
    gboolean supported;
    guint32 helloPacket;
    guint32 selectPacket;
    guint32 ackPacket;
} ms_conv_info_t;

/* Code to actually dissect the packets */
static int
dissect_multistream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void *data _U_)
{
  /* Set up structures needed to add the protocol subtree and manage it */
  proto_item *ti; // , *expert_ti;
  proto_tree *multistream_tree;
  /* Other misc. local variables. */
  guint       offset = 0;
  int         len    = tvb_captured_length(tvb);
  gboolean    raw    = 0;
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
    if (tvb_reported_length(tvb) < multistream_MIN_LENGTH)
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

  /* Set the Protocol column to the constant string of multistream */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "multistream");
  col_set_str(pinfo->cinfo, COL_INFO, "MS");

  conversation_t *conversation = find_or_create_conversation(pinfo);
  ms_conv_info_t* conv = (ms_conv_info_t *)conversation_get_proto_data(conversation, proto_multistream);
  if (!conv) {
    conv = wmem_new(wmem_file_scope(), ms_conv_info_t);
  }

  gboolean listener = 0;
  gboolean dialer = 0;

  if (conv->listenerAddr.len && addresses_equal(&pinfo->src, &conv->listenerAddr)) {
    listener = 1;
  }

  if (conv->dialerAddr.len && addresses_equal(&pinfo->src, &conv->dialerAddr)) {
    dialer = 1;
  }

  if (!conv->handshaked) {
    if (!conv->listenerAddr.len && !listener && !dialer) {
      copy_address_wmem(wmem_file_scope(), &conv->listenerAddr, &pinfo->src);
      listener = 1;
    }

    if (!conv->dialerAddr.len && !listener && !dialer && !addresses_equal(&pinfo->src, &conv->listenerAddr)) {
      copy_address_wmem(wmem_file_scope(), &conv->dialerAddr, &pinfo->src);
      dialer = 1;
    }

    if (listener) {
      if (!conv->listenerMSVer) { // version message
        if (len < 20) {
          pinfo->desegment_len = (guint32)20 -len;
        } else {
          int bytesCount;
          gchar* proto = lp_decode_cut(tvb, 0, &bytesCount, 1);
          if (proto) {
            conv->listenerMSVer = g_strdup(proto);
            conv->helloPacket = pinfo->num;
          } else {
            pinfo->desegment_len = (guint32)bytesCount - len;
          }
        }
      } else { // ack/nack
        if (len < 1) {
          pinfo->desegment_len = 1;
        } else {
          int bytesCount;
          gchar* resProto = lp_decode_cut(tvb, 0, &bytesCount, 1);
          if (resProto) {
            conv->supported = conv->protocol == resProto;
            conv->handshaked = TRUE;
            conv->ackPacket = pinfo->num;
            if (conv->supported) {
              col_append_fstr(pinfo->cinfo, COL_INFO, " NACK");
            } else {
              col_append_fstr(pinfo->cinfo, COL_INFO, " ACK (%s)", resProto);
            }
          } else {
            pinfo->desegment_len = (guint32)bytesCount - len;
          }
        }
      }
    } else if (dialer) {
      if (!conv->dialerMSVer) { // version message and select
        if (len < 21) {
          pinfo->desegment_len = (guint32)21 - len;
        } else {
          int bytesCount;
          gchar *proto = lp_decode_cut(tvb, 0, &bytesCount, 1);
          if (proto) {
            offset += bytesCount;
            int bytesCount2 = 0;
            gchar *reqProto = lp_decode_cut(tvb, 20, &bytesCount2, 1);
            if (reqProto) {
              conv->dialerMSVer = g_strdup(proto);
              conv->protocol = g_strdup(reqProto);
              conv->selectPacket = pinfo->num;
            } else {
              pinfo->desegment_len = (guint32)bytesCount2 - (len - offset);
            }
          } else {
            pinfo->desegment_len = (guint32)bytesCount - len;
          }
        }
      }
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

  if (pinfo->num == conv->helloPacket) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " ready (%s)", conv->listenerMSVer);
  } else if (pinfo->num == conv->selectPacket) {
    col_append_fstr(pinfo->cinfo, COL_INFO, " ready (%s) select (%s)", conv->dialerMSVer, conv->protocol);
  } else if (pinfo->num == conv->ackPacket) {
    if (conv->supported) {
      col_append_fstr(pinfo->cinfo, COL_INFO, " NACK");
    } else {
      col_append_fstr(pinfo->cinfo, COL_INFO, " ACK (%s)", conv->protocol);
    }
  } else if (conv->handshaked) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, conv->protocol);
    col_set_str(pinfo->cinfo, COL_INFO, "Data");
    if (len == 1) {
      col_append_str(pinfo->cinfo, COL_INFO, " 1 byte");
    } else {
      col_append_fstr(pinfo->cinfo, COL_INFO, " %i bytes", len);
    }
    raw = TRUE;
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
    ti = proto_tree_add_item(tree, proto_multistream, tvb, 0, -1, ENC_NA);
    multistream_tree = proto_item_add_subtree(ti, ett_multistream);

    proto_item* hidden = NULL;
    if (dialer) {
      hidden = proto_tree_add_boolean(multistream_tree, hf_multistream_dialer, tvb, 0, 0, 1);
    }
    if (listener) {
      hidden = proto_tree_add_boolean(multistream_tree, hf_multistream_listener, tvb, 0, 0, 1);
    }
    if (hidden) {
      PROTO_ITEM_SET_HIDDEN(hidden);
      PROTO_ITEM_SET_GENERATED(hidden);
    }
    hidden = NULL;

    if (pinfo->num == conv->helloPacket) {
      proto_tree_add_string(multistream_tree, hf_multistream_version, tvb, 0, offset,  conv->listenerMSVer);
      hidden = proto_tree_add_boolean(multistream_tree, hf_multistream_handshake, tvb, 0, 0, 1);
    } else if (pinfo->num == conv->selectPacket) {
      proto_tree_add_string(multistream_tree, hf_multistream_version, tvb, 0, offset,  conv->dialerMSVer);
      proto_tree_add_string(multistream_tree, hf_multistream_protocol, tvb, 0, offset, conv->protocol);
      hidden = proto_tree_add_boolean(multistream_tree, hf_multistream_handshake, tvb, 0, 0, 1);
    } else if (pinfo->num == conv->ackPacket) {
      proto_tree_add_string(multistream_tree, hf_multistream_version, tvb, 0, offset,  conv->listenerMSVer);
      proto_tree_add_string(multistream_tree, hf_multistream_protocol, tvb, 0, offset, conv->protocol);
      hidden = proto_tree_add_boolean(multistream_tree, hf_multistream_handshake, tvb, 0, 0, 1);
    } else if (conv->handshaked) {
      proto_tree_add_string(multistream_tree, hf_multistream_version, tvb, 0, offset,  conv->listenerMSVer); // at this point they are equal
      proto_tree_add_string(multistream_tree, hf_multistream_protocol, tvb, 0, offset, conv->protocol);
      hidden = proto_tree_add_item(multistream_tree, hf_multistream_data, tvb, offset, -1, ENC_NA);
    }
    if (hidden) {
      PROTO_ITEM_SET_HIDDEN(hidden);
      PROTO_ITEM_SET_GENERATED(hidden);
    }
  }

  conversation_add_proto_data(conversation, proto_multistream, conv);

#if 0
  /* Add an item to the subtree, see section 1.5 of README.dissector for more
     * information. */
    expert_ti = proto_tree_add_item(multistream_tree, hf_multistream_FIELDABBREV, tvb,
            offset, len, ENC_xxx);
    offset += len;
    /* Some fields or situations may require "expert" analysis that can be
     * specifically highlighted. */
    if ( TEST_EXPERT_condition )
        /* value of hf_multistream_FIELDABBREV isn't what's expected */
        expert_add_info(pinfo, expert_ti, &ei_multistream_EXPERTABBREV);
#endif
  /* Continue adding tree items to process the packet here... */

  /* If this protocol has a sub-dissector call it here, see section 1.8 of
   * README.dissector for more information. */

  /* Return the amount of data this dissector was able to dissect (which may
   * or may not be the total captured packet as we return here). */
  if (raw) return 0;
  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_multistream(void)
{
  module_t        *multistream_module;
  expert_module_t *expert_multistream;

  /* Setup list of header fields  See Section 1.5 of README.dissector for
   * details. */
  static hf_register_info hf[] = {
          { &hf_multistream_protocol,
                  { "Protocol",    "multistream.protocol",
                          FT_STRING,       BASE_NONE,      NULL,   0x0,
                          "Protocol being negotiated on", HFILL }},
          { &hf_multistream_dialer,
                  { "Dialer",    "multistream.dialer",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "TRUE if the packet is sent from the dialer", HFILL }},
          { &hf_multistream_listener,
                  { "Listener",    "multistream.listener",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "TRUE if the packet is sent from the listener", HFILL }},
          { &hf_multistream_handshake,
                  { "Handshake",    "multistream.handshake",
                          FT_BOOLEAN,       BASE_NONE,      NULL,   0x0,
                          "TRUE if the packet is part of the handshake process", HFILL }},
          { &hf_multistream_data,
                  { "Data",    "multistream.data",
                          FT_BYTES,       BASE_NONE,      NULL,   0x0,
                          "Raw bytes transferred", HFILL }},
          { &hf_multistream_version,
                  { "Version",    "multistream.version",
                          FT_STRING,       BASE_NONE,      NULL,   0x0,
                          "Multistream version used", HFILL }}
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
          &ett_multistream
  };

  /* Setup protocol expert items */
  static ei_register_info ei[] = {
          /* { &ei_multistream_EXPERTABBREV,
            { "multistream.EXPERTABBREV", PI_GROUP, PI_SEVERITY,
              "EXPERTDESCR", EXPFILL }
          } */
  };

  /* Register the protocol name and description */
  proto_multistream = proto_register_protocol("Multistream 1.0.0",
                                              "Multistream", "multistream");

  /* Required function calls to register the header fields and subtrees */
  proto_register_field_array(proto_multistream, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Required function calls to register expert items */
  expert_multistream = expert_register_protocol(proto_multistream);
  expert_register_field_array(expert_multistream, ei, array_length(ei));

  /* Register a preferences module (see section 2.6 of README.dissector
   * for more details). Registration of a prefs callback is not required
   * if there are no preferences that affect protocol registration (an example
   * of a preference that would affect registration is a port preference).
   * If the prefs callback is not needed, use NULL instead of
   * proto_reg_handoff_multistream in the following.
   */
  multistream_module = prefs_register_protocol(proto_multistream,
                                               proto_reg_handoff_multistream);
#if 0
  /* Register a preferences module under the preferences subtree.
     * Only use this function instead of prefs_register_protocol (above) if you
     * want to group preferences of several protocols under one preferences
     * subtree.
     *
     * Argument subtree identifies grouping tree node name, several subnodes can
     * be specified using slash '/' (e.g. "OSI/X.500" - protocol preferences
     * will be accessible under Protocols->OSI->X.500-><Multistream>
     * preferences node.
     */
    multistream_module = prefs_register_protocol_subtree(const char *subtree,
            proto_multistream, proto_reg_handoff_multistream);
#endif
  /* Register a simple example preference */
  prefs_register_bool_preference(multistream_module, "show_hex",
                                 "Display numbers in Hex",
                                 "Enable to display numerical values in hexadecimal.",
                                 &pref_hex);

  /* Register an example port preference */
  prefs_register_uint_preference(multistream_module, "tcp.port", "multistream TCP Port",
                                 " multistream TCP port if other than the default",
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
proto_reg_handoff_multistream(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t multistream_handle;
  static int current_port;

  if (!initialized) {
    /* Use create_dissector_handle() to indicate that
     * dissect_multistream() returns the number of bytes it dissected (or 0
     * if it thinks the packet does not belong to Multistream 1.0.0).
     */
    multistream_handle = create_dissector_handle(dissect_multistream,
                                                 proto_multistream);
    initialized = TRUE;

  } else {
    /* If you perform registration functions which are dependent upon
     * prefs then you should de-register everything which was associated
     * with the previous settings and re-register using the new prefs
     * settings here. In general this means you need to keep track of
     * the multistream_handle and the value the preference had at the time
     * you registered.  The multistream_handle value and the value of the
     * preference can be saved using local statics in this
     * function (proto_reg_handoff).
     */
    dissector_delete_uint("tcp.port", current_port, multistream_handle);
  }

  current_port = tcp_port_pref;

  dissector_add_uint("tcp.port", current_port, multistream_handle);
}

#if 0

/* Simpler form of proto_reg_handoff_multistream which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_multistream(void)
{
    dissector_handle_t multistream_handle;

    /* Use create_dissector_handle() to indicate that dissect_multistream()
     * returns the number of bytes it dissected (or 0 if it thinks the packet
     * does not belong to Multistream 1.0.0).
     */
    multistream_handle = create_dissector_handle(dissect_multistream,
            proto_multistream);
    dissector_add_uint_with_preference("tcp.port", multistream_TCP_PORT, multistream_handle);
}
#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
