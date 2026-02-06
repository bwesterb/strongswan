/*
 * Copyright (C) 2025
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "test_suite.h"

#include <daemon.h>
#include <tests/utils/exchange_test_helper.h>
#include <tests/utils/exchange_test_asserts.h>
#include <tests/utils/sa_asserts.h>

/**
 * Regular IKE_SA establishment with both peers supporting full transcript auth.
 */
START_TEST(test_both_support)
{
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												NULL);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* <-- IKE_SA_INIT */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	ck_assert(a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Test using establish_sa helper.
 */
START_TEST(test_establish_sa)
{
	ike_sa_t *a, *b;

	exchange_test_helper->establish_sa(exchange_test_helper, &a, &b, NULL);

	ck_assert(a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Initiator doesn't support full transcript auth, responder does.
 */
START_TEST(test_initiator_no_support)
{
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", FALSE, lib->ns);

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												NULL);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);

	/* <-- IKE_SA_INIT (responder sends notify even though initiator didn't) */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	ck_assert(!a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(!b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Initiator supports full transcript auth, responder doesn't.
 */
START_TEST(test_responder_no_support)
{
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												NULL);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", FALSE, lib->ns);

	/* <-- IKE_SA_INIT */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_no_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	ck_assert(!a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(!b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Neither peer supports full transcript auth.
 */
START_TEST(test_neither_support)
{
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", FALSE, lib->ns);

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												NULL);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* <-- IKE_SA_INIT */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_no_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	ck_assert(!a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(!b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Config for multiple KE exchange tests (triggers IKE_INTERMEDIATE)
 */
static exchange_test_sa_conf_t multi_ke_conf = {
	.initiator = {
		.ike = "aes256-sha256-modp3072-ke1_ecp256",
	},
	.responder = {
		.ike = "aes256-sha256-modp3072-ke1_ecp256",
	},
};

/**
 * Full transcript auth with IKE_INTERMEDIATE exchange (multi-KE).
 * Verifies that the IntAuth data from IKE_INTERMEDIATE is correctly appended
 * to the modified signed octets (spec Section 7.1).
 */
START_TEST(test_with_ike_intermediate)
{
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												&multi_ke_conf);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* <-- IKE_SA_INIT */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_INTERMEDIATE --> */
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	/* <-- IKE_INTERMEDIATE */
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* IKE_AUTH --> */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_hook();

	/* <-- IKE_AUTH */
	assert_hook_called(child_updown);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_hook();

	ck_assert(a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Verify that IKE_SA rekeying inherits the downgrade prevention extension
 * from the original SA and that no IKE_SA_INIT_FULL_TRANSCRIPT_AUTH notify
 * is sent during the CREATE_CHILD_SA exchange used for rekeying.
 */
START_TEST(test_rekey_inherits_extension)
{
	ike_sa_t *a, *b, *new_sa;
	status_t s;

	exchange_test_helper->establish_sa(exchange_test_helper, &a, &b, NULL);

	/* original SAs should have the extension */
	ck_assert(a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	/* initiate rekeying */
	assert_hook_not_called(ike_rekey);
	call_ikesa(a, rekey);
	assert_ike_sa_state(a, IKE_REKEYING);
	assert_hook();

	/* CREATE_CHILD_SA { SA, Ni, KEi } --> (no full transcript notify) */
	assert_hook_rekey(ike_rekey, 1, 3);
	assert_no_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	assert_ike_sa_state(b, IKE_REKEYED);
	new_sa = assert_ike_sa_checkout(3, 4, FALSE);
	assert_ike_sa_state(new_sa, IKE_ESTABLISHED);
	/* rekeyed SA inherits the extension via inherit_pre() */
	ck_assert(new_sa->supports_extension(new_sa,
										 EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	assert_hook();

	/* <-- CREATE_CHILD_SA { SA, Nr, KEr } (no full transcript notify) */
	assert_hook_rekey(ike_rekey, 1, 3);
	assert_no_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	assert_ike_sa_state(a, IKE_DELETING);
	new_sa = assert_ike_sa_checkout(3, 4, TRUE);
	assert_ike_sa_state(new_sa, IKE_ESTABLISHED);
	/* rekeyed SA inherits the extension via inherit_pre() */
	ck_assert(new_sa->supports_extension(new_sa,
										 EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	assert_hook();

	assert_hook_not_called(ike_rekey);

	/* INFORMATIONAL { D } --> */
	assert_single_payload(IN, PLV2_DELETE);
	s = exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	ck_assert_int_eq(DESTROY_ME, s);
	call_ikesa(b, destroy);
	/* <-- INFORMATIONAL { } */
	assert_message_empty(IN);
	s = exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert_int_eq(DESTROY_ME, s);
	call_ikesa(a, destroy);

	/* ike_rekey */
	assert_hook();

	charon->ike_sa_manager->flush(charon->ike_sa_manager);
}
END_TEST

/**
 * Listener that strips the IKE_SA_INIT_FULL_TRANSCRIPT_AUTH notify from an
 * IKE_SA_INIT message.  Used to simulate an attacker removing the notify.
 */
typedef struct {
	listener_t listener;
	bool strip_request;
} strip_notify_listener_t;

static bool strip_full_transcript_notify(listener_t *listener,
										 ike_sa_t *ike_sa,
										 message_t *message, bool incoming,
										 bool plain)
{
	strip_notify_listener_t *this = (strip_notify_listener_t*)listener;

	if (plain && !incoming &&
		message->get_exchange_type(message) == IKE_SA_INIT &&
		message->get_request(message) == this->strip_request)
	{
		enumerator_t *enumerator;
		payload_t *payload;

		enumerator = message->create_payload_enumerator(message);
		while (enumerator->enumerate(enumerator, &payload))
		{
			if (payload->get_type(payload) == PLV2_NOTIFY)
			{
				notify_payload_t *notify = (notify_payload_t*)payload;

				if (notify->get_notify_type(notify) ==
					IKE_SA_INIT_FULL_TRANSCRIPT_AUTH)
				{
					message->remove_payload_at(message, enumerator);
					payload->destroy(payload);
				}
			}
		}
		enumerator->destroy(enumerator);
		free(listener);
		return FALSE;
	}
	return TRUE;
}

/**
 * Register a listener that strips the full transcript auth notify from
 * an outgoing IKE_SA_INIT message (request or response).
 */
#define strip_notify_from_ike_sa_init(request) ({ \
	strip_notify_listener_t *_listener; \
	INIT(_listener, \
		.listener = { .message = strip_full_transcript_notify, }, \
		.strip_request = request, \
	); \
	exchange_test_helper->add_listener(exchange_test_helper, \
									   &_listener->listener); \
})

/**
 * Attacker strips the IKE_SA_INIT_FULL_TRANSCRIPT_AUTH notify from the
 * initiator's IKE_SA_INIT request.  The initiator enables the extension (it
 * receives the responder's notify), but the responder does not (it never saw
 * the initiator's notify).  Authentication must fail because the peers compute
 * different signed octets.
 */
START_TEST(test_strip_initiator_notify)
{
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;
	status_t s;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												NULL);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* strip the notify from the initiator's outgoing IKE_SA_INIT request */
	strip_notify_from_ike_sa_init(TRUE);

	/* IKE_SA_INIT --> (notify stripped by attacker) */
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* <-- IKE_SA_INIT (responder sends its notify regardless) */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	/* initiator receives responder's notify and enables the extension */
	assert_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* initiator has extension enabled, responder does not -- mismatch */
	ck_assert(a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(!b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	/* IKE_AUTH --> responder verifies initiator's AUTH which was built with
	 * full transcript, but responder expects standard auth: MAC mismatch */
	assert_hook_not_called(child_updown);
	assert_single_notify(OUT, AUTHENTICATION_FAILED);
	s = exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	ck_assert_int_eq(DESTROY_ME, s);
	assert_hook();
	call_ikesa(b, destroy);

	/* <-- IKE_AUTH response with AUTHENTICATION_FAILED */
	assert_hook_not_called(child_updown);
	s = exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert_int_eq(DESTROY_ME, s);
	assert_hook();
	call_ikesa(a, destroy);
}
END_TEST

/**
 * Attacker strips the IKE_SA_INIT_FULL_TRANSCRIPT_AUTH notify from the
 * responder's IKE_SA_INIT response.  The responder enables the extension (it
 * received the initiator's notify), but the initiator does not (it never saw
 * the responder's notify).  Authentication must fail because the peers compute
 * different signed octets.
 */
START_TEST(test_strip_responder_notify)
{
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;
	status_t s;

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												NULL);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> (initiator sends notify normally) */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* strip the notify from the responder's outgoing IKE_SA_INIT response */
	strip_notify_from_ike_sa_init(FALSE);

	/* <-- IKE_SA_INIT (responder's notify stripped by attacker) */
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	/* initiator does not receive the notify */
	assert_no_notify(IN, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	id_a->set_responder_spi(id_a, id_b->get_responder_spi(id_b));
	exchange_test_helper->process_message(exchange_test_helper, a, NULL);

	/* responder has extension enabled, initiator does not -- mismatch */
	ck_assert(!a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	/* IKE_AUTH --> responder verifies initiator's AUTH which was built with
	 * standard auth, but responder expects full transcript: MAC mismatch */
	assert_hook_not_called(child_updown);
	assert_single_notify(OUT, AUTHENTICATION_FAILED);
	s = exchange_test_helper->process_message(exchange_test_helper, b, NULL);
	ck_assert_int_eq(DESTROY_ME, s);
	assert_hook();
	call_ikesa(b, destroy);

	/* <-- IKE_AUTH response with AUTHENTICATION_FAILED */
	assert_hook_not_called(child_updown);
	s = exchange_test_helper->process_message(exchange_test_helper, a, NULL);
	ck_assert_int_eq(DESTROY_ME, s);
	assert_hook();
	call_ikesa(a, destroy);
}
END_TEST

Suite *downgrade_prevention_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("downgrade prevention");

	tc = tcase_create("negotiation");
	tcase_add_test(tc, test_both_support);
	tcase_add_test(tc, test_establish_sa);
	tcase_add_test(tc, test_initiator_no_support);
	tcase_add_test(tc, test_responder_no_support);
	tcase_add_test(tc, test_neither_support);
	suite_add_tcase(s, tc);

	tc = tcase_create("ike_intermediate");
	tcase_add_test(tc, test_with_ike_intermediate);
	suite_add_tcase(s, tc);

	tc = tcase_create("rekeying");
	tcase_add_test(tc, test_rekey_inherits_extension);
	suite_add_tcase(s, tc);

	tc = tcase_create("stripping attack");
	tcase_add_test(tc, test_strip_initiator_notify);
	tcase_add_test(tc, test_strip_responder_notify);
	suite_add_tcase(s, tc);

	return s;
}
