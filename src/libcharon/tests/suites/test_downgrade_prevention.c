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
 * Both peers support full transcript auth.
 */
START_TEST(test_both_support)
{
	ike_sa_t *a, *b;

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);

	exchange_test_helper->establish_sa(exchange_test_helper, &a, &b, NULL);

	ck_assert(a->supports_extension(a, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));
	ck_assert(b->supports_extension(b, EXT_IKE_SA_INIT_FULL_TRANSCRIPT_AUTH));

	call_ikesa(a, destroy);
	call_ikesa(b, destroy);
}
END_TEST

/**
 * Responder doesn't support full transcript auth.
 */
START_TEST(test_responder_no_support)
{
	ike_sa_t *a, *b;
	ike_sa_id_t *id_a, *id_b;
	child_cfg_t *child_cfg;

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);

	child_cfg = exchange_test_helper->create_sa(exchange_test_helper, &a, &b,
												NULL);
	id_a = a->get_id(a);
	id_b = b->get_id(b);

	/* IKE_SA_INIT --> */
	assert_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	call_ikesa(a, initiate, child_cfg, NULL);
	id_b->set_initiator_spi(id_b, id_a->get_initiator_spi(id_a));

	/* Disable for responder */
	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", FALSE, lib->ns);

	/* <-- IKE_SA_INIT */
	assert_no_notify(OUT, IKE_SA_INIT_FULL_TRANSCRIPT_AUTH);
	exchange_test_helper->process_message(exchange_test_helper, b, NULL);
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

	lib->settings->set_bool(lib->settings,
							"%s.full_transcript_auth", TRUE, lib->ns);
}
END_TEST

Suite *downgrade_prevention_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("downgrade prevention");

	tc = tcase_create("negotiation");
	tcase_add_test(tc, test_both_support);
	tcase_add_test(tc, test_responder_no_support);
	suite_add_tcase(s, tc);

	return s;
}
