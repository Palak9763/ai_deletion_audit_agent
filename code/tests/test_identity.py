"""
tests/test_identity.py — Unit tests for Phase 2 identity resolution gate.

Covers:
  1. Alias chain: A -> B -> C resolves all three with proper shortest paths
  2. Merged accounts resolve to one unified set
  3. Similar-but-different user is NOT merged
  4. Link dated after audit_at is ignored
  5. Recycled identifier is not carried across reassignment to the other owner
  6. Ambiguous link is flagged and unmerged
"""
from __future__ import annotations

import unittest
from datetime import datetime, timezone

from code.identity.graph import IdentityGraph, IdentityNode


class TestIdentityResolution(unittest.TestCase):
    """Test identity resolution graph under all Phase 2 gate conditions."""

    def test_alias_chain(self):
        """A -> B -> C resolves all three."""
        g = IdentityGraph()
        t = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        node_a = IdentityNode("email", "a@test.com")
        node_b = IdentityNode("user_id", "user_b")
        node_c = IdentityNode("email", "c@test.com")

        # A -> B (direct)
        g.add_edge(node_a, node_b, "identities", "rec_1", t, "direct")
        # B -> C (alias)
        g.add_edge(node_b, node_c, "system_activity", "rec_2", t, "alias")

        res = g.resolve(node_a, as_of=t)

        self.assertIn(node_a, res.identifiers)
        self.assertIn(node_b, res.identifiers)
        self.assertIn(node_c, res.identifiers)
        self.assertEqual(len(res.identifiers[node_a]), 0)
        self.assertEqual(len(res.identifiers[node_b]), 1)
        self.assertEqual(len(res.identifiers[node_c]), 2)
        # Check path structure
        path_c = res.identifiers[node_c]
        self.assertEqual(path_c[0].source, node_a)
        self.assertEqual(path_c[0].target, node_b)
        self.assertEqual(path_c[1].source, node_b)
        self.assertEqual(path_c[1].target, node_c)

    def test_merged_accounts(self):
        """Merged accounts resolve to one unified set."""
        g = IdentityGraph()
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t_merge = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)

        u1 = IdentityNode("user_id", "user_01")
        e1 = IdentityNode("email", "u1@test.com")
        u2 = IdentityNode("user_id", "user_02")
        e2 = IdentityNode("email", "u2@test.com")

        g.add_edge(u1, e1, "identities", "rec_1", t1, "direct")
        g.add_edge(u2, e2, "identities", "rec_2", t1, "direct")

        # Explicit account merge
        g.add_edge(u1, u2, "system_activity", "act_merge_01", t_merge, "merge")

        # Before merge: resolving e1 only gets u1, e1
        res_before = g.resolve(e1, as_of=t1)
        self.assertIn(u1, res_before.identifiers)
        self.assertIn(e1, res_before.identifiers)
        self.assertNotIn(u2, res_before.identifiers)
        self.assertNotIn(e2, res_before.identifiers)

        # As of merge: resolving e1 gets both accounts
        res_after = g.resolve(e1, as_of=t_merge)
        self.assertIn(u1, res_after.identifiers)
        self.assertIn(e1, res_after.identifiers)
        self.assertIn(u2, res_after.identifiers)
        self.assertIn(e2, res_after.identifiers)

    def test_similar_different_user_not_merged(self):
        """Users with same name or similar attributes are NOT merged."""
        g = IdentityGraph()
        t = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        u1 = IdentityNode("user_id", "user_alice")
        e1 = IdentityNode("email", "alice.smith@domain.com")
        name_shared = IdentityNode("name", "Alice Smith")

        u2 = IdentityNode("user_id", "user_alice_2")
        e2 = IdentityNode("email", "alice.smith@other.org")

        g.add_edge(u1, e1, "identities", "rec_1", t, "direct")
        g.add_edge(u1, name_shared, "identities", "rec_1", t, "direct")

        g.add_edge(u2, e2, "identities", "rec_2", t, "direct")
        g.add_edge(u2, name_shared, "identities", "rec_2", t, "direct")

        # Resolving e1 must NOT bridge across name to u2
        res = g.resolve(e1, as_of=t)
        self.assertIn(e1, res.identifiers)
        self.assertIn(u1, res.identifiers)
        self.assertNotIn(u2, res.identifiers)
        self.assertNotIn(e2, res.identifiers)

    def test_link_dated_after_audit_at_ignored(self):
        """Edges created after audit_at are ignored."""
        g = IdentityGraph()
        t_early = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        audit_at = datetime(2026, 2, 1, 12, 0, 0, tzinfo=timezone.utc)
        t_late = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)

        u = IdentityNode("user_id", "user_10")
        e = IdentityNode("email", "user10@test.com")
        new_phone = IdentityNode("phone", "+15555550199")

        g.add_edge(u, e, "identities", "rec_1", t_early, "direct")
        # Added after audit_at
        g.add_edge(u, new_phone, "user_audit_log", "audit_99", t_late, "change")

        res = g.resolve(e, as_of=audit_at)
        self.assertIn(u, res.identifiers)
        self.assertIn(e, res.identifiers)
        self.assertNotIn(new_phone, res.identifiers)

    def test_recycled_identifier_not_carried_to_new_owner(self):
        """A recycled identifier is bound to its time window and does not merge owners."""
        g = IdentityGraph()
        t_orig = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t_reassign = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        t_audit = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        u1 = IdentityNode("user_id", "user_old")
        u2 = IdentityNode("user_id", "user_new")
        shared_email = IdentityNode("email", "recycled@test.com")
        u1_personal = IdentityNode("phone", "+1111111111")
        u2_personal = IdentityNode("phone", "+2222222222")

        g.add_edge(u1, u1_personal, "identities", "rec_old", t_orig, "direct")
        g.add_edge(u2, u2_personal, "identities", "rec_new", t_orig, "direct")

        # Initially assigned to u1
        g.add_edge(u1, shared_email, "identities", "rec_old", t_orig, "direct")

        # Reassigned to u2 at t_reassign
        g.register_reassignment(
            ident=shared_email,
            old_user_id="user_old",
            new_user_id="user_new",
            reassigned_at=t_reassign,
            evidence_source="system_activity",
            record_id="reassign_01",
        )

        # Resolving as of t_audit (after reassignment):
        # Starting from shared_email resolves u2 and u2_personal, but NOT u1 or u1_personal
        res_new = g.resolve(shared_email, as_of=t_audit)
        self.assertIn(u2, res_new.identifiers)
        self.assertIn(u2_personal, res_new.identifiers)
        self.assertNotIn(u1, res_new.identifiers)
        self.assertNotIn(u1_personal, res_new.identifiers)

    def test_ambiguous_link_flagged_not_merged(self):
        """Ambiguous link concurrently referencing multiple users is held unmerged."""
        g = IdentityGraph()
        t = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        u1 = IdentityNode("user_id", "user_alpha")
        u2 = IdentityNode("user_id", "user_beta")
        ambig_phone = IdentityNode("phone", "+15550009999")

        e1 = IdentityNode("email", "alpha@test.com")
        e2 = IdentityNode("email", "beta@test.com")

        g.add_edge(u1, e1, "identities", "rec_1", t, "direct")
        g.add_edge(u2, e2, "identities", "rec_2", t, "direct")

        # Concurrently linked to ambig_phone with no reassignment
        g.add_edge(u1, ambig_phone, "system_activity", "rec_conflict_1", t, "alias")
        g.add_edge(u2, ambig_phone, "system_activity", "rec_conflict_2", t, "alias")

        res1 = g.resolve(e1, as_of=t)
        self.assertIn(u1, res1.identifiers)
        self.assertIn(e1, res1.identifiers)
        # Must NOT merge u2
        self.assertNotIn(u2, res1.identifiers)
        self.assertNotIn(e2, res1.identifiers)
        # Must be recorded in ambiguous_links
        self.assertTrue(len(res1.ambiguous_links) > 0)
        conflicting = [a["identifier"] for a in res1.ambiguous_links]
        self.assertIn(str(ambig_phone), conflicting)


if __name__ == "__main__":
    unittest.main()
