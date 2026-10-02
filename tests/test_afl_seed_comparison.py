from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.afl_seed_comparison import (
    ARCHETYPES,
    EPD_BY_PARSER,
    ORDINARY_SEEDS,
    apply_seed_hygiene,
    build_paired_run_plan,
    curated_ordinary_seeds,
    coverage_auc,
    extract_frontier_seeds,
    generate_coverage_gap_variants,
    _matrix_plan_shard_indices,
    parse_plot_data,
    parse_fuzzer_stats,
    parse_seed_array,
    prepare_campaign,
    run_coverage_feedback_round,
    summarize_paired_rows,
    validate_and_merge_frontier_seeds,
    write_coverage_analysis,
    write_report,
    write_repeatability_report,
    _coverage_gap_prompt,
    _resolve_nas_code_range,
    _validate_structured_spec,
)


class SeedComparisonTests(unittest.TestCase):
    def test_matrix_sharding_keeps_matched_arms_together(self):
        first = _matrix_plan_shard_indices(40, shard_index=0, shard_count=2)
        second = _matrix_plan_shard_indices(40, shard_index=1, shard_count=2)
        self.assertEqual(len(first), 20)
        self.assertEqual(len(second), 20)
        self.assertEqual(set(first) | set(second), set(range(40)))
        self.assertFalse(set(first) & set(second))
        for indices in (first, second):
            self.assertEqual(len({index // 2 for index in indices}), 10)
            self.assertTrue(all((index + 1 in indices) for index in indices if index % 2 == 0))

    def test_plot_data_parser_and_auc_use_elapsed_time_and_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plot_data"
            path.write_text(
                "# relative_time, cycles_done, edges_found, saved_crashes\n"
                "0, 0, 10, 0\n"
                "5, 1, 15, 0\n"
                "bad, 2, 20, 0\n"
                "10, 2, 20, 0\n",
                encoding="utf-8",
            )
            points = parse_plot_data(path)

        self.assertEqual(points, [(0, 10), (5, 15), (10, 20)])
        self.assertEqual(coverage_auc(points, 10), 150.0)

    def test_coverage_analysis_writes_paired_auc_and_svg_curves(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory)
            rows = []
            for arm, low, high in (("ordinary", 10, 20), ("llm", 12, 22)):
                run_path = Path("runs") / "fixture" / "gmm" / "rep_01" / arm
                output = campaign / run_path / "default"
                output.mkdir(parents=True)
                (output / "plot_data").write_text(
                    "# relative_time, cycles_done, edges_found\n"
                    f"0, 0, {low}\n10, 1, {high}\n",
                    encoding="utf-8",
                )
                rows.append({
                    "model": "fixture", "parser": "gmm", "repeat": "1", "seed_arm": arm,
                    "run_path": str(run_path),
                })

            write_coverage_analysis(campaign, rows, duration_seconds=10)
            with (campaign / "coverage_auc_paired.csv").open(encoding="utf-8", newline="") as handle:
                paired = list(csv.DictReader(handle))

            self.assertEqual(paired[0]["llm_minus_ordinary_auc_edge_seconds"], "20.000")
            self.assertTrue((campaign / "coverage_curves.svg").is_file())
            self.assertIn("fixture / GMM", (campaign / "coverage_curves.svg").read_text(encoding="utf-8"))

    def test_matrix_plan_pairs_arms_on_same_seed_and_alternates_order(self):
        models = ["llama3.2:3b", "qwen2.5-coder:3b"]
        plan = build_paired_run_plan(models, repeats=3, base_seed=90)
        pairs = {}
        for row in plan:
            key = (row["model"], row["parser"], row["repeat"])
            pairs.setdefault(key, []).append(row)
        self.assertEqual(len(pairs), 12)
        for key, rows in pairs.items():
            self.assertEqual({row["arm"] for row in rows}, {"ordinary", "llm"})
            self.assertEqual(len({row["afl_seed"] for row in rows}), 1)
            self.assertEqual(rows[0]["arm"], "ordinary" if key[2] % 2 else "llm")

    def test_paired_delta_summary_keeps_each_repetition(self):
        rows = []
        for repeat, baseline, llm in ((1, 10, 13), (2, 20, 18)):
            for arm, value in (("ordinary", baseline), ("llm", llm)):
                rows.append({
                    "model": "fixture",
                    "parser": "gmm",
                    "repeat": str(repeat),
                    "seed_arm": arm,
                    "afl_seed": str(100 + repeat),
                    "executions": str(value),
                    "executions_per_second": "1",
                    "corpus_found": "0",
                    "edges_found": str(value),
                    "bitmap_coverage": "1.0%",
                })
        deltas = summarize_paired_rows(rows, ["fixture"], ("gmm",), repeats=2)
        self.assertEqual([row["llm_minus_ordinary_executions"] for row in deltas], ["3.0000", "-2.0000"])

    def test_seed_parser_accepts_hex_and_rejects_duplicates(self):
        seeds = parse_seed_array('["7e0043", "2e0100"]', 2)
        self.assertEqual(seeds, [bytes.fromhex("7e0043"), bytes.fromhex("2e0100")])
        object_seeds = parse_seed_array('{"hex_strings": ["7e0043", "2e0100"]}', 2)
        self.assertEqual(object_seeds, seeds)

    def test_seed_parser_requires_unique_bounded_even_hex(self):
        with self.assertRaisesRegex(ValueError, "unique valid seeds"):
            parse_seed_array('["7e0043", "7e0043", "bad"]', 2)
        with self.assertRaisesRegex(ValueError, "only 0 unique valid seeds"):
            parse_seed_array('["123"]', 1)
        with self.assertRaisesRegex(ValueError, "only 0 unique valid seeds"):
            parse_seed_array('[""]', 1)

    def test_built_in_ordinary_seed_arms_have_equal_nonempty_counts(self):
        self.assertEqual(set(ORDINARY_SEEDS), {"gmm", "gsm"})
        for seeds in ORDINARY_SEEDS.values():
            self.assertEqual(len(seeds), 8)

    def test_seed_hygiene_rejects_short_and_wrong_discriminator_seeds(self):
        good_gmm = bytes.fromhex("7e004179000b0100f110000000002143f5")
        too_short = bytes.fromhex("7e0001")
        wrong_epd = bytes.fromhex("2e00417900")  # GSM EPD in a GMM batch
        duplicate = good_gmm
        kept, report = apply_seed_hygiene([good_gmm, too_short, wrong_epd, duplicate], "gmm", hand_crafted_hashes=set())
        self.assertEqual(kept, [good_gmm])
        self.assertEqual(report["rejected_too_short"], 1)
        self.assertEqual(report["rejected_bad_discriminator"], 1)
        self.assertEqual(report["rejected_duplicate"], 1)
        self.assertEqual(report["kept_count"], 1)

    def test_seed_hygiene_reports_handcrafted_overlap_percent(self):
        import hashlib

        seed_a = bytes.fromhex("7e004179000b0100f110000000002143f5")
        seed_b = bytes.fromhex("7e00417a000a0100f1100000000089671002")
        handcrafted = {hashlib.sha256(seed_a).hexdigest()}
        kept, report = apply_seed_hygiene([seed_a, seed_b], "gmm", handcrafted)
        self.assertEqual(len(kept), 2)
        self.assertEqual(report["cross_arm_overlap_with_handcrafted_count"], 1)
        self.assertEqual(report["cross_arm_overlap_with_handcrafted_percent"], 50.0)

    def test_protocol_discriminators_match_3gpp_epd_values(self):
        self.assertEqual(EPD_BY_PARSER, {"gmm": 0x7E, "gsm": 0x2E})

    def test_structured_spec_validation_rejects_unknown_mutation_and_ie(self):
        base = {
            "parser": "gmm", "message_type": "registration_request", "archetype": "tlv_boundary",
            "fields": {}, "mutations": [],
        }
        _validate_structured_spec(dict(base), "gmm", "tlv_boundary")  # no mutations: fine

        bad_op = {**base, "mutations": [{"op": "delete_everything", "ie": "capability_5gmm"}]}
        with self.assertRaisesRegex(ValueError, "unsupported mutation op"):
            _validate_structured_spec(bad_op, "gmm", "tlv_boundary")

        bad_ie = {**base, "mutations": [{"op": "set_ie_length", "ie": "made_up_ie", "declared_length": 1}]}
        with self.assertRaisesRegex(ValueError, "unsupported mutation IE"):
            _validate_structured_spec(bad_ie, "gmm", "tlv_boundary")

        wrong_parser = {**base, "parser": "gsm"}
        with self.assertRaisesRegex(ValueError, "spec parser"):
            _validate_structured_spec(wrong_parser, "gmm", "tlv_boundary")

    def test_deep_valid_archetype_strips_any_model_supplied_mutation(self):
        spec = {
            "parser": "gmm", "message_type": "registration_request", "archetype": "deep_valid",
            "fields": {}, "mutations": [{"op": "set_ie_length", "ie": "capability_5gmm"}],
        }
        validated = _validate_structured_spec(spec, "gmm", "deep_valid")
        self.assertEqual(validated["mutations"], [])

    def test_mutation_target_forces_its_ie_field_present(self):
        spec = {
            "parser": "gmm", "message_type": "registration_request", "archetype": "ie_sequencing",
            "fields": {"nssai": []},  # model disabled the very IE it asks to move
            "mutations": [{"op": "move_ie_to_front", "ie": "requested_nssai"}],
        }
        validated = _validate_structured_spec(spec, "gmm", "ie_sequencing")
        self.assertNotIn("nssai", validated["fields"])

    def test_extra_mutations_are_truncated_to_the_first_one(self):
        spec = {
            "parser": "gmm", "message_type": "registration_request", "archetype": "tlv_boundary",
            "fields": {},
            "mutations": [
                {"op": "set_ie_length", "ie": "capability_5gmm", "declared_length": 0},
                {"op": "set_ie_length", "ie": "ue_security_capability", "declared_length": 255},
            ],
        }
        validated = _validate_structured_spec(spec, "gmm", "tlv_boundary")
        self.assertEqual(len(validated["mutations"]), 1)
        self.assertEqual(validated["mutations"][0]["ie"], "capability_5gmm")

    def test_truncate_after_bytes_is_clamped_to_hygiene_floor(self):
        spec = {
            "parser": "gmm", "message_type": "registration_request", "archetype": "truncated",
            "fields": {}, "mutations": [{"op": "truncate", "after_bytes": 2}],
        }
        validated = _validate_structured_spec(spec, "gmm", "truncated")
        self.assertEqual(validated["mutations"][0]["after_bytes"], 4)

    def test_resolve_nas_code_range_returns_none_for_missing_binary(self):
        self.assertIsNone(_resolve_nas_code_range(Path("/nonexistent/binary-xyz")))

    def test_repeatability_report_passes_above_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory)
            rows = [
                {"repeat": str(i), "parser": "gmm", "afl_seed": "1", "stability": "99.10%",
                 "executions": "100", "edges_found": "50", "bitmap_coverage": "1.0%"}
                for i in range(1, 6)
            ]
            summary = write_repeatability_report(campaign, rows)
            self.assertTrue(summary["passed"])
            self.assertAlmostEqual(summary["min_stability_percent"], 99.10)
            self.assertIn("PASS", (campaign / "repeatability_report.md").read_text())

    def test_repeatability_report_fails_below_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory)
            rows = [
                {"repeat": str(i), "parser": "gmm", "afl_seed": "1", "stability": "90.00%",
                 "executions": "100", "edges_found": "50", "bitmap_coverage": "1.0%"}
                for i in range(1, 6)
            ]
            summary = write_repeatability_report(campaign, rows)
            self.assertFalse(summary["passed"])
            self.assertIn("FAIL", (campaign / "repeatability_report.md").read_text())

    def test_extract_frontier_seeds_keeps_only_plus_cov_non_orig_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            queue = Path(directory)
            names = [
                "id:000000,time:0,execs:0,orig:seed_001.bin",  # initial seed: excluded
                "id:000001,src:000000,time:10,execs:5,op:havoc,rep:1,+cov",  # frontier
                "id:000002,src:000000,time:20,execs:9,op:trim,rep:0",  # trimmed, no new coverage: excluded
                "id:000003,src:000001,time:30,execs:12,op:havoc,rep:2,+cov",  # frontier
            ]
            for name in names:
                (queue / name).write_bytes(b"\x7e\x00\x41")
            (queue / ".state").mkdir()  # AFL keeps a hidden .state dir alongside queue entries
            frontier = extract_frontier_seeds(queue)
            self.assertEqual(
                sorted(p.name for p in frontier),
                sorted(n for n in names if n.endswith(",+cov")),
            )

    def test_coverage_gap_prompt_names_the_reached_ie_and_current_value(self):
        prompt = _coverage_gap_prompt("gmm", "ue_security_capability", "0f0f", 5)
        self.assertIn("ue_security_capability", prompt)
        self.assertIn("0f0f", prompt)
        self.assertIn("5", prompt)

    @patch("scripts.afl_seed_comparison._request_coverage_gap_variants")
    @patch("scripts.afl_seed_comparison._compile_specs")
    def test_coverage_gap_variants_rejects_unsupported_ie(self, compile_specs, request_variants):
        with self.assertRaisesRegex(ValueError, "unsupported IE"):
            generate_coverage_gap_variants(
                "fixture-model", "http://127.0.0.1:11434", Path("/dev/null"), "gmm",
                b"\x7e\x00\x41", "made_up_ie", "00", 3,
            )
        compile_specs.assert_not_called()
        request_variants.assert_not_called()

    @patch("scripts.afl_seed_comparison._request_coverage_gap_variants")
    @patch("scripts.afl_seed_comparison._compile_specs")
    def test_coverage_gap_variants_compiles_each_candidate_and_reports_errors(self, compile_specs, request_variants):
        request_variants.return_value = json.dumps({"value_hex_variants": ["ff", "not-hex", "00"]})
        compile_specs.return_value = [
            (b"\x7e\x00\x41\xff", ""),
            (None, "replace_ie_value: value_hex: invalid hex byte in \"not-hex\""),
            (b"\x7e\x00\x41\x00", ""),
        ]
        variants, errors = generate_coverage_gap_variants(
            "fixture-model", "http://127.0.0.1:11434", Path("/dev/null"), "gmm",
            b"\x7e\x00\x41\x0f", "ue_security_capability", "0f", 3,
        )
        self.assertEqual(len(variants), 2)
        self.assertEqual(len(errors), 1)
        self.assertIn("not-hex", errors[0])

    @patch("scripts.afl_seed_comparison._resolve_nas_code_range", return_value=None)
    @patch("scripts.afl_seed_comparison.subprocess.run")
    def test_validate_and_merge_rejects_exact_duplicate_and_accepts_genuine_new_edge(
        self, mock_run, _mock_code_range
    ):
        # Regression test for a real bug found during live validation: afl-showmap's
        # single-file "-f" mode uses a different hit-count bucketing scheme than its
        # "-C/-i directory" mode, so comparing a -f-measured candidate against a
        # -C-measured baseline produced a spurious, deterministic "new edge" for a
        # byte-identical duplicate. All measurement (baseline AND candidates) must
        # go through -C/-i so edge IDs are computed consistently, and a candidate
        # must show the same new edge in every repeat to be accepted.
        baseline_edges = {"000001": 1, "000002": 1}
        genuinely_new_edge = "000099"

        def fake_run(command, cwd, env, check, capture_output, text):
            output_path = Path(command[command.index("-o") + 1])
            input_dir = Path(command[command.index("-i") + 1])
            is_candidate = (input_dir / "candidate.bin").exists()
            if is_candidate:
                candidate_bytes = (input_dir / "candidate.bin").read_bytes()
                edges = dict(baseline_edges)
                if candidate_bytes == b"genuinely-novel-input":
                    edges[genuinely_new_edge] = 1
                # the exact-duplicate candidate (b"existing-seed") intentionally
                # reports ONLY baseline edges here, proving no mode-mismatch bug
                # remains: if -f/-C bucketing diverged again, a real implementation
                # bug would have to inject a spurious edge itself, which this fake
                # deliberately does NOT do.
            else:
                edges = baseline_edges
            output_path.write_text("".join(f"{edge}:{count}\n" for edge, count in edges.items()))
            result = type("Result", (), {"returncode": 0, "stderr": ""})()
            return result

        mock_run.side_effect = fake_run

        with tempfile.TemporaryDirectory() as directory:
            queue_dir = Path(directory) / "queue"
            queue_dir.mkdir()
            (queue_dir / "seed_001.bin").write_bytes(b"existing-seed")
            output_corpus = Path(directory) / "round2"
            report = validate_and_merge_frontier_seeds(
                Path("/fake/afl-showmap"), Path("/fake/binary"), "gmm", queue_dir,
                [b"existing-seed", b"genuinely-novel-input"], output_corpus,
            )

            self.assertEqual(report["accepted_count"], 1)
            self.assertFalse(report["verdicts"][0]["accepted"])
            self.assertTrue(report["verdicts"][1]["accepted"])
            self.assertEqual(report["verdicts"][1]["new_edge_count"], 1)
            self.assertEqual(sorted(p.name for p in output_corpus.iterdir()), ["seed_001.bin"])

    @patch("scripts.afl_seed_comparison.validate_and_merge_frontier_seeds")
    @patch("scripts.afl_seed_comparison.generate_coverage_gap_variants")
    @patch("scripts.afl_seed_comparison.dissect_seeds")
    @patch("scripts.afl_seed_comparison._build_seed_compiler")
    def test_coverage_feedback_round_skips_and_targets_are_recorded_honestly(
        self, mock_build_compiler, mock_dissect, mock_generate, mock_validate
    ):
        mock_build_compiler.return_value = Path("/fake/compiler")
        mock_dissect.return_value = [
            {"ok": False, "error": "RegReq.MobileId5GS: incorrect IE length(20)"},
            {"ok": True, "message_type": "RegReq", "reached_ies": ["UESecCapability"],
             "mutable_ie_values": {"ue_security_capability": "0f0f0000"}},
            {"ok": True, "message_type": "RegReq", "reached_ies": ["Ngksi"], "mutable_ie_values": {}},
        ]
        mock_generate.return_value = ([b"variant-a", b"variant-b"], [])
        mock_validate.return_value = {"candidate_count": 2, "accepted_count": 1, "verdicts": []}

        with tempfile.TemporaryDirectory() as directory:
            queue_dir = Path(directory) / "queue"
            queue_dir.mkdir()
            (queue_dir / "id:000001,src:000000,time:1,execs:1,op:havoc,rep:0,+cov").write_bytes(b"seed-a")
            (queue_dir / "id:000002,src:000000,time:2,execs:2,op:havoc,rep:1,+cov").write_bytes(b"seed-b")
            (queue_dir / "id:000003,src:000000,time:3,execs:3,op:havoc,rep:2,+cov").write_bytes(b"seed-c")

            result = run_coverage_feedback_round(
                Path(directory) / "campaign", queue_dir, Path("/fake/binary"), Path("/fake/afl-showmap"),
                "gmm", "fixture-model", "http://127.0.0.1:11434", Path(directory) / "round2",
            )

        self.assertEqual(result["frontier_seed_count"], 3)
        entries = result["candidate_generation"]
        self.assertTrue(entries[0]["skipped"])
        self.assertIn("incorrect IE length", entries[0]["reason"])
        self.assertEqual(entries[1]["ie"], "ue_security_capability")
        self.assertEqual(entries[1]["candidates_compiled"], 2)
        self.assertTrue(entries[2]["skipped"])
        self.assertIn("no mutable IE", entries[2]["reason"])
        mock_generate.assert_called_once()
        mock_validate.assert_called_once()
        self.assertEqual(mock_validate.call_args.args[4], [b"variant-a", b"variant-b"])

    def test_invalid_hex_field_lengths_fall_back_to_safe_defaults(self):
        spec = {
            "parser": "gmm", "message_type": "registration_request", "archetype": "deep_valid",
            "fields": {
                "security_capability_hex": "aa",  # odd number of bytes not allowed (1 byte, must be 2-8 even)
                "capability_5gmm_hex": "",  # falls through unchanged (empty means "drop")
                "nssai": [{"sst": 1, "sd_hex": "zz"}],  # invalid hex
            },
            "mutations": [],
        }
        validated = _validate_structured_spec(spec, "gmm", "deep_valid")
        self.assertEqual(validated["fields"]["security_capability_hex"], "8080")
        self.assertEqual(validated["fields"]["nssai"][0]["sd_hex"], "010203")

    def test_curated_ordinary_seeds_are_archetype_matched_and_distinct(self):
        for parser_name in ("gmm", "gsm"):
            seeds = curated_ordinary_seeds(parser_name, count=4)
            self.assertEqual(len(seeds), 4)
            self.assertEqual(len(set(seeds)), 4)
            for seed in seeds:
                self.assertEqual(seed[0], EPD_BY_PARSER[parser_name])

    def test_curated_ordinary_seeds_requires_multiple_of_archetype_count(self):
        with self.assertRaisesRegex(ValueError, "multiple of"):
            curated_ordinary_seeds("gmm", count=3)

    def test_archetypes_cover_four_named_classes(self):
        self.assertEqual(ARCHETYPES, ("deep_valid", "tlv_boundary", "ie_sequencing", "truncated"))

    def test_fuzzer_stats_parser_preserves_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fuzzer_stats"
            path.write_text("run_time : 30\nexecs_done : 1234\nstability : 99.5%\n", encoding="utf-8")
            self.assertEqual(
                parse_fuzzer_stats(path),
                {"run_time": "30", "execs_done": "1234", "stability": "99.5%"},
            )

    @patch("scripts.afl_seed_comparison._request_ollama")
    def test_prepare_campaign_writes_paired_corpora_and_provenance(self, request_ollama):
        request_ollama.return_value = json.dumps(
            {"hex_strings": ["7e0043", "7e005e", "7e005d18", "7e005b", "7e0000", "7e01", "7e", "2e0100"]}
        )
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory) / "campaign"
            prepare_campaign(campaign, 8, "fixture-model", "http://127.0.0.1:11434")
            manifest = json.loads((campaign / "seed_manifest.json").read_text(encoding="utf-8"))

            for parser_name in ("gmm", "gsm"):
                ordinary = list((campaign / "corpus" / parser_name / "ordinary").glob("*.bin"))
                llm = list((campaign / "corpus" / parser_name / "llm").glob("*.bin"))
                self.assertEqual((len(ordinary), len(llm)), (8, 8))
            self.assertEqual(manifest["model"], "fixture-model")
            self.assertEqual(manifest["cross_arm_duplicate_inputs_by_parser"]["gmm"], 7)
            self.assertIn("harness_sha256", manifest)
            self.assertEqual(request_ollama.call_count, 2)

    @patch("scripts.afl_seed_comparison._request_ollama", side_effect=RuntimeError("offline"))
    def test_prepare_campaign_leaves_no_partial_seed_tree_on_model_failure(self, request_ollama):
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory) / "campaign"
            with self.assertRaisesRegex(RuntimeError, "offline"):
                prepare_campaign(campaign, 8, "fixture-model", "http://127.0.0.1:11434")
            self.assertFalse((campaign / "corpus").exists())
            self.assertFalse((campaign / "seed_manifest.json").exists())

    def test_report_renders_matched_metrics_and_limitations(self):
        rows = [
            {
                "parser": parser_name,
                "seed_arm": arm,
                "runtime_seconds": "30",
                "executions": "400",
                "executions_per_second": "13.3",
                "final_corpus": "20",
                "corpus_found": "16",
                "maximum_depth": "2",
                "bitmap_coverage": "13.5%",
                "edges_found": "8800",
                "total_edges": "65536",
                "saved_crashes": "0",
                "saved_hangs": "0",
                "timeouts": "0",
                "stability": "90.0%",
            }
            for parser_name in ("gmm", "gsm")
            for arm in ("ordinary", "llm")
        ]
        with tempfile.TemporaryDirectory() as directory:
            campaign = Path(directory) / "campaign"
            campaign.mkdir()
            (campaign / "seed_manifest.json").write_text(
                json.dumps({"model": "fixture", "seed_count_per_arm_per_parser": 4}), encoding="utf-8"
            )
            (campaign / "run_config.json").write_text(
                json.dumps({"runtime_seconds": 30, "timeout_ms": 1000, "memory_limit_mb": 2048}),
                encoding="utf-8",
            )
            write_report(campaign, rows)
            report = (campaign / "results.md").read_text(encoding="utf-8")
        self.assertIn("GMM LLM seeds", report)
        self.assertIn("instrumentation-instability warnings", report)
        self.assertIn("external handler", report)


if __name__ == "__main__":
    unittest.main()
