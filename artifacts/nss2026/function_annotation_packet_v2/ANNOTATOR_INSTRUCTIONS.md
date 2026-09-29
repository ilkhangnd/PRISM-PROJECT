# Blinded function-level annotation

Review only the anonymized `sources/R*.sol` files and your own worksheet. Do not consult `ground_truth_57.json`, filenames from the original corpus, or `ADJUDICATOR_ONLY_identity_key.csv`. For each callable region, choose `vulnerable`, `safe`, or `uncertain`; record the vulnerability class and a short source-grounded rationale. Keep `label_source=independent_manual`.

An adjudicator should later reconcile the two completed worksheets into a separate manifest with `label_source=joint_adjudication` and run `scripts/validate_function_label_manifest.py --require-final`.
