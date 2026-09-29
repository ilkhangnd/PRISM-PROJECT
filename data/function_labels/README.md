# Independent function/span labels

This directory is reserved for labels used in the **function-level** PRISM
evaluation. Do not populate it by propagating a contract-level label to every
function: that would reproduce the construct-validity problem this dataset is
meant to remove.

Create one CSV row per annotator decision, using the columns below. Annotators
should inspect the source blinded to the existing contract-level corpus label.
A second reviewer should independently label each candidate, after which an
adjudicator records the final decision in a `joint_adjudication` row.

```csv
contract_id,source_path,function_signature,start_line,end_line,decision,vulnerability_class,label_source,annotator_id,adjudication_status,evidence
example_001,data/raw/example.sol,withdraw(uint256),18,31,vulnerable,reentrancy,independent_manual,annotator_A,pending,external call before balance update
example_001,data/raw/example.sol,withdraw(uint256),18,31,vulnerable,reentrancy,joint_adjudication,adjudicator_1,adjudicated,reviewers agree after trace inspection
```

`decision` is `vulnerable`, `safe`, or `uncertain`. A vulnerable row needs a
non-empty `vulnerability_class`. `label_source` is restricted to
`independent_manual` and `joint_adjudication`; the validator rejects
`contract_derived`. Before publishing metrics, run:

```bash
/Users/nguyendinhkhang/khangnd/PRISM/.venv/bin/python \
  scripts/validate_function_label_manifest.py data/function_labels/labels.csv \
  --require-final --output artifacts/nss2026/function_labels/validation.json
```

Only adjudicated/agreeing rows with valid source spans should enter a
function-level test set. Keep the contract-derived 57-contract labels as a
separate, explicitly weaker contract-level evaluation.
