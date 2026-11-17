# Source-bound retrieval trial

This trial ranks a fixed document set for a fixed query set. It does not admit
evidence to the graph. Keep original PDFs, labels, model snapshots, extracted
fields, and full rankings in the authorized external data root.

## Inputs and ordering

1. Generate the immutable 10,000-document fields manifest from the pinned
   original PDFs and the final native extractor. Check the field receipt and
   count all documents, including pages with no usable native text.
   Field verification hashes each source PDF, cached page PDF, review image,
   and native JSON buffer before decoding those same buffers. A path that
   presents different content to the decoder cannot pass on the recorded hash.
   The builder rereads input hashes before publishing its immutable receipt.
2. Freeze the query IDs and text before evaluating any target labels. The
   `ranking_inputs_sha256` binds only ID and text; `evaluation_labels_sha256`
   binds ID and target separately. A target-only edit must leave candidate
   pools and reranked order unchanged.
3. Build the local SPECTER2 discovery cache using `python -m
   src.parallel_source_v4.specter2_cache` with `--data-root`, `--fields`,
   `--queries`, `--model-root`, `--model-manifest`, and `--output` paths relative
   to that root. The producer requires a complete hash manifest for a local
   base model and distinct paper/query adapters, 512-token input limit,
   normalized CLS vectors, and cosine ranking. It loads no remote code or
   remote model files. Every vector checkpoint has an immutable batch receipt
   binding its exact bytes, text inputs, and protocol. A checkpoint without
   its receipt is held for investigation; resume in a new output directory.
   Documents with neither a title nor an
   abstract stay in the 10,000-document denominator but are masked from the
   dense ranking; the cache lists their IDs and count.
   The [SPECTER2 base model card](https://huggingface.co/allenai/specter2_base)
   and [adhoc query adapter card](https://huggingface.co/allenai/specter2_adhoc_query)
   identify the Apache 2.0 license and the paper/query adapter pairing.
4. Evaluate the frozen lexical, dense, and page candidate channels at the
   recorded depth, then rerank their union with a locally pinned reranker.
   Report each channel's candidate recall, union recall, final recall and MRR,
   runtime, missing text, converter errors, and source/field hashes. Reranker
   output must bind its exact model files and inputs in the private receipt.
   The pinned [MS MARCO MiniLM cross-encoder model card](https://huggingface.co/cross-encoder/ms-marco-MiniLM-L6-v2)
   lists the Apache 2.0 license; use only the verified local safetensors snapshot.

The SPECTER2 cache uses `ranking-inputs-v2`: target labels are excluded from
ranking inputs. Legacy caches without that version remain accepted only when
their full query records, including targets, match exactly. An unsupported
binding version fails closed. The cache is a ranking aid; a high similarity
score never supplies a source quote or graph-publication authority.

## Freeze and run an empirical receipt

`src.parallel_source_v4.retrieval_trial` wraps the existing producer and
reranker. Generate fields on the final implementation tree first: the wrapper
requires the field receipt's entire module map to equal the current module
map. Its new module therefore also requires a new field build. Use the pinned
PDF environment for fields and a separate, unchanged local model environment
for this wrapper. The model environment needs PyTorch, Transformers, adapters,
NumPy, tokenizers, safetensors and sentence-transformers; freezing records all
their installed versions and both interpreter file hashes. It does not install
packages or fetch models.

Freeze the full 10,000-document/60-query configuration before scoring. All paths
below except `--source-root` and `--field-verifier-python` are relative to the authorized external data root;
the protocol is private because it records that source root. Use new output
names. The `freeze` command verifies every original PDF and saved page, image
and native JSON against the preparation manifest. It also checks exact field
and query identities, code, runtime and all installed model files.

```sh
python -m src.parallel_source_v4.retrieval_trial freeze \
  --data-root /authorized/TRACE-GC_RealPaper_Test \
  --source-root /authorized/original-pdfs \
  --field-verifier-python /authorized/pinned-pdf-env/bin/python \
  --preparation-manifest runs/preparation/manifest.json \
  --fields runs/final-fields.json \
  --queries validation_expanded200/queries.json \
  --dense-model-root models/specter2 \
  --dense-model-manifest protocol/specter2-model.json \
  --reranker-directory models/reranker \
  --reranker-manifest protocol/reranker-model.json \
  --cpu-threads 4 --without-dense-ablation --without-page-ablation \
  --historical-fields validation_v2/retrieval_fields.jsonl \
  --historical-fields-sha256 <externally-recorded-legacy-file-sha256> \
  --output runs/trial-protocol.json
```

Keep the printed protocol file SHA-256 outside the file itself and supply it
explicitly when running. The original expanded-200 query file contains 60
queries; the earlier `validation_200_10k/retrieval_queries.json` contains a
different set and is not interchangeable. Query IDs must be explicit, and every
target must exist in the unchanged corpus denominator.

```sh
python -m src.parallel_source_v4.retrieval_trial run \
  --data-root /authorized/TRACE-GC_RealPaper_Test \
  --protocol runs/trial-protocol.json \
  --expected-protocol-sha256 <externally-recorded-64-hex-file-hash> \
  --output runs/trial-UNIQUE
```

The wrapper uses CPU only, four PyTorch/BLAS threads and one PyTorch interop
thread. The existing dense producer sets four threads explicitly, so other
thread budgets are rejected. Dense batches contain 16 inputs and each channel
contributes at most 50 candidates. The cross-encoder scores the actual union,
then scores it again after rotating only the target labels by one position.
The same dense cache is used for both passes. Success requires identical query
ranking-input hashes, candidate pools, dense-cache identity and final ranking
hashes, with different evaluation-label hashes. This is an empirical check;
unit-test scorers do not substitute for the local model on the real corpus.
Each reranker call records a hash of its exact input pairs and the returned
scores, enabling private readback without exposing text in public reports.
Every full ranking is retained and its order is checked against the evaluator's
ranking hash, including its rule that tied scores retain candidate-pool order.

`--without-dense-ablation` omits the dense channel with unchanged fields and
reranker. `--without-page-ablation` omits only the page candidate channel:
weighted BM25 still uses its body weight, and reranker document text is unchanged.
An omitted channel has empty candidates and `NOT_RUN` metrics.

`--historical-fields` plus its external SHA-256 freezes the complete ordered
legacy JSONL, including empty/error rows. It must contain exactly the current
corpus IDs in order. This condition measures the effect of archived field text
under the current ranking algorithm, with its own newly produced SPECTER2
embeddings. It is not a rerun of the historical extraction algorithm or a
certification of legacy source provenance: the archived rows have no source-byte
hashes. The old model cache is never reused. If both flags are selected, the
wrapper measures the four field/page combinations, allowing page effects to be
compared within each field condition and field effects within each page condition.
Every condition, including without-dense, gets its own actual target-only
permutation pass with the same condition-specific cache. All must pass.

## Corpus-wide field eligibility

New trial protocols require an explicit policy receipt from `fields --corpus-policy`.
The policy accepts no paper-ID exceptions, query labels or targeted title reviews.
For a declared native-only baseline, use this exact JSON:

```json
{"schema_version":"retrieval-corpus-policy-v1","abstract_mode":"disabled","assessment_method":null,"ocr_mode":"disabled","ocr_identity":null}
```

For repaired native abstract fields, set `abstract_mode` to `native_assessments`
and `assessment_method` to one supported method such as `parallel_structure_v4`.
Supply its source-bound map with `--abstract-assessments`. Every page with valid,
nonempty native text and a matching saved page needs an assessment from that
same declared method. Complete proposals populate the abstract; partial, absent,
uncertain, truncated and error outcomes remain explicit holds. An absent file
is `missing`, never an invented converter error. Missing inputs are retained in
the field receipt and block trial freezing. Existing sparse development maps
cannot establish full-corpus assessment coverage. The map proves source binding;
genuine converter execution still needs its actual producer receipts. The current
fixed-200 replay controller is not a general 10,000-paper converter runner.

OCR is either disabled for the whole corpus or `empty_native_local`. The latter
requires `ocr_identity` with exact `engine`, `revision`, and `configuration` from
the pinned local Windows OCR runtime. Every eligible empty-native page must have
an entry in `--ocr-caches`, mapping its document ID to six descriptors:
`preparation`, `candidate`, `execution`, `raw_ocr`, `page_image`, `crop_image`.
Each descriptor has `relative` and raw-byte `sha256`. These are actual artifacts
from `image_ocr prepare` and `recognize`, with the retrieval document ID as
`source_id`, the full first page as crop, and the current complete code identity.
The source can be an immutable private copy of the original external PDF with
the same bytes. The builder verifies original render, raw text, crop, producer
lineage and exact frozen runtime/configuration. This policy fixes OCR rendering
at 144 DPI for every eligible page. Cropped, corrected or reviewed
substitutions are rejected in this route. Successful raw OCR fills only body;
it supplies no inferred title, abstract, native offsets or admission authority.
Error/truncated outputs stay held. Missing eligible executions block freezing.
Nonempty corrupt native text, native extraction errors, and page mismatches
remain explicit holds; this policy does not silently replace them with OCR.

Example field build (paths are relative to the private root):

```sh
python -m src.parallel_source_v4.fields \
  --data-root /authorized/TRACE-GC_RealPaper_Test \
  --source-root /authorized/original-pdfs \
  --manifest runs/preparation/manifest.json \
  --corpus-policy protocol/corpus-field-policy.json \
  --abstract-assessments runs/all-corpus-assessments.json \
  --ocr-caches runs/all-eligible-ocr-assets.json \
  --output runs/final-fields.json
```

Omit the assessment/OCR arguments only when their policy disables the route.
Every document remains in the corpus. The policy receipt reports independent
axes for native extraction, cached-page match, abstract decisions, OCR decisions,
searchability, and empty title/abstract/body counts; these axes overlap and must
not be summed into one denominator. Each decision axis sums to the full corpus.
No target-specific repair or generated corpus/model output belongs in the repo.

Source/page/image/native files are verified at run start and immediately before
completion. At freeze, start and end, the wrapper also reconstructs the entire
field receipt from its owned `build_inputs`, original PDF/native buffers and
actual assessment/OCR artifacts. All derived fields, eligibility, decisions,
provenance and input descriptors must match; only elapsed build time is excluded.
Changing claimed eligibility or recomputing a self-hash cannot prove coverage.
This runs in `--field-verifier-python`, the same pinned PDF environment used for
preparation/building; the model environment may use different PDF dependencies.
The verifier interpreter/base interpreter hashes and full installed-distribution
receipt are frozen and checked throughout the experiment. Full reconstruction
adds source I/O and rendering time to the measured wall time; this is
not counted as model-only latency. Parsed JSON and its file hash use the same byte buffer. Model,
field, query, code and runtime identities are checked after dense production,
after model loading, after each evaluation and again at publication. Saved
dense artifacts and measured outputs also undergo final readback. Modified
inputs or an unavailable runtime produce a redacted `BLOCKED` receipt; a
ranking change under target permutation produces `FAIL`. Intermediate result
files explicitly remain pending until `receipt.json` says `COMPLETE`.

The receipt records total wall/current-process CPU time and separate dense
production and reranker-load timings, including elapsed time on failed loads.
Each evaluation also records its measured ranking-stage times. It records the operating
system's lifetime peak resident memory for the wrapper process, including its
model threads. It does **not** claim host-wide or child-process memory. This
scope includes preflight work and model loading; it is not an isolated model
benchmark. All calls use local model files and produce no graph writes.

The wrapper refuses to reuse an output directory. An interrupted directory is
retained for diagnosis; start a new wrapper run rather than treating a partial
receipt as complete. Its dense checkpoints remain individually bound, but this
wrapper does not claim whole-experiment resume support. A numerical `COMPLETE`
receipt does not close the issue: attributed relevance judgments, miss
classification, f115/f076 source readback and the required comparable ablations
remain separate deliverables. `issue_acceptance_complete` stays false.

## Review and interpretation

Review f115 and f076 from the original first-page images and native lines.
Report the exact page-one title, abstract, and body lengths alongside their
searchability states. For misses, inspect candidate-stage recall before
attributing failure to the reranker. Record competing relevant documents with
attributed source-first judgments. Do not silently remove unsearchable pages
from the denominator or claim that first-page retrieval measures full-paper
retrieval. Keep all raw text and per-query details outside this repository.

Before interpreting competing results, freeze a separate relevance-review
protocol: pool the top ten document IDs across the non-permuted measured arms
for each query, deduplicate, and order by a fixed hash of query ID plus document
ID. Hide arm names, scores, ranks and known-item target labels from the reviewer.
Supply query text and the exact bound source page; retain a source/field identity,
reviewer identity and kind, timestamp, relevance decision, scope and uncertainty
for every pair. Record previous exposure honestly. Review unresolved/disputed
items explicitly; unjudged documents are not automatically irrelevant. Keep
known-item recall/MRR separate from these judgments. Internal assistant reviews
must not be called independent human judgments. A later independent query set
is still required for generalization claims after tuning on these 60 queries.

## Sanitized metrics report

Run `python -m src.retrieval_trial_report --trial-dir DIR --output FILE` against
a completed private trial directory, with a new output file. The
`retrieval-trial-sanitized-metrics-v1` schema separates candidate-channel
recall from final-stage top-one, top-ten and MRR metrics, preserves NOT_RUN
channels, and labels candidate-order-only results as not reranked. It exports
only allowlisted aggregate measurements, hashes and fixed statuses; permutation
arms contribute statuses, not quality scores. Private IDs, text, paths and
rankings are excluded.

The reporter requires the primary results and every declared ablation with its
target-permutation results. It checks the receipt dimensions, every listed
file's hash, and the consistency of candidate-pool membership, ranks and
channel metrics. Receipt and result files must be regular files. Input errors
use fixed codes and may identify an arm by its predefined name. The report
certifies arithmetic consistency and always sets `issue_acceptance_complete`
to false. It is ready to run once the real corpus trial exists.
