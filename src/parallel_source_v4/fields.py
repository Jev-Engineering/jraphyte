"""Build source-hashed, query-independent fields from a prepared page-one manifest."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from trace_gc.pdf_source_parallel_v4 import digest_value,source_lines,validate_lines
from .common import REPO,child,data_root,digest,method_hashes,write_once
from .retrieval import ASSESSMENT_VERSION,extract_fields,verify_source_bound_assessment

METHODS = frozenset({'parallel_structure_v4','parallel_grobid_v4','parallel_mineru_v4','parallel_olmocr_v4'})
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


def parse_bound_json(raw: bytes):
    """Reject ambiguous duplicate keys before binding a manifest or assessment."""
    def unique_pairs(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate_key_in_bound_json')
            result[key]=value
        return result
    def reject_constant(value):
        raise ValueError('nonfinite_value_in_bound_json:'+value)
    return json.loads(raw.decode('utf-8'),object_pairs_hook=unique_pairs,parse_constant=reject_constant)


def verified_json(path: Path, expected_sha256: str, error: str):
    """Parse precisely the bytes whose hash was checked."""
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected_sha256:
        raise ValueError(error)
    return parse_bound_json(raw)


def strict_json(path: Path):
    return parse_bound_json(path.read_bytes())


def source_path(root: Path, row: dict, source_root: Path | None) -> Path:
    scope=row.get('source_root_id','data_root')
    if scope=='data_root':
        return child(root,row['source_relative'])
    if scope=='external' and source_root is not None:
        external=Path(source_root).expanduser().resolve()
        if not external.is_dir():raise ValueError('authorized_external_source_root_missing')
        return child(external,row['source_relative'])
    raise ValueError('explicit_authorized_source_root_required')


def verify_pinned_source(root: Path, row: dict, source_root: Path | None) -> tuple[list[dict],list[float],dict]:
    """Reread original visual and native evidence; flag a divergent page copy."""
    import fitz
    from PIL import Image,ImageChops
    state=row.get('native_extraction_state','complete')
    error=row.get('native_extraction_error')
    if not ((state=='complete' and error is None) or
            (state=='error' and error=='source_box_outside_first_page')):
        raise ValueError('invalid_native_extraction_state_or_error')
    source=source_path(root,row,source_root)
    paths={'source':source, **{k:child(root,row[k+'_relative']) for k in ('page','image','native')}}
    for key,path in paths.items():
        if key=='native':continue
        if digest(path)!=row[key+'_sha256']:
            raise ValueError('field_source_hash_mismatch:'+key)
    native=verified_json(paths['native'],row['native_sha256'],'field_source_hash_mismatch:native')
    with fitz.open(source) as original,fitz.open(paths['page']) as extracted:
        if not len(original) or len(extracted)!=1:
            raise ValueError('retrieval_fields_require_first_physical_page')
        left=original[0].get_pixmap(dpi=120,alpha=False)
        right=extracted[0].get_pixmap(dpi=120,alpha=False)
        page_cache={'state':'matched_under_2_channel_tolerance','max_channel_delta':0,
                    'changed_channels':0,'source_renderer':'pymupdf_120dpi_original_first_page',
                    'cached_renderer':'pymupdf_120dpi_saved_one_page_pdf'}
        if (left.width,left.height)!=(right.width,right.height):
            page_cache.update(state='render_mismatch_review_required',max_channel_delta=None,
                              changed_channels=None,dimension_mismatch=True)
        if left.samples!=right.samples:
            if (left.width,left.height)==(right.width,right.height):
                a=Image.frombytes('RGB',(left.width,left.height),left.samples)
                b=Image.frombytes('RGB',(right.width,right.height),right.samples)
                difference=ImageChops.difference(a,b)
                maximum=max(channel[1] for channel in difference.getextrema())
                changed=sum(1 for value in difference.tobytes() if value)
                page_cache.update(max_channel_delta=maximum,changed_channels=changed)
                if maximum>2:
                    page_cache['state']='render_mismatch_review_required'
        with Image.open(paths['image']) as image:
            image=image.convert('RGB')
            if image.size!=(left.width,left.height) or image.tobytes()!=left.samples:
                raise ValueError('review_image_does_not_match_original_first_page')
        page_size=[original[0].rect.width,original[0].rect.height]
        try:
            current=source_lines(original[0])
        except ValueError as exc:
            if row.get('native_extraction_error')!=str(exc) or str(exc)!='source_box_outside_first_page':
                raise ValueError('native_extraction_error_does_not_match_original') from exc
            current=[]
        else:
            if row.get('native_extraction_error') is not None:
                raise ValueError('stale_native_extraction_error')
    native=validate_lines(native,page_size)
    if digest_value(current)!=digest_value(native):
        raise ValueError('pinned_native_differs_from_original_under_current_runtime')
    for key in ('source','page','image'):
        if digest(paths[key])!=row[key+'_sha256']:
            raise ValueError('field_source_changed_during_verification:'+key)
    return native,page_size,page_cache


def assessment_entries(mapping: dict | None, ids: set[str]) -> tuple[str | None, dict[str, dict]]:
    """Validate an explicit, query-independent map of immutable assessment files."""
    if mapping is None:
        return None, {}
    if not isinstance(mapping,dict) or mapping.get('schema_version')!='retrieval-assessment-map-v1':
        raise ValueError('invalid_abstract_assessment_map_schema')
    method=mapping.get('method')
    if (method not in METHODS or mapping.get('extractor_version')!=ASSESSMENT_VERSION or
            not isinstance(mapping.get('entries'),list)):
        raise ValueError('explicit_supported_assessment_method_and_entries_required')
    found={}
    for entry in mapping['entries']:
        if not isinstance(entry,dict):
            raise ValueError('invalid_assessment_mapping_entry')
        sid=entry.get('sample_id')
        if not isinstance(sid,str) or sid not in ids or sid in found:
            raise ValueError('duplicate_or_unknown_assessment_sample_id')
        if not isinstance(entry.get('assessment_relative'),str) or any(
                not isinstance(entry.get(k),str) or not SHA256.fullmatch(entry[k])
                for k in ('assessment_sha256','native_sha256')):
            raise ValueError('assessment_mapping_requires_file_and_hashes')
        parts=Path(entry['assessment_relative'].replace('\\','/')).parts
        if not any(parts[i:i+2]==('assessments',method) for i in range(len(parts)-1)):
            raise ValueError('assessment_path_does_not_match_declared_method')
        found[sid]=entry
    return method,found


def bound_assessment(root: Path, entry: dict, row: dict, native: list[dict], page_size: list[float],
                     expected_version: str) -> dict:
    """An assessment seal does not by itself prove a source span exists."""
    if entry['native_sha256']!=row['native_sha256']:
        raise ValueError('assessment_native_representation_mismatch')
    path=child(root,entry['assessment_relative'])
    assessment=verified_json(path,entry['assessment_sha256'],'assessment_file_hash_mismatch')
    if not isinstance(assessment,dict):
        raise ValueError('assessment_record_required')
    if assessment.get('extractor_version')!=expected_version:
        raise ValueError('assessment_extractor_version_mismatch')
    verify_source_bound_assessment(assessment,native,page_size=page_size,
                                   source_sha256=row['source_sha256'],page_sha256=row['page_sha256'])
    return assessment


def build_fields(root: Path, manifest: dict, output: Path, *, title_reviews=None, ocr_caches=None,
                 abstract_assessments=None, source_root: Path | None=None) -> dict:
    import fitz
    import PIL
    started=time.perf_counter(); fields=[]; ids=set(); rows=manifest['pdfs']
    bound_code=method_hashes(REPO)
    current_extractor={'python':sys.version.split()[0],'pymupdf':fitz.VersionBind,
                       'mupdf':fitz.VersionFitz,'pillow':PIL.__version__,
                       'source_module_sha256':digest(REPO/'trace_gc/pdf_source_parallel_v4.py'),
                       'retrieval_preparer_sha256':digest(REPO/'src/parallel_source_v4/retrieval_prepare.py'),
                       'render_dpi':120}
    recorded_extractor=manifest.get('native_extractor')
    expected_extractor=dict(current_extractor)
    if manifest.get('stage')!='retrieval_source_first_no_predictions':
        expected_extractor.pop('retrieval_preparer_sha256')
    if recorded_extractor is not None and recorded_extractor!=expected_extractor:
        raise ValueError('native_preparation_environment_or_code_mismatch')
    for row in rows:
        sid=row['sample_id']
        if not isinstance(sid,str) or sid in ids:raise ValueError('duplicate_field_document_id')
        ids.add(sid)
    method,entries=assessment_entries(abstract_assessments,ids)
    for row in manifest['pdfs']:
        sid=row['sample_id']
        if row.get('physical_page')!=1:raise ValueError('retrieval_fields_require_first_physical_page')
        native,page_size,page_cache=verify_pinned_source(root,row,source_root)
        if (page_cache['state']=='render_mismatch_review_required' and
                (sid in entries or sid in (title_reviews or {}) or sid in (ocr_caches or {}))):
            raise ValueError('derived_fields_require_matching_cached_page:'+sid)
        assessment=bound_assessment(root,entries[sid],row,native,page_size,abstract_assessments['extractor_version']) if sid in entries else None
        field=extract_fields(sid,native,page_size=page_size,source_sha256=row['source_sha256'],page_sha256=row['page_sha256'],image_sha256=row['image_sha256'],
                             abstract_assessment=assessment,reviewed_title=(title_reviews or {}).get(sid),ocr_cache=(ocr_caches or {}).get(sid))
        field['native_sha256']=row['native_sha256']
        field['native_extraction_state']=row.get('native_extraction_state','complete')
        field['native_extraction_error']=row.get('native_extraction_error')
        field['image_sha256']=row['image_sha256']
        field['source_root_id']=row.get('source_root_id','data_root')
        field['native_representation_sha256']=digest_value(native)
        field['native_representation']='pinned_saved_first_page_native_json'
        field['cached_page_render']=page_cache
        field['native_preparation_sha256']=digest_value(recorded_extractor) if recorded_extractor else None
        field['abstract_assessment_state']=assessment['status'] if assessment else 'missing'
        if assessment:
            field['field_provenance'].setdefault('abstract_assessment',{}).update({
                'declared_method':method,'extractor_version':assessment.get('extractor_version'),
                'schema_version':assessment.get('schema_version'),
                'assessment_sha256':assessment['assessment_sha256'],
                'assessment_file_sha256':entries[sid]['assessment_sha256'],
                'native_sha256':row['native_sha256'],'source_reviewed':False})
        field['fields_sha256']=digest_value({k:v for k,v in field.items() if k!='fields_sha256'})
        fields.append(field)
    end_extractor={'python':sys.version.split()[0],'pymupdf':fitz.VersionBind,
                   'mupdf':fitz.VersionFitz,'pillow':PIL.__version__,
                   'source_module_sha256':digest(REPO/'trace_gc/pdf_source_parallel_v4.py'),
                   'retrieval_preparer_sha256':digest(REPO/'src/parallel_source_v4/retrieval_prepare.py'),
                   'render_dpi':120}
    for row in rows:
        paths={'source':source_path(root,row,source_root),
               **{key:child(root,row[key+'_relative']) for key in ('page','image','native')}}
        for key,path in paths.items():
            if digest(path)!=row[key+'_sha256']:
                raise ValueError('field_input_changed_before_publication:'+row['sample_id']+':'+key)
    for sid,entry in entries.items():
        if digest(child(root,entry['assessment_relative']))!=entry['assessment_sha256']:
            raise ValueError('assessment_changed_before_field_publication:'+sid)
    if method_hashes(REPO)!=bound_code or end_extractor!=current_extractor:
        raise ValueError('field_builder_code_changed_during_run')
    result={'fields':fields,'fields_sha256':digest_value(fields),'field_count':len(fields),
            'unsearchable_ids':[x['id'] for x in fields if not x['searchable']], 'query_independent':True,
            'manifest_sha256':digest_value(manifest),
            'native_verification_environment':current_extractor,
            'field_builder_code_sha256':bound_code,
            'final_input_readback':'all_source_page_image_native_hashes_match',
            'final_input_readback_count':len(rows),
            'title_review_map_sha256':digest_value(title_reviews) if title_reviews is not None else None,
            'ocr_cache_map_sha256':digest_value(ocr_caches) if ocr_caches is not None else None,
            'native_preparation':recorded_extractor or 'legacy_manifest_did_not_record_extractor_identity',
            'source_verification':'original_first_page_render_and_native_readback',
            'assessment_map_sha256':digest_value(abstract_assessments) if abstract_assessments is not None else None,
            'assessment_method':method,
            'assessment_method_provenance':'caller_declared_and_assessment_path_scoped',
            'abstract_assessment_counts':{state:sum(x['abstract_assessment_state']==state for x in fields)
                                          for state in sorted({x['abstract_assessment_state'] for x in fields})},
            'native_extraction_counts':{state:sum(x['native_extraction_state']==state for x in fields)
                                        for state in sorted({x['native_extraction_state'] for x in fields})},
            'cached_page_render_mismatch_ids':[x['id'] for x in fields
                                               if x['cached_page_render']['state']=='render_mismatch_review_required'],
            'cached_page_render_state_counts':{state:sum(x['cached_page_render']['state']==state for x in fields)
                                               for state in sorted({x['cached_page_render']['state'] for x in fields})},
            'runtime_seconds':time.perf_counter()-started,'new_paid_api_calls':0,'production_graph_writes':0}
    write_once(output,result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data-root');p.add_argument('--manifest',required=True)
    p.add_argument('--title-reviews');p.add_argument('--ocr-caches');p.add_argument('--abstract-assessments');p.add_argument('--source-root');p.add_argument('--output',required=True)
    a=p.parse_args();root=data_root(a.data_root)
    build_fields(root,strict_json(child(root,a.manifest)),child(root,a.output),
                 title_reviews=strict_json(child(root,a.title_reviews)) if a.title_reviews else None,
                 ocr_caches=strict_json(child(root,a.ocr_caches)) if a.ocr_caches else None,
                 abstract_assessments=strict_json(child(root,a.abstract_assessments)) if a.abstract_assessments else None,
                 source_root=Path(a.source_root) if a.source_root else None)
    return 0


if __name__=='__main__':raise SystemExit(main())
