"""Prepare hash-bound first-page retrieval fields from an authorized external corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path

from trace_gc.pdf_source_parallel_v4 import digest_value,source_lines
from .common import REPO, child, data_root, digest, within, write_once
from .fields import parse_bound_json

ID = re.compile(r'[A-Za-z0-9_-]+\Z')


def read_hashed_json(path: Path) -> tuple[dict,str]:
    raw=path.read_bytes()
    return parse_bound_json(raw),hashlib.sha256(raw).hexdigest()


def owned(destination: Path, path: Path) -> Path:
    path=Path(path)
    if path.is_symlink() or (hasattr(path,'is_junction') and path.is_junction()):
        raise ValueError('retrieval_preparation_linked_output_not_owned')
    return within(destination,path)


def _inputs(data: Path, source_root: Path, retrieval: dict, index: dict) -> list[tuple[dict,Path,str]]:
    rows=retrieval.get('pdfs')
    ids=index.get('document_ids')
    if (not isinstance(rows,list) or not isinstance(ids,list) or not rows or
            len(rows)!=len(ids) or len(ids)!=len(set(ids))):
        raise ValueError('retrieval_requires_exact_unique_index_documents')
    result=[]; works=set()
    for number,(row,sid) in enumerate(zip(rows,ids)):
        if (not isinstance(row,dict) or not isinstance(sid,str) or not ID.fullmatch(sid) or
                row.get('sample_id')!=sid or not isinstance(row.get('work_id'),str) or
                not row['work_id'] or row['work_id'] in works):
            raise ValueError('retrieval_source_index_identity_mismatch:'+str(number))
        works.add(row['work_id'])
        raw=row.get('source_path')
        if not isinstance(raw,str):raise ValueError('retrieval_source_path_missing:'+sid)
        source=Path(raw).expanduser().resolve()
        if not source.is_file() or not source.is_relative_to(source_root):
            raise ValueError('retrieval_source_outside_authorized_root_or_missing:'+sid)
        relative=source.relative_to(source_root).as_posix()
        if child(source_root,relative)!=source:
            raise ValueError('retrieval_source_path_not_stable:'+sid)
        result.append((row,source,relative))
    return result


def prepare_retrieval(data_root_path: Path, source_root_path: Path, retrieval: dict, index: dict,
                      destination: Path, *, input_hashes: dict | None=None) -> dict:
    import fitz
    import PIL
    data=Path(data_root_path).resolve();source_root=Path(source_root_path).resolve()
    destination=within(data,destination)
    if (not source_root.is_dir() or source_root==data or data in source_root.parents or
            source_root in data.parents or REPO==source_root or REPO in source_root.parents or
            source_root in REPO.parents):
        raise ValueError('explicit_external_read_only_source_root_required')
    if destination==data or destination.relative_to(data).parts[0] in {'validation_v2','validation_expanded200','validation_200_10k'}:
        raise ValueError('retrieval_preparation_requires_new_owned_output')
    items=_inputs(data,source_root,retrieval,index)
    extractor={'python':sys.version.split()[0],'pymupdf':fitz.VersionBind,
               'mupdf':fitz.VersionFitz,'pillow':PIL.__version__,
               'source_module_sha256':digest(REPO/'trace_gc/pdf_source_parallel_v4.py'),
               'retrieval_preparer_sha256':digest(REPO/'src/parallel_source_v4/retrieval_prepare.py'),
               'render_dpi':120}
    protocol={'schema_version':'retrieval-preparation-v2',
              'retrieval_input_sha256':digest_value(retrieval),'index_input_sha256':digest_value(index),
              'source_root':str(source_root),'native_extractor':extractor,
              'input_file_hashes':input_hashes or {}}
    if destination.exists():
        path=owned(destination,destination/'protocol.json')
        if not path.is_file() or read_hashed_json(path)[0]!=protocol:
            raise ValueError('retrieval_preparation_protocol_or_owner_mismatch')
    else:
        destination.mkdir(parents=True)
        write_once(destination/'protocol.json',protocol)
    pages=owned(destination,destination/'pages')
    prepared=[]
    for original,source,relative in items:
        sid=original['sample_id'];folder=owned(destination,pages/sid)
        if folder.is_dir():
            receipt_file=owned(destination,folder/'receipt.json')
            if not receipt_file.is_file():raise ValueError('incomplete_retrieval_page_receipt:'+sid)
            row=read_hashed_json(receipt_file)[0]
            expected_paths={key:owned(destination,folder/name) for key,name in
                            {'page':'page.pdf','image':'page.png','native':'native.json'}.items()}
            if (row.get('sample_id')!=sid or row.get('work_id')!=original['work_id'] or
                    row.get('source_relative')!=relative or row.get('source_root_id')!='external' or
                    row.get('physical_page')!=1 or
                    any(row.get(key+'_relative')!=path.relative_to(data).as_posix()
                        for key,path in expected_paths.items()) or
                    (row.get('native_extraction_state'),row.get('native_extraction_error')) not in
                    {('complete',None),('error','source_box_outside_first_page')}):
                raise ValueError('retrieval_page_receipt_identity_mismatch:'+sid)
            for key,path in {'source':source,**expected_paths}.items():
                if digest(path)!=row[key+'_sha256']:
                    raise ValueError('retrieval_page_receipt_hash_mismatch:'+sid+':'+key)
        else:
            temp=owned(destination,pages/('.'+sid+'-'+uuid.uuid4().hex+'.partial'))
            temp.mkdir(parents=True,exist_ok=False)
            source_hash=digest(source)
            if original.get('source_sha256') and original['source_sha256']!=source_hash:
                raise ValueError('historical_source_hash_mismatch:'+sid)
            with fitz.open(source) as pdf:
                if not len(pdf):raise ValueError('empty_retrieval_source_pdf:'+sid)
                page=pdf[0]
                one=fitz.open();one.insert_pdf(pdf,from_page=0,to_page=0)
                one.save(temp/'page.pdf');one.close()
                page.get_pixmap(dpi=120,alpha=False).save(temp/'page.png')
                try:
                    native=source_lines(page)
                    native_error=None
                except ValueError as exc:
                    # A glyph bounding box can cross the page edge even when
                    # the PDF renders. Preserve the source and an explicit
                    # unsearchable native state; never clip or invent spans.
                    if str(exc)!='source_box_outside_first_page':raise
                    native=[]
                    native_error=str(exc)
            write_once(temp/'native.json',native)
            if digest(source)!=source_hash:raise ValueError('source_changed_during_retrieval_preparation:'+sid)
            final_paths={'page':owned(destination,folder/'page.pdf'),
                         'image':owned(destination,folder/'page.png'),
                         'native':owned(destination,folder/'native.json')}
            row={'sample_id':sid,'work_id':original['work_id'],'physical_page':1,
                 'source_root_id':'external','source_relative':relative,
                 'native_extraction_state':'error' if native_error else 'complete',
                 'native_extraction_error':native_error,
                 **{k+'_relative':p.relative_to(data).as_posix() for k,p in final_paths.items()},
                 'source_sha256':source_hash,
                 **{k+'_sha256':digest(temp/name) for k,name in
                    {'page':'page.pdf','image':'page.png','native':'native.json'}.items()}}
            write_once(temp/'receipt.json',row)
            os.replace(temp,folder)
        if original.get('source_sha256') and original['source_sha256']!=row['source_sha256']:
            raise ValueError('historical_source_hash_mismatch:'+sid)
        prepared.append(row)
    result={'stage':'retrieval_source_first_no_predictions','pdfs':prepared,'field_count':len(prepared),
            'retrieval_input_hashes':input_hashes or {},
            'native_extractor':extractor,
            'query_independent':True,'new_paid_api_calls':0,'production_graph_writes':0}
    write_once(owned(destination,destination/'manifest.json'),result)
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-root',required=True)
    parser.add_argument('--source-root',required=True)
    parser.add_argument('--retrieval-manifest',required=True)
    parser.add_argument('--index-manifest',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    data=data_root(args.data_root)
    retrieval_file=child(data,args.retrieval_manifest)
    index_file=child(data,args.index_manifest)
    retrieval,retrieval_sha=read_hashed_json(retrieval_file)
    index,index_sha=read_hashed_json(index_file)
    result=prepare_retrieval(data,Path(args.source_root),retrieval,index,
                             child(data,args.output),input_hashes={'retrieval_manifest':retrieval_sha,
                                                                    'index_manifest':index_sha})
    print(json.dumps({'status':'PREPARED_RETRIEVAL_INPUTS_NOT_QUALITY_RESULT',
                      'field_count':result['field_count'],'new_paid_api_calls':0,'production_graph_writes':0}))
    return 0


if __name__=='__main__':raise SystemExit(main())
