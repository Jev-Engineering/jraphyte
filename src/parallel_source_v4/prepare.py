"""Render authorized page-one inputs for source-first review; no predictions."""
from __future__ import annotations
import argparse
from pathlib import Path
import re
import sys
from .common import REPO,child,data_root,digest,read,write_once
from trace_gc.pdf_source_parallel_v4 import source_lines


def prepare(root: Path, sources: list[dict], destination: Path) -> dict:
    import fitz
    import PIL
    if destination.exists():raise ValueError('new_preparation_directory_required')
    ids=[r['sample_id'] for r in sources]
    if len(ids)!=len(set(ids)) or not ids:raise ValueError('nonempty_unique_sources_required')
    manifest=[]
    for row in sources:
        sid=row['sample_id']
        if not re.fullmatch(r'[A-Za-z0-9_-]+',sid):raise ValueError('unsafe_sample_id')
        if not row.get('work_id'):raise ValueError('work_identity_required')
        source=child(root,row['source_relative'])
        with fitz.open(source) as pdf:
            page=pdf[0]; native=source_lines(page)
            folder=destination/'pages'/sid;folder.mkdir(parents=True,exist_ok=False)
            one=fitz.open();one.insert_pdf(pdf,from_page=0,to_page=0);one.save(folder/'page.pdf');one.close()
            page.get_pixmap(dpi=120).save(folder/'page.png')
            write_once(folder/'native.json',native)
        paths={'source':source,'page':folder/'page.pdf','image':folder/'page.png','native':folder/'native.json'}
        manifest.append({'sample_id':sid,'work_id':row['work_id'],'physical_page':1,'predictions_examined':False,
                         **{k+'_relative':p.relative_to(root).as_posix() for k,p in paths.items()},
                         **{k+'_sha256':digest(p) for k,p in paths.items()},
                         'conversion_outputs':{name:(destination/'conversions'/name/(sid+'.json')).relative_to(root).as_posix()
                                               for name in ('docling','docling_document','grobid','mineru','olmocr')}})
    result={'pdfs':manifest,'stage':'source_review_inputs_only_no_predictions',
            'native_extractor':{'python':sys.version.split()[0],'pymupdf':fitz.VersionBind,
                                'mupdf':fitz.VersionFitz,'pillow':PIL.__version__,
                                'source_module_sha256':digest(REPO/'trace_gc/pdf_source_parallel_v4.py'),
                                'render_dpi':120}}
    write_once(destination/'manifest.json',result)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--data-root');p.add_argument('--sources',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();root=data_root(a.data_root)
    prepare(root,read(child(root,a.sources)),child(root,a.output))
    return 0


if __name__=='__main__':raise SystemExit(main())
