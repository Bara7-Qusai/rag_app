from fastapi import FastAPI, APIRouter, status, Request
from fastapi.responses import JSONResponse, StreamingResponse
from routes.schemes.nlp import PushRequest, SearchRequest
from models.ProjectModel import ProjectModel
from models.ChunkModel import ChunkModel
from models.AssetModel import AssetModel
from controllers import NLPController
from models import ResponseSignal

import logging
import asyncio
import json

logger = logging.getLogger('uvicorn.error')

nlp_router = APIRouter(
    prefix="/api/v1/nlp",
    tags=["api_v1", "nlp"],
)

@nlp_router.post("/index/push/{project_id}")
async def index_project(request: Request, project_id: int):

    try:
        body = await request.json()
        push_request = PushRequest(**body)
    except Exception as e:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Invalid JSON body"}
        )

    project_model = await ProjectModel.create_instance(
        db_client=request.app.db_client
    )

    chunk_model = await ChunkModel.create_instance(
        db_client=request.app.db_client
    )

    project = await project_model.get_project_or_create_one(
        project_id=project_id
    )

    if not project:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.PROJECT_NOT_FOUND_ERROR.value
            }
        )
    
    asset_filter_id = None
    if push_request.file_id:
        if push_request.file_id.isdigit():
            asset_filter_id = int(push_request.file_id)
        else:
            asset_model = await AssetModel.create_instance(
                db_client=request.app.db_client
            )
            asset_record = await asset_model.get_asset_record(
                asset_project_id=project.project_id,
                asset_name=push_request.file_id
            )
            if asset_record is None:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"signal": ResponseSignal.FILE_ID_ERROR.value}
                )
            asset_filter_id = asset_record.asset_id
    else:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": "file_id_required", "detail": "file_id is required for indexing to prevent data inconsistency"}
        )
    
    logger.info(f"Starting index push for project {project_id}, file_id: {push_request.file_id}, asset_filter_id: {asset_filter_id}, do_reset: {push_request.do_reset}")

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    async def process_batch(batch_chunks, batch_ids, reset_flag):
        logger.info(f"Starting to process batch with {len(batch_chunks)} chunks")
        result = await nlp_controller.index_into_vector_db(
            project=project,
            chunks=batch_chunks,
            chunks_ids=batch_ids,
            do_reset=reset_flag,
        )
        logger.info(f"Finished processing batch with {len(batch_chunks)} chunks, inserted {result} vectors")
        return result

    page_no = 1
    inserted_items_count = 0
    idx = 0
    first_batch = True

        # create collection if not exists
    collection_name = nlp_controller.create_collection_name(project_id=project.project_id)

    _ = await request.app.vectordb_client.create_collection(
        collection_name=collection_name,
        embedding_size=request.app.embedding_client.embedding_size,
        do_reset=push_request.do_reset,
    )

    if push_request.do_reset and asset_filter_id:
        logger.warning(f"do_reset=1 with file_id provided: resetting entire collection for project {project_id}, not just file {push_request.file_id}")


    while True:
        page_chunks = await chunk_model.get_project_chunks(
            project_id=project.project_id,
            page_no=page_no,
            page_size=200,
            asset_id=asset_filter_id,
        )

        if not page_chunks:
            break

        if page_chunks:
            page_no += 1

        logger.info(f"Processing page {page_no-1} with {len(page_chunks)} chunks")

        chunks_ids = list(range(idx, idx + len(page_chunks)))
        idx += len(page_chunks)

        reset_flag = bool(push_request.do_reset) if first_batch else False
        first_batch = False

        # Process batch sequentially to avoid concurrency issues
        try:
            result = await process_batch(page_chunks, chunks_ids, reset_flag)
            if result == 0:
                logger.error("Batch processing returned 0 inserted vectors")
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={"signal": ResponseSignal.INSERT_INTO_VECTORDB_ERROR.value, "detail": "Batch processing returned 0 inserted vectors"}
                )
            inserted_items_count += result
        except Exception as e:
            logger.error(f"Batch error: {e}")
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"signal": ResponseSignal.INSERT_INTO_VECTORDB_ERROR.value, "detail": str(e)}
            )

    # All processing done sequentially
    # inserted_items_count is now the actual number of vectors inserted

    logger.info(f"Index push completed for project {project_id}, file_id: {push_request.file_id}, total inserted vectors: {inserted_items_count}")

    return JSONResponse(
        content={
            "signal": ResponseSignal.INSERT_INTO_VECTORDB_SUCCESS.value,
            "inserted_items_count": inserted_items_count
        }
    )

@nlp_router.post("/index/search/{project_id}")
async def search_index(request: Request, project_id: int, search_request: SearchRequest):
    
    project_model = await ProjectModel.create_instance(
        db_client=request.app.db_client
    )

    project = await project_model.get_project_or_create_one(
        project_id=project_id
    )

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    results = await nlp_controller.search_vector_db_collection(
        project=project, text=search_request.text, limit=search_request.limit
    )

    if not results:
        return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "signal": ResponseSignal.VECTORDB_SEARCH_ERROR.value
                }
            )
    
    return JSONResponse(
        content={
            "signal": ResponseSignal.VECTORDB_SEARCH_SUCCESS.value,
            "results": [ result.dict()  for result in results ]
        }
    )

@nlp_router.get("/index/info/{project_id}")
async def get_project_index_info(request: Request, project_id: int):
    
    project_model = await ProjectModel.create_instance(
        db_client=request.app.db_client
    )

    project = await project_model.get_project_or_create_one(
        project_id=project_id
    )

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    collection_name = nlp_controller.create_collection_name(project_id=project.project_id)
    logger.info(f"Info endpoint: collection_name = {collection_name} for project {project_id}")

    collection_info = await nlp_controller.get_vector_db_collection_info(project=project)

    if not collection_info:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.VECTORDB_COLLECTION_NOT_FOUND.value
            }
        )

    return JSONResponse(
        content={
            "signal": ResponseSignal.VECTORDB_COLLECTION_RETRIEVED.value,
            "collection_info": collection_info
        }
    )

@nlp_router.get("/index/debug/{project_id}")
async def debug_project_index(request: Request, project_id: int):
    
    project_model = await ProjectModel.create_instance(
        db_client=request.app.db_client
    )

    project = await project_model.get_project_or_create_one(
        project_id=project_id
    )

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    collection_name = nlp_controller.create_collection_name(project_id=project.project_id)
    
    # Get collection info
    collection_info = await nlp_controller.get_vector_db_collection_info(project=project)
    
    if not collection_info:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.VECTORDB_COLLECTION_NOT_FOUND.value,
                "collection_name": collection_name
            }
        )
    
    # Get sample records - using a zero vector for debugging
    try:
        sample_records = await request.app.vectordb_client.search_by_vector(
            collection_name=collection_name,
            vector=[0.0] * request.app.embedding_client.embedding_size,
            limit=5
        )
    except Exception as e:
        sample_records = []
        logger.error(f"Error getting sample records: {e}")
    
    return JSONResponse(
        content={
            "signal": ResponseSignal.VECTORDB_COLLECTION_RETRIEVED.value,
            "collection_name": collection_name,
            "collection_info": collection_info,
            "sample_records": [record.__dict__ if hasattr(record, '__dict__') else record for record in sample_records] if sample_records else []
        }
    )

@nlp_router.get("/index/chunks/{project_id}")
async def get_project_chunks_info(request: Request, project_id: int, file_id: str = None):
    
    project_model = await ProjectModel.create_instance(
        db_client=request.app.db_client
    )

    project = await project_model.get_project_or_create_one(
        project_id=project_id
    )

    if not project:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.PROJECT_NOT_FOUND_ERROR.value
            }
        )

    chunk_model = await ChunkModel.create_instance(
        db_client=request.app.db_client
    )

    asset_filter_id = None
    if file_id:
        if file_id.isdigit():
            asset_filter_id = int(file_id)
        else:
            asset_model = await AssetModel.create_instance(
                db_client=request.app.db_client
            )
            asset_record = await asset_model.get_asset_record(
                asset_project_id=project.project_id,
                asset_name=file_id
            )
            if asset_record is None:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"signal": ResponseSignal.FILE_ID_ERROR.value}
                )
            asset_filter_id = asset_record.asset_id

    # Get total chunks for the project or specific asset
    total_chunks = 0
    page_no = 1
    while True:
        chunks = await chunk_model.get_project_chunks(
            project_id=project.project_id,
            page_no=page_no,
            page_size=1000,
            asset_id=asset_filter_id
        )
        if not chunks:
            break
        total_chunks += len(chunks)
        page_no += 1

    return JSONResponse(
        content={
            "signal": ResponseSignal.CHUNKS_INFO_RETRIEVED.value,
            "project_id": project_id,
            "file_id": file_id,
            "asset_id": asset_filter_id,
            "total_chunks": total_chunks
        }
    )

@nlp_router.post("/index/answer/{project_id}")
async def answer_index_question(request: Request, project_id: int, search_request: SearchRequest):
    project_model = await ProjectModel.create_instance(
        db_client=request.app.db_client
    )

    project = await project_model.get_project_or_create_one(
        project_id=project_id
    )

    if not project:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": ResponseSignal.PROJECT_NOT_FOUND_ERROR.value}
        )

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    logger.info(f"RAG question received for project {project_id}: '{search_request.text}', limit={search_request.limit}")
    answer = await nlp_controller.answer_rag_question(
        project=project,
        query=search_request.text,
        limit=search_request.limit or 10,
    )
    logger.info(f"RAG controller returned answer keys: {list(answer.keys()) if isinstance(answer, dict) else 'none'}")

    if not answer or not answer.get("answer"):
        error_content = {"signal": ResponseSignal.RAG_ANSWER_ERROR.value}
        if answer and answer.get("raw_output"):
            error_content["raw_output"] = answer["raw_output"]
        if answer and answer.get("reason"):
            error_content["reason"] = answer["reason"]
        if answer and answer.get("query"):
            error_content["query"] = answer["query"]
        logger.error(f"RAG answer error for project {project_id}: {error_content}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=error_content
        )

    report = answer.get("answer")
    if isinstance(report, str):
        try:
            report = json.loads(report)
        except (json.JSONDecodeError, TypeError):
            report = {"raw": report}

    return JSONResponse(
        content={
            "signal": ResponseSignal.RAG_ANSWER_SUCCESS.value,
            "report": report
        }
    )


@nlp_router.post("/index/summarize/{project_id}")
async def summarize_project(request: Request, project_id: int):
    """
    يُشغَّل بعد /index/push مباشرةً.
    يقرأ chunks المفهرسة من PGVector، يولد ملخصاً أمنياً شاملاً،
    ويُخزّنه كـ chunk مميز (RAPTOR level-1) للاسترجاع السريع لاحقاً.
    Body (اختياري): { "file_id": "اسم الملف للتوثيق" }
    """
    try:
        body = await request.json()
        file_label = body.get("file_id", f"project_{project_id}")
    except Exception:
        file_label = f"project_{project_id}"

    project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
    project = await project_model.get_project_or_create_one(project_id=project_id)
    if not project:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": ResponseSignal.PROJECT_NOT_FOUND_ERROR.value}
        )

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    logger.info(f"Generating RAPTOR summary for project {project_id}, label={file_label}")
    summary = await nlp_controller.generate_file_summary(project=project, file_label=file_label)

    if summary.get("error"):
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"signal": "SUMMARY_GENERATION_FAILED", "detail": summary["error"]}
        )

    return JSONResponse(content={
        "signal": "SUMMARY_GENERATED_SUCCESS",
        "project_id": project_id,
        "file_label": file_label,
        "summary": summary,
    })

