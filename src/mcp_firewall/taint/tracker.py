import structlog

from typing import Set, Any

logger = structlog.get_logger()

                                                                 

_taint_store: Set[str] = set()

def clear_taint():

    _taint_store.clear()

def mark_tainted(data: Any, source: str) -> None:

    if isinstance(data, str):

                                                                                             

        if len(data) > 20:

            _taint_store.add(data)

            logger.info("Marked string as tainted", source=source, length=len(data))

    elif isinstance(data, dict):

        for v in data.values():

            mark_tainted(v, source)

    elif isinstance(data, list):

        for item in data:

            mark_tainted(item, source)

def check_taint(arguments: Any) -> bool:

    if not _taint_store:

        return False

        

    arg_str = str(arguments)

    for tainted in _taint_store:

        if tainted in arg_str:

            return True

            

    return False

