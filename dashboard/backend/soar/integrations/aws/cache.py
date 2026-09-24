"""Security Hub·Inspector 가 함께 쓰는 프로세스 메모리 캐시.

잠금과 저장소를 하나로 둔다. 둘로 나누면 동시 요청이 같은 목록을 중복 조회해
GetFindings 호출 한도(TooManyRequests)에 걸린다.
ponytail: 프로세스 메모리 캐시. 워커를 여러 프로세스로 늘리면 공유 캐시로.
"""
import threading


class SharedCache:
    def __init__(self):
        self.lock = threading.Lock()
        self.entries = {}
