# -*- coding: utf-8 -*-
"""데모 CVE 카탈로그 생성기. 결과를 app/catalog/vulnerabilities.yaml 로 커밋한다."""
import io

# (cve, 패키지, 설치버전, 수정버전, 심각도, cvss, 계열)
# 계열: os=OS 패키지 · lang=언어 런타임/라이브러리 · app=애플리케이션 서버
SEED = [
    ("CVE-2021-44228", "log4j-core", "2.14.1", "2.15.0", "CRITICAL", 10.0, "lang"),
    ("CVE-2021-45046", "log4j-core", "2.15.0", "2.16.0", "CRITICAL", 9.0, "lang"),
    ("CVE-2022-22965", "spring-beans", "5.3.17", "5.3.18", "CRITICAL", 9.8, "lang"),
    ("CVE-2022-42889", "commons-text", "1.9", "1.10.0", "CRITICAL", 9.8, "lang"),
    ("CVE-2020-36518", "jackson-databind", "2.13.1", "2.13.2.1", "HIGH", 7.5, "lang"),
    ("CVE-2022-42003", "jackson-databind", "2.13.2", "2.13.4.1", "HIGH", 7.5, "lang"),
    ("CVE-2022-42004", "jackson-databind", "2.13.2", "2.13.4", "HIGH", 7.5, "lang"),
    ("CVE-2019-11358", "jquery", "3.3.1", "3.4.0", "MEDIUM", 6.1, "lang"),
    ("CVE-2020-8203", "lodash", "4.17.15", "4.17.19", "HIGH", 7.4, "lang"),
    ("CVE-2021-23337", "lodash", "4.17.20", "4.17.21", "HIGH", 7.2, "lang"),
    ("CVE-2023-4863", "libwebp", "1.2.2", "1.3.2", "CRITICAL", 8.8, "os"),
    ("CVE-2022-37434", "zlib", "1.2.11", "1.2.12", "HIGH", 9.8, "os"),
    ("CVE-2018-25032", "zlib", "1.2.11", "1.2.12", "HIGH", 7.5, "os"),
    ("CVE-2021-3711", "openssl", "1.1.1k", "1.1.1l", "CRITICAL", 9.8, "os"),
    ("CVE-2022-0778", "openssl", "1.1.1l", "1.1.1n", "HIGH", 7.5, "os"),
    ("CVE-2022-2068", "openssl", "1.1.1n", "1.1.1p", "HIGH", 9.8, "os"),
    ("CVE-2023-0215", "openssl", "3.0.7", "3.0.8", "HIGH", 7.5, "os"),
    ("CVE-2023-0286", "openssl", "3.0.7", "3.0.8", "HIGH", 7.4, "os"),
    ("CVE-2023-0464", "openssl", "3.0.8", "3.0.9", "HIGH", 7.5, "os"),
    ("CVE-2021-3712", "openssl", "1.1.1k", "1.1.1l", "HIGH", 7.4, "os"),
    ("CVE-2020-1971", "openssl", "1.1.1g", "1.1.1i", "MEDIUM", 5.9, "os"),
    ("CVE-2015-7547", "glibc", "2.19", "2.23", "CRITICAL", 8.1, "os"),
    ("CVE-2021-33574", "glibc", "2.31", "2.32", "CRITICAL", 9.8, "os"),
    ("CVE-2022-23219", "glibc", "2.31", "2.35", "CRITICAL", 9.8, "os"),
    ("CVE-2021-22946", "curl", "7.74.0", "7.79.0", "HIGH", 7.5, "os"),
    ("CVE-2021-22947", "curl", "7.74.0", "7.79.0", "MEDIUM", 5.9, "os"),
    ("CVE-2022-32221", "curl", "7.83.0", "7.86.0", "CRITICAL", 9.8, "os"),
    ("CVE-2019-5481", "curl", "7.61.0", "7.66.0", "HIGH", 8.8, "os"),
    ("CVE-2023-38408", "openssh", "8.9p1", "9.3p2", "CRITICAL", 9.8, "os"),
    ("CVE-2021-41617", "openssh", "8.2p1", "8.8p1", "MEDIUM", 7.0, "os"),
    ("CVE-2018-15473", "openssh", "7.6p1", "7.7p1", "MEDIUM", 5.3, "os"),
    ("CVE-2016-5195", "linux-kernel", "4.4.0", "4.8.3", "HIGH", 7.8, "os"),
    ("CVE-2022-0847", "linux-kernel", "5.8.0", "5.16.11", "HIGH", 7.8, "os"),
    ("CVE-2021-4034", "polkit", "0.105", "0.120", "HIGH", 7.8, "os"),
    ("CVE-2021-3156", "sudo", "1.8.31", "1.9.5p2", "HIGH", 7.8, "os"),
    ("CVE-2022-1271", "gzip", "1.10", "1.12", "HIGH", 8.8, "os"),
    ("CVE-2021-33560", "libgcrypt", "1.8.5", "1.9.4", "HIGH", 7.5, "os"),
    ("CVE-2016-2183", "openssl", "1.0.2", "1.1.0", "MEDIUM", 7.5, "os"),
    ("CVE-2023-44487", "nghttp2", "1.43.0", "1.57.0", "HIGH", 7.5, "app"),
    ("CVE-2019-9511", "nginx", "1.18.0", "1.19.1", "HIGH", 7.5, "app"),
    ("CVE-2019-9513", "nginx", "1.18.0", "1.19.1", "HIGH", 7.5, "app"),
    ("CVE-2022-41741", "nginx", "1.22.0", "1.23.2", "HIGH", 7.8, "app"),
    ("CVE-2022-41742", "nginx", "1.22.0", "1.23.2", "HIGH", 7.1, "app"),
    ("CVE-2023-21980", "mysql-server", "8.0.32", "8.0.33", "HIGH", 7.1, "app"),
    ("CVE-2023-21912", "mysql-server", "8.0.31", "8.0.33", "HIGH", 7.1, "app"),
    ("CVE-2021-2154", "mysql-server", "8.0.23", "8.0.24", "MEDIUM", 6.5, "app"),
    ("CVE-2023-25690", "apache2", "2.4.54", "2.4.56", "CRITICAL", 9.8, "app"),
    ("CVE-2022-31813", "apache2", "2.4.52", "2.4.54", "CRITICAL", 9.8, "app"),
    ("CVE-2023-24329", "python3", "3.10.6", "3.10.9", "HIGH", 7.5, "lang"),
    ("CVE-2022-45061", "python3", "3.9.2", "3.9.16", "HIGH", 7.5, "lang"),
    ("CVE-2021-3737", "python3", "3.8.10", "3.8.12", "HIGH", 7.5, "lang"),
    ("CVE-2023-30861", "flask", "2.2.2", "2.2.5", "HIGH", 7.5, "lang"),
    ("CVE-2023-32681", "requests", "2.28.1", "2.31.0", "MEDIUM", 6.1, "lang"),
    ("CVE-2022-40897", "setuptools", "59.6.0", "65.5.1", "HIGH", 7.5, "lang"),
    ("CVE-2023-5752", "pip", "22.0.2", "23.3", "MEDIUM", 5.5, "lang"),
]

# 점검 대상 — Trivy(이미지) / Inspector(인스턴스)
TARGETS = [
    ("ecr/app:1.2", "Trivy", "IMAGE", "docker-host 의 web 컨테이너 이미지", ["lang", "os", "app"]),
    ("ecr/app:1.3", "Trivy", "IMAGE", "교체 후보 이미지", ["lang"]),
    ("ecr/nginx:1.22", "Trivy", "IMAGE", "리버스 프록시 이미지", ["app", "os"]),
    ("ecr/mysql:8.0.31", "Trivy", "IMAGE", "3-Tier DB 컨테이너 이미지", ["app", "os"]),
    ("i-seoul-app-01", "Inspector", "INSTANCE", "docker-host", ["os", "lang"]),
    ("i-seoul-db-01", "Inspector", "INSTANCE", "MySQL EC2", ["os", "app"]),
    ("i-seoul-web-01", "Inspector", "INSTANCE", "DVWA 웹서버", ["os", "app"]),
    ("i-seoul-dash-01", "Inspector", "INSTANCE", "보안 대시보드", ["os", "lang"]),
]

HEADER = """# 취약점(CVE) 카탈로그 — 데모/로컬 모드 전용
#
# 정본 주의:
#   - **이 파일은 발표·개발용 데모 데이터다.** CVE ID 와 패키지명은 공개 정보를 참고했지만
#     CVSS 점수·설치/수정 버전은 화면 검증용 표기값이며 NVD 원본과 다를 수 있다.
#   - 실모드(USE_DEMO_DATA=false)는 이 파일을 쓰지 않는다. Inspector2 ListFindings 와
#     S3 의 Trivy 리포트가 정본이다(adapters/live.py vulnerabilities()).
#   - 실제 점검 결과로 교체할 때는 generator(tools/gen_vulnerabilities.py)를 다시 돌린다.
#
# 대상(target) 종류
#   IMAGE     ECR 이미지 — Trivy 컨테이너 이미지 점검(수동 모니터링 ②)
#   INSTANCE  EC2 인스턴스 — Inspector2 패키지 CVE 스캔(자동 모니터링 ①)
#
# scenario 는 조치 동선을 잇기 위한 매핑이다. SEC-04(이미지 취약점) / SEC-07(자격증명)
# 판정은 scenarios.yaml 이 정본이고, 여기서는 표시용으로만 쓴다.

version: 1
updated: 2026-09-22
"""


def main() -> None:
    out = io.StringIO()
    out.write(HEADER)
    out.write("\ntargets:\n")
    for tid, source, kind, note, _ in TARGETS:
        out.write(f'  - id: "{tid}"\n    source: {source}\n    kind: {kind}\n    note: "{note}"\n')
    out.write("\nvulnerabilities:\n")
    count = 0
    for tid, source, kind, _note, families in TARGETS:
        rows = [s for s in SEED if s[6] in families]
        # 이미지 app:1.3 은 교체 후보라 잔존 취약점만 남긴다(재검증 실패 시연용)
        if tid.endswith("app:1.3"):
            rows = [s for s in rows if s[4] in ("MEDIUM", "LOW")][:2]
        for cve, pkg, installed, fixed, sev, cvss, family in rows:
            count += 1
            out.write(
                f'  - cveId: {cve}\n'
                f'    target: "{tid}"\n'
                f'    source: {source}\n'
                f'    kind: {kind}\n'
                f'    package: {pkg}\n'
                f'    installedVersion: "{installed}"\n'
                f'    fixedVersion: "{fixed}"\n'
                f'    severity: {sev}\n'
                f'    cvss: {cvss}\n'
                f'    family: {family}\n'
            )
    out.write(f"\n# 총 {count}건\n")
    print(out.getvalue(), end="")


if __name__ == "__main__":
    main()
