import os
import argparse
import json
import logging
import time
from pathlib import Path
from typing import List, Dict, Any
from openai import OpenAI

# 1. 配置日志 (Logging) - 面试点: 生产环境不用 print，要用 logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('DeepSeek-Scanner')


class SecurityScanner:
    def __init__(self, api_key: str, model: str = "deepseek-chat"):
        """初始化扫描器，配置 DeepSeek 客户端"""
        if not api_key:
            raise ValueError("未配置 API Key，请设置环境变量 DEEPSEEK_API_KEY")

        self.client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )
        self.model = model

        # 支持的文件扩展名映射
        self.supported_extensions = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.php': 'PHP',
            '.c': 'C',
            '.cpp': 'C++'
        }

    def scan_directory(self, directory: str, recursive: bool = True, exclude_dirs: List[str] = None) -> List[Dict]:
        """
        核心功能：遍历目录
        面试点: 如何高效遍历并过滤无关文件？
        """
        if exclude_dirs is None:
            exclude_dirs = ['.git', '__pycache__', 'venv', 'node_modules', '.idea']

        results = []
        path_obj = Path(directory)

        logger.info(f"开始扫描目录: {directory}")

        # 使用 rglob (递归) 或 glob (非递归)
        pattern = '**/*' if recursive else '*'

        for file_path in path_obj.glob(pattern):
            # 1. 排除目录本身
            if not file_path.is_file():
                continue

            # 2. 检查是否在排除列表中 (如 .git)
            if any(part in exclude_dirs for part in file_path.parts):
                continue

            # 3. 检查后缀是否支持
            if file_path.suffix.lower() not in self.supported_extensions:
                continue

            # 4. 执行扫描
            logger.info(f"正在扫描: {file_path}")
            scan_result = self._scan_single_file(file_path)
            if scan_result:
                results.append(scan_result)

        return results

    def _scan_single_file(self, file_path: Path) -> Dict:
        """读取单个文件并调用 LLM"""
        try:
            language = self.supported_extensions.get(file_path.suffix.lower())
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()

            # 构造 Prompt
            prompt = self._build_prompt(code, language, file_path.name)

            # 调用 DeepSeek
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "你是一个资深代码安全审计专家。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0,  # 确保结果确定性
                response_format={"type": "json_object"}  # 强制 JSON
            )

            content = response.choices[0].message.content
            data = json.loads(content)

            # 补充文件信息
            return {
                "file": str(file_path),
                "language": language,
                "vulnerabilities": data.get("vulnerabilities", [])
            }

        except Exception as e:
            logger.error(f"扫描文件 {file_path} 失败: {str(e)}")
            return {"file": str(file_path), "error": str(e), "vulnerabilities": []}

    def _build_prompt(self, code: str, language: str, filename: str) -> str:
        """
        Prompt 工程：动态插入语言类型
        """
        return f"""
        请分析以下 {language} 代码文件 "{filename}"。
        找出其中潜在的安全漏洞（如 SQL注入、XSS、RCE、硬编码密钥、越权访问等）。

        请严格以 JSON 格式输出，不要包含 Markdown 格式，结构如下：
        {{
            "vulnerabilities": [
                {{
                    "type": "漏洞类型",
                    "severity": "High/Medium/Low",
                    "line_number": 10,
                    "description": "漏洞描述",
                    "recommendation": "修复建议"
                }}
            ]
        }}
        如果无漏洞，"vulnerabilities" 返回空数组。

        代码内容：
        ```
        {code}
        ```
        """


def generate_report(results: List[Dict], output_file: str):
    """生成 Markdown 报告"""
    total_vulns = sum(len(r.get('vulnerabilities', [])) for r in results)

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# 🛡️ 代码安全审计报告\n\n")
        f.write(f"- **扫描时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"- **扫描文件数**: {len(results)}\n")
        f.write(f"- **发现漏洞数**: {total_vulns}\n\n")

        if total_vulns == 0:
            f.write("✅ 太棒了！未发现高危漏洞。\n")
            return

        f.write("## 漏洞详情\n\n")

        for file_res in results:
            vulns = file_res.get('vulnerabilities', [])
            if not vulns:
                continue

            f.write(f"### 📄 文件: `{file_res['file']}`\n")
            for v in vulns:
                icon = "🔴" if v.get('severity') == 'High' else "🟠" if v.get('severity') == 'Medium' else "🟡"
                f.write(f"#### {icon} {v.get('type')} ({v.get('severity')})\n")
                f.write(f"- **行号**: {v.get('line_number')}\n")
                f.write(f"- **描述**: {v.get('description')}\n")
                f.write(f"- **建议**: {v.get('recommendation')}\n\n")
            f.write("---\n")

    logger.info(f"报告已生成: {output_file}")


def main():
    """
    CLI 入口
    面试点: 使用 argparse 处理命令行参数
    """
    parser = argparse.ArgumentParser(description="LLM 代码安全扫描器 (DeepSeek 版)")

    parser.add_argument("--target", required=True, help="要扫描的文件或目录路径")
    parser.add_argument("--recursive", action="store_true", help="是否递归扫描子目录")
    parser.add_argument("--output", default="scan_report.md", help="输出报告的文件名")

    args = parser.parse_args()

    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        logger.error("请设置环境变量 DEEPSEEK_API_KEY")
        return

    scanner = SecurityScanner(api_key=api_key)

    # 判断是文件还是目录
    target_path = Path(args.target)
    results = []

    if target_path.is_file():
        logger.info(f"单文件扫描模式: {target_path}")
        results.append(scanner._scan_single_file(target_path))
    elif target_path.is_dir():
        logger.info(f"目录扫描模式: {target_path}")
        results = scanner.scan_directory(str(target_path), args.recursive)
    else:
        logger.error(f"目标不存在: {target_path}")
        return

    generate_report(results, args.output)


if __name__ == "__main__":
    main()